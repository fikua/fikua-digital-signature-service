# The JAR is the same on every architecture: compile once on the build
# platform, so Gradle never runs under QEMU in multi-arch builds.
FROM --platform=$BUILDPLATFORM docker.io/gradle:9.3.1-jdk25 AS build
WORKDIR /workspace
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
COPY src ./src
RUN gradle bootJar --no-daemon
# A throwaway P-256 credential for the AOT training run below; it never
# reaches the final image.
RUN mkdir /training && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
      -keyout /training/key.pem -out /training/cert.pem -days 1 -subj /CN=aot-training

# AOT cache (JEP 483, 514, 515): a training run starts the Spring context and
# exits; the JVM stores the classes it loaded and linked, and the start reads
# them instead of doing that work again. Built per architecture (the cache is
# tied to the JVM and the platform), from the same base image as the final stage.
FROM eclipse-temurin:25-jre-alpine AS aot
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar /tmp/dss.jar
RUN java -Djarmode=tools -jar /tmp/dss.jar extract --destination /app && rm /tmp/dss.jar
COPY --from=build /training /training
# BuildKit traces build steps through OTEL_* variables pointing to its own
# unix socket, which the OpenTelemetry starter refuses: the training run starts
# without any of them (the application's exporters then default to none).
RUN for v in $(env | sed -n 's/^\(OTEL_[A-Z_]*\)=.*/\1/p'); do unset "$v"; done; \
    DSS_TENANTS_0_CLIENT_ID=training DSS_TENANTS_0_CLIENT_SECRET=training \
    DSS_TENANTS_0_CREDENTIAL_ID=training DSS_TENANTS_0_CREDENTIAL_PASSWORD=training \
    DSS_TENANTS_0_CERTIFICATE_CERT_PATH=file:/training/cert.pem \
    DSS_TENANTS_0_CERTIFICATE_KEY_PATH=file:/training/key.pem \
    java -XX:AOTCacheOutput=/app/dss.aot -Dspring.context.exit=onRefresh -jar /app/dss.jar

FROM eclipse-temurin:25-jre-alpine
# uid/gid 65532, the distroless "nonroot" every Fikua image runs as: the
# platform writes secret files as root:65532 0640 (fikua-docs conv-deployment.md).
RUN addgroup -S -g 65532 nonroot && adduser -S -u 65532 -G nonroot nonroot
USER nonroot
WORKDIR /app
COPY --from=aot /app /app
EXPOSE 9090
# GET /health (OBS-17, DEP-10) with the image's busybox wget; a 503 fails it.
# Traefik routes only to healthy containers: --start-interval makes a new one
# healthy seconds after it is ready.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --start-interval=2s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${SERVER_PORT:-9090}/health" || exit 1
# A JVM that does not match the cache ignores it with a warning and starts as before.
ENTRYPOINT ["java", "-XX:AOTCache=/app/dss.aot", "-jar", "/app/dss.jar"]
