# The JAR is the same on every architecture: compile once on the build
# platform, so Gradle never runs under QEMU in multi-arch builds.
FROM --platform=$BUILDPLATFORM docker.io/gradle:9.3.1-jdk25 AS build
WORKDIR /workspace
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
COPY src ./src
RUN gradle bootJar --no-daemon

FROM eclipse-temurin:25-jre-alpine
# uid/gid 65532, the distroless "nonroot" every Fikua image runs as: the
# platform writes secret files as root:65532 0640 (fikua-docs conv-deployment.md).
RUN addgroup -S -g 65532 nonroot && adduser -S -u 65532 -G nonroot nonroot
USER nonroot
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar /app/dss.jar
EXPOSE 9090
ENTRYPOINT ["java", "-jar", "/app/dss.jar"]
