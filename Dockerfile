FROM docker.io/gradle:9.3.1-jdk25 AS build
WORKDIR /workspace
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
COPY src ./src
RUN gradle bootJar --no-daemon

FROM eclipse-temurin:25-jre-alpine
RUN addgroup -S nonroot && adduser -S nonroot -G nonroot
USER nonroot
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar /app/mock-qtsp.jar
EXPOSE 9090
ENTRYPOINT ["java", "-jar", "/app/mock-qtsp.jar"]
