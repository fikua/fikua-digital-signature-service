# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.1] - 2026-05-22

### Notes
- Re-tags the production-readiness work that landed via PR #2. v0.3.0 was
  pushed before the PR merge as a snapshot of the partially-completed
  feature set; v0.3.1 marks the first published image with the full
  Actuator + OTEL + OpenAPI + JaCoCo + Sonar baseline.
- OpenAPI document `info.version` bumped to match.

## [0.3.0] - 2026-05-22

### Security
- **Removed embedded e-seal certificate and private key from the image.**
  Previous versions baked an Altia e-seal cert into `src/main/resources/certs/`
  and shipped it inside the published Docker image. The Docker Hub repository
  was wiped and re-created under the new image name; the embedded key is
  considered compromised and must be rotated wherever it was used.
- **Log injection (CWE-117 / Sonar S5145)** fixed: every log statement that
  consumes request-derived input (grant_type, scope, credentialID, …) goes
  through `LogSanitizer.clean(...)` which strips CR/LF/tab/control chars and
  caps length at 200.
- **Security headers** added on every response: HSTS, X-Content-Type-Options,
  X-Frame-Options, Referrer-Policy, Cache-Control no-store.

### Changed
- **Renamed Docker image** to `fikua/fikua-digital-signature-service` (was
  `fikua/digital-signature-service`). Repository renamed to match.
- **Renamed Gradle project** to `fikua-digital-signature-service` (so the
  boot JAR is now `fikua-digital-signature-service-<version>.jar`).
- **Certificate loading is now filesystem-only.** Defaults to
  `file:/certs/mock-eseal.{crt,key}`; the host must mount its own certs
  read-only at runtime.
- **`/health` is now Spring Boot Actuator** (`{"status":"UP","components":…}`)
  instead of the previous bespoke JSON shape. The custom `HealthController`
  has been removed; a `CertificateHealthIndicator` exposes cert validity and
  signing-key state as a `certificate` component.
- `deploy.sh` now goes through Cloudflare Tunnel (`vps.fikua.com`) instead of
  raw SSH + port 49222.
- `docker-compose.yml` mounts `./certs:/certs:ro` and points at the new image
  name + filesystem defaults.

### Added
- **Production-readiness**:
  - Spring Boot Actuator with `/health` (+ liveness/readiness probes) and
    `/info` exposed at root.
  - Structured JSON logs via `logstash-logback-encoder`, with the OTEL
    `trace_id` / `span_id` and a per-request `X-Request-Id` propagated
    through MDC. Bootstrap noise demoted to WARN; banner off.
  - OpenAPI 3 (`/v3/api-docs`) and Swagger UI (`/swagger-ui.html`) via
    springdoc-openapi 2.7.0, with OAuth2 client_credentials + Bearer
    security schemes declared.
  - OpenTelemetry Java instrumentation 2.10.0 wired in; exporters default
    to `none` and become active when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
  - Global `@RestControllerAdvice` mapping framework exceptions and
    unexpected errors to typed `ErrorResponse` JSON.
  - Graceful shutdown (30s phase) and tighter request body limits.
- **CI / quality**:
  - SonarCloud workflow (`.github/workflows/build.yml`) running on push to
    `main` and on every PR.
  - JaCoCo Gradle plugin (0.8.13) with XML report wired into Sonar
    (`sonar.coverage.jacoco.xmlReportPaths`).
  - Branch protection on `main`: required PR + status checks
    (`build-and-push`, `build`), no force-push, no deletion, linear
    history, conversation resolution.
- **Tests**: real Spring context + MockMvc tests for `OAuth2Controller`,
  `CscController` (all 6 endpoints, happy + error paths), Actuator probes,
  global exception handler, plus pure unit tests for `TokenService`,
  `LogSanitizer`, `GlobalExceptionHandler` and `CertificateHealthIndicator`.
  Local coverage: 92% line, 91% instruction, 100% class.
- `LICENSE` (Apache-2.0, copyright Fikua) and `NOTICE` file.
- `.dockerignore` blocking any cert/key material from being baked into
  images.
- `.gitignore` hardened with `**/certs/`, `*.pem`, `*.key`, `*.crt`, `*.p12`,
  `*.pfx`, `*.jks`.
- README rewritten with mock-cert quick-start, production-readiness section,
  OpenAPI pointers and Apache-2.0 license note.

## [0.1.0] - 2026-04-02

### Added
- CSC API v2 endpoints: `/csc/v2/info`, `/csc/v2/credentials/list`, `/csc/v2/credentials/info`, `/csc/v2/credentials/authorize`, `/csc/v2/signatures/signHash`, `/csc/v2/signatures/signDoc`
- OAuth2 `client_credentials` token endpoint (`/oauth2/token`) with HTTP Basic Auth
- Health endpoint (`/health`) with certificate validity and signing key checks
- X.509 certificate loading from classpath (embedded) or filesystem (override via env var)
- Support for EC (P-256) and RSA signing keys
- SAD (Signature Activation Data) issuance and validation with configurable TTL
- Dockerfile multi-stage build (gradle:9.3.1-jdk25 / temurin:25-jre-alpine)
- Deploy script for OVH VPS (`deploy.sh`) with `linux/amd64` cross-platform build
- Altia e-seal certificate embedded in JAR for out-of-the-box operation
