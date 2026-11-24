# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Users and credentials in PostgreSQL**, optional (`DSS_DATABASE_URL`, `DSS_DATABASE_USERNAME`,
  `DSS_DATABASE_PASSWORD`; migrated with Flyway at start). The users of the configuration
  still work. A user deactivated in the database is refused at once, also one of the
  configuration and with a token it already has. A credential's password is kept as an
  Argon2id hash and can be rotated with an overlap. When the database cannot be read,
  the answer is 503.
- **Key store** (fikua-docs ADR 0022), with `DSS_KEYS_MASTER_KEY`: the service creates the
  key of a credential, gives its CSR and activates it with the certificate of an accepted
  CA (`DSS_KEYS_ACCEPTED_CAS_<n>`, PEM files). A private key never comes in or out; it is
  kept encrypted (AES-256-GCM, a data key per credential) and destroyed when the
  credential is revoked. There is no API for it yet (#10).
- Operator command `create-list-signer`: a credential with the self-signed certificate of
  a trusted list signer (ADR 0022). The service itself cannot create one.

### Changed
- Every signature is made by the credential's signer, without the in-memory PKCS#12.

## [0.11.0] - 2026-11-24

### Changed
- **CSC conformance** (1.0.3.0 and 2.1.0.1). Signatures are Base64, no longer base64url.
  `signAlgo` is required in signHash and must be ES256. An authorization signs once
  (`numSignatures` 1) and, when it names hashes, only those; the v1 names `hash` and
  `hashAlgo` are accepted in v2 `credentials/authorize`. `credentials/info` and
  `credentials/list` honour `certificates`, `certInfo`, `authInfo`, `credentialInfo` and
  `onlyValid`, and tell an expired certificate. `info` announces only what there is, with
  the authorization server as `oauth2Issuer`; v1 `info` is also a POST. Absent values are
  left out instead of null.

### Fixed
- Stricter check of what an authorization (SAD) allows.

## [0.10.0] - 2026-11-24

### Added
- **Access tokens of an authorization server** (Keycloak): a JWT signed with
  ES256, checked with its JWK set (cached, with the last keys used up to four hours
  while the server does not answer), its issuer, audience and expiry. The user is
  the client it was issued to (`azp`). Configured with `DSS_OAUTH_ISSUER`,
  `DSS_OAUTH_JWKS_URI` and `DSS_OAUTH_AUDIENCE`; off by default. The service's own
  tokens are still accepted. When the keys cannot be obtained, the answer is 503.

## [0.9.0] - 2026-11-22

### Changed
- **Users and credentials** (CSC v2) instead of "tenants": `dss.users[n]` with
  `client-id`, `client-secret` and `credentials[m]` (`id`, `password`,
  `certificate`). A user can own several credentials; `credentials/list` returns
  all of them. **Breaking configuration**: `DSS_TENANTS_<n>_*` becomes
  `DSS_USERS_<n>_*` with `CREDENTIALS_<m>_*`; the flat `CLIENT_ID`,
  `CREDENTIAL_ID`, ... aliases are gone.
- **Audit and metrics**: the attribute `tenant.client_id` is now `user.id` and the
  `dss.business.operations` label `tenant` is now `user` (records archived before
  0.9.0 keep the old names; noted in the `AuditEvents` catalogue).
- signHash and signDoc sign with the credential the SAD authorizes (before, with
  the user's only credential).
- Client secrets and credential passwords are compared in constant time.
- CSC v2 `info` announces what the service produces: `C` and `J`, `AdES-B-B`.

## [0.8.0] - 2026-11-22

### Added
- **EU trusted lists** (ETSI TS 119 612) with the EU DSS libraries
  (`dss-tsl-validation`): a local copy of the List of Trusted Lists and the 31
  national lists (~4,700 trust anchors). After the start a background thread
  loads the copy on disk, then downloads what changed, every hour
  (`dss.trusted-lists.refresh`); never in the request path. The LoTL signature
  is checked against the signers announced in the Official Journal
  (`trust/eu-lotl-signers.p12`, from the EU DSS demonstrations, OJ C/2026/1944)
  and the pivots after it; a list with an invalid signature or past its next
  update is not trusted.
- `trustedLists` in `/health`: `pass` while the copy is fresh, `warn` before
  the first refresh or when it is older than `dss.trusted-lists.max-age` (26 h);
  never `fail`, signing does not depend on it.

### Changed
- The image runs the JVM with 60 % of the container memory as heap (the default
  is 25 %): the trust anchors need ~145 MB. Deploy with 640 MB and a volume at
  `/var/lib/dss/trusted-lists`.

## [0.7.2] - 2026-11-21

### Changed
- **Startup with an AOT cache** (Java 25, JEP 483/514/515): the image runs a
  training start at build time and ships the cache; the jar is extracted
  (`-Djarmode=tools extract`). Measured locally with 384 MB: at 0.25 CPU from
  72.7 s to 39.4 s, at 1 CPU from 5.9 s to 2.9 s; memory at rest 175 MB
  (was 185-268 MB). The image is about 100 MB larger.

## [0.7.1] - 2026-11-21

### Changed
- **ES256 only** (ECDSA P-256 with SHA-256, RFC 7518 §3.4; required by HAIP):
  a credential whose key is not EC P-256 stops the start; signHash refuses any
  `hashAlgorithmOID` / `hashAlgo` other than SHA-256 with 400 `invalid_request`.
  `credentials/info` announces ecdsa-with-SHA256 and 256 bits. The RSA paths are
  gone.

## [0.7.0] - 2026-11-21

### Changed
- **Signing with the EU DSS libraries 6.5.1** (`dss-token`, `dss-jades`,
  `dss-cades`) instead of hand-written JCA code.
- **signHash** follows `hashAlgorithmOID` / `hashAlgo` (SHA-256, -384, -512;
  SHA-256 when absent) and refuses a hash of the wrong length. Output format
  unchanged: ECDSA in DER, RSA PKCS#1 v1.5.
- **signDoc** produces AdES baseline B: `J` → enveloping JAdES (compact JWS) in
  `DocumentWithSignature`; `C` → detached CAdES in `SignatureObject`. Without
  `signature_format`, the raw signature as before. `P`, `X` and levels above
  B-B answer 400 `invalid_request`.

## [0.6.1] - 2026-11-21

### Security
- OpenAPI spec and Swagger UI off unless `SPRINGDOC_ENABLED=true`: in
  production `/v3/api-docs` and `/swagger-ui.html` were public.

### Changed
- Log attributes configured with the OpenTelemetry starter's current
  properties (`common.logging.structured-attributes`,
  `logback-appender.experimental.mdc-attributes`); the old ones are deprecated.

## [0.6.0] - 2026-11-21

### Changed
- **Spring Boot 4.2** (3.4.4 was out of support): health API in
  `org.springframework.boot.health`, web MVC starters, Jackson 3 in tests.
  springdoc 3.2, OpenTelemetry starter 2.34, BouncyCastle 1.87,
  nimbus-jose-jwt 10.10.
- **Logs** (fikua-docs conv-observability.md, OBS-08): a stable message with
  the values as SLF4J key-value pairs, exported as log attributes (columns in
  OpenObserve). Unhandled errors carry `error.type`, `exception.type` and
  `error.message` (280 characters). The per-request echoes and the
  `credential.signed` log lines are gone: traces and the audit events cover them.
- `service.version` and the startup log carry the release version; the build
  fails on a `v*` tag that does not match `build.gradle`.

### Removed
- `SignHashRawBodyLoggingFilter`, a temporary diagnostic that logged every
  `signHash` request body, SAD included (OBS-05).
- The certificate subject in the startup log: once credentials hold personal
  certificates it is a name.

## Released in 0.4.0 – 0.5.0 (not recorded per version)

### Added
- **Audit events** (fikua-docs ADR 0014 and ADR 0017): `token.issued`,
  `credential.authorized`, `credential.signed` and `auth.rejected`, emitted
  through the OpenTelemetry logs API with `event.domain = audit` and only the
  attributes of the catalogue in `AuditEvents`. The platform Collector archives
  them for five years in a locked bucket.
- **Business counter** `dss.business.operations` (operation, outcome, tenant and,
  for a rejection, error.type), one increment per audit event (fikua-docs
  observability convention, OBS-09).

### Fixed
- An unknown path (`NoResourceFoundException`: scanners, `/actuator/health`)
  answers 404 instead of being logged as an unhandled ERROR with a stack trace.

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
