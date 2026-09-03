# Fikua Digital Signature Service

Spring Boot service implementing the [Cloud Signature Consortium (CSC) API v2.0](https://cloudsignatureconsortium.org/resources/). Initial mode is a **mock Trust Service Provider (TSP)** for local development and CI testing of remote signing flows used by Issuer/EBW components in the EUDI Wallet stack. The roadmap is to extend it with real DSS (Digital Signature Service — European Commission) support.

> [!WARNING]
> **Mock mode is for development and testing only.** It accepts static client secrets and signs with test certificates. **Never deploy this as a real (qualified) TSP** and never feed it a production e-seal certificate.

## Multi-tenant

The service can serve several CSC clients ("tenants") at once, each with its own OAuth2 `client_id`/`client_secret`, CSC `credentialId`, and signing certificate. A tenant's access token can only ever list, inspect, authorize, or sign with **its own** certificate — the token carries the tenant it was minted for, and every subsequent call is resolved from that token, not from client-supplied identifiers. See `MultiTenantIsolationTest` for the enforced isolation guarantees.

## Endpoints

### CSC v2 API

| Method | Path                            | Description                                |
| ------ | ------------------------------- | ------------------------------------------ |
| POST   | `/oauth2/token`                 | OAuth2 `client_credentials` token endpoint |
| POST   | `/csc/v2/info`                  | Service information                        |
| POST   | `/csc/v2/credentials/list`      | List available credentials                 |
| POST   | `/csc/v2/credentials/info`      | Credential and certificate info            |
| POST   | `/csc/v2/credentials/authorize` | Get SAD (Signature Activation Data)        |
| POST   | `/csc/v2/signatures/signHash`   | Sign pre-computed hash(es)                 |
| POST   | `/csc/v2/signatures/signDoc`    | Sign document(s)                           |

### Observability and operations

| Method | Path                | Description                                                            |
| ------ | ------------------- | ---------------------------------------------------------------------- |
| GET    | `/health`           | Spring Boot Actuator health (cert validity + signing key + readiness)  |
| GET    | `/health/liveness`  | Kubernetes-style liveness probe                                        |
| GET    | `/health/readiness` | Readiness probe (includes the `certificate` indicator)                 |
| GET    | `/info`             | Build, Java and OS metadata                                            |
| GET    | `/v3/api-docs`      | OpenAPI 3 specification                                                |
| GET    | `/swagger-ui.html`  | Interactive Swagger UI (lets you authenticate against `/oauth2/token`) |

## Configuration

All settings via environment variables. The container does **not** ship with any certificate inside — you must mount your own at `/certs/`.

Tenant 0 (the default/first tenant) is configured via the flat variables below, kept for backward compatibility:

| Variable              | Default                      | Description                       |
| --------------------- | ----------------------------- | --------------------------------- |
| `SERVER_PORT`         | `9090`                       | HTTP port                         |
| `CLIENT_ID`           | `mock-client`                | OAuth2 client ID (tenant 0)       |
| `CLIENT_SECRET`       | `mock-secret`                | OAuth2 client secret (tenant 0)   |
| `CREDENTIAL_ID`       | `mock-credential-001`        | CSC credential identifier (tenant 0) |
| `CREDENTIAL_PASSWORD` | `mock-password`              | Credential authorization password (tenant 0) |
| `CERT_PATH`           | `file:/certs/mock-eseal.crt` | X.509 certificate, PEM (tenant 0) |
| `KEY_PATH`            | `file:/certs/mock-eseal.key` | Private key, PKCS#8 PEM (tenant 0) |
| `TOKEN_TTL`           | `3600`                       | Access token lifetime (seconds), applies to all tenants |
| `SAD_TTL`             | `300`                        | SAD lifetime (seconds), applies to all tenants |

Additional tenants are added via indexed `DSS_TENANTS_<n>_*` variables (Spring binds indexed env vars onto the `dss.tenants` list), or `DSS_TENANTS_0_*` to override tenant 0 explicitly instead of the flat aliases above:

```bash
DSS_TENANTS_1_CLIENT_ID=fikua-issuer
DSS_TENANTS_1_CLIENT_SECRET=<secret>
DSS_TENANTS_1_CREDENTIAL_ID=fikua-credential-001
DSS_TENANTS_1_CREDENTIAL_PASSWORD=<password>
DSS_TENANTS_1_CERTIFICATE_CERT_PATH=file:/certs/fikua/fikua-eseal-chain.pem
DSS_TENANTS_1_CERTIFICATE_KEY_PATH=file:/certs/fikua/fikua-eseal.key
```

Every tenant's certificate + key must be mounted read-only into the container; the image never bakes in any cert material (see [Certificates — never bake into the image](CLAUDE.md)). Secrets (`*_CLIENT_SECRET`, `*_CREDENTIAL_PASSWORD`) are only ever supplied via environment variables backed by a gitignored `.env` file (or the platform's secret store) — never hardcoded in source or compose defaults.

## Quick start

### Generate a mock certificate

```bash
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout certs/mock-eseal.key -out certs/mock-eseal.crt \
    -sha256 -days 3650 -nodes \
    -subj "/C=ES/O=Fikua/CN=Fikua Mock e-Seal (test only)"
```

### Run with Docker (published image)

```bash
docker run --rm -p 9090:9090 \
    -v "$(pwd)/certs:/certs:ro" \
    fikua/fikua-digital-signature-service:latest
```

### Run with Docker Compose (local build)

```bash
docker compose up --build
```

Service listens at `http://localhost:9090`.

### Build locally

```bash
./gradlew bootJar
java -jar build/libs/fikua-digital-signature-service-0.3.1.jar \
    --dss.certificate.cert-path=file:./certs/mock-eseal.crt \
    --dss.certificate.key-path=file:./certs/mock-eseal.key
# (the boot JAR name follows rootProject.name + version in settings.gradle / build.gradle)
```

## Issuer / client configuration

Configure the calling service (Issuer, EBW…) to use this DSS via its runtime signing config:

```bash
curl -X PUT http://localhost:8080/internal/signing/config \
    -H "Content-Type: application/json" \
    -d '{
      "provider": "csc-sign-hash",
      "remoteSignature": {
        "type": "cloud",
        "url": "http://localhost:9090",
        "clientId": "mock-client",
        "clientSecret": "mock-secret",
        "credentialId": "mock-credential-001",
        "credentialPassword": "mock-password"
      }
    }'
```

## Signing flow

```text
Client                                  DSS
  │                                      │
  ├─ POST /oauth2/token ────────────────►│  Basic auth, client_credentials
  │◄─── access_token ────────────────────┤
  │                                      │
  ├─ POST /csc/v2/credentials/info ─────►│  Bearer token
  │◄─── certificate chain + key info ────┤
  │                                      │
  ├─ POST /csc/v2/credentials/authorize ►│  hash + password
  │◄─── SAD ─────────────────────────────┤
  │                                      │
  ├─ POST /csc/v2/signatures/signHash ──►│  SAD + hash
  │◄─── signature ───────────────────────┤
```

## Production readiness

- **Health probes** at `/health`, `/health/liveness`, `/health/readiness` via Spring Boot Actuator. A custom `certificate` component reports DOWN when the cert is expired, not yet valid, or the private key is missing.
- **Structured logging**: `logstash-logback-encoder` emits JSON in production and a human-readable line in `local` / `dev` profiles. Bootstrap noise from autoconfigure, Tomcat, OpenTelemetry and Springdoc is demoted to WARN; the Spring banner is off.
- **Correlation**: every response carries an `X-Request-Id` header (honours an incoming one or generates a UUID). The same id is in the MDC alongside OTEL `trace_id` / `span_id`.
- **OpenTelemetry**: `opentelemetry-spring-boot-starter` is wired in. Exporters default to `none`; set `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_TRACES_EXPORTER=otlp` (etc.) to enable.
- **Security headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security` and `Cache-Control: no-store` on every response.
- **Graceful shutdown** (30 s phase) plus a global `@RestControllerAdvice` that maps known framework exceptions and unexpected errors to a typed `ErrorResponse`.

## OpenAPI / Swagger

Spec is at [`/v3/api-docs`](http://localhost:9090/v3/api-docs); the interactive UI is at [`/swagger-ui.html`](http://localhost:9090/swagger-ui.html). The OAuth2 `client_credentials` flow is declared, so you can use the "Authorize" button in the UI to mint a token against `/oauth2/token` and call the rest of the endpoints from the browser.

## Tech stack

- Java 25 (Gradle toolchain)
- Spring Boot 3.4.4 + Spring Boot Actuator
- BouncyCastle 1.80 (signing primitives)
- Nimbus JOSE+JWT 9.40 (token signing)
- springdoc-openapi 2.7.0 (OpenAPI + Swagger UI)
- OpenTelemetry Java instrumentation 2.10.0
- Logback + logstash-logback-encoder 8.0 (JSON logs)

## Releases

- **Image:** `fikua/fikua-digital-signature-service` on Docker Hub (public).
- **CI:** `.github/workflows/release.yml` builds and pushes on every push to `main` (`:latest`) and on `vX.Y.Z` tags (semver tags).
- Multi-arch: `linux/amd64` + `linux/arm64`.

## Contributing

Conventional Commits, squash-merge to `main`. PRs welcome — please keep mock-mode and (future) real-TSP paths cleanly separated.

## License

Apache-2.0. See [LICENSE](LICENSE).

## References

- CSC API v2.0 specification: <https://cloudsignatureconsortium.org/resources/>
- DSS (European Commission): <https://github.com/esig/dss>
