# Fikua Digital Signature Service

Spring Boot service implementing the [Cloud Signature Consortium (CSC) API](https://cloudsignatureconsortium.org/resources/), exposing both **CSC v1 (1.0.3.0)** and **CSC v2 (2.1.0.1)** as strict, version-conformant surfaces in parallel (`/csc/v1/...` and `/csc/v2/...`). Initial mode is a **mock Trust Service Provider (TSP)** for local development and CI testing of remote signing flows used by Issuer/EBW components in the EUDI Wallet stack. It signs with the European Commission's DSS libraries.

> [!NOTE]
> **Two things are called DSS.** In this repository, *Fikua DSS* is this service, and *EU DSS* is the European Commission's library and demonstrations ([esig/dss](https://github.com/esig/dss)). The Fikua DSS uses the EU DSS libraries; a relying system may also run the EU DSS demonstrations on its own to validate trust. They are different deployments.

> [!WARNING]
> **Mock mode is for development and testing only.** It accepts static client secrets and signs with test certificates. **Never deploy this as a real (qualified) TSP** and never feed it a production e-seal certificate.

## Users and credentials

The model is CSC v2's: a **user** is an OAuth2 client (`client_credentials`) and owns one or more **credentials**, each a certificate with its private key, unlocked with its own password. A user's access token only ever lists, inspects, authorizes or signs with **its own** credentials: every call resolves the user from the token, and a credential is used only when it belongs to that user and a SAD for it was issued to that user. See `UserIsolationTest`.

One user per calling system (the Lab issuer, verifier and Wallet Provider are three users), so a leaked token cannot sign with another system's key.

## Keys and certificates

- **Today**, each credential's certificate and key are files mounted at `/certs/`.
- **Decided, not built yet** ([#9](https://github.com/fikua/fikua-digital-signature-service/issues/9)): the Fikua DSS creates the key of each credential, gives a CSR, and activates the credential when it receives the certificate a CA issued for that key. Private keys are never imported or returned. A credential waiting for its certificate does not sign, and revoking one destroys its key.

## Endpoints

Both CSC versions are exposed side-by-side; pick the path prefix that matches your client's CSC version.

### CSC v1 API (1.0.3.0)

| Method | Path                            | Description                                |
| ------ | ------------------------------- | ------------------------------------------ |
| POST   | `/oauth2/token`                 | OAuth2 `client_credentials` token endpoint (shared) |
| GET    | `/csc/v1/info?lang=`            | Service information (GET in v1)            |
| POST   | `/csc/v1/credentials/list`      | List available credentials                 |
| POST   | `/csc/v1/credentials/info`      | Credential and certificate info (`authMode`/`PIN`/`OTP`/`multisign`/`lang`) |
| POST   | `/csc/v1/credentials/authorize` | Get SAD using `PIN` + `OTP` strings        |
| POST   | `/csc/v1/signatures/signHash`   | Sign pre-computed hash(es) (`hash` + `hashAlgo`) |

v1 has no `signDoc` endpoint — it is not defined by the 1.0.3.0 spec.

### CSC v2 API (2.1.0.1)

| Method | Path                            | Description                                |
| ------ | ------------------------------- | ------------------------------------------ |
| POST   | `/oauth2/token`                 | OAuth2 `client_credentials` token endpoint (shared) |
| POST   | `/csc/v2/info`                  | Service information (POST in v2)           |
| POST   | `/csc/v2/credentials/list`      | List available credentials                 |
| POST   | `/csc/v2/credentials/info`      | Credential and certificate info (`auth` object) |
| POST   | `/csc/v2/credentials/authorize` | Get SAD using `authData: [{id, value}]` array |
| POST   | `/csc/v2/signatures/signHash`   | Sign pre-computed hash(es) (`hashes` + `hashAlgorithmOID`) |
| POST   | `/csc/v2/signatures/signDoc`    | Sign document(s) — v2 only: JAdES (`J`) or CAdES (`C`), baseline B |

### CSC v1 vs v2 contract divergences

| Concern                                    | v1 (1.0.3.0)                                      | v2 (2.1.0.1)                                  |
| ------------------------------------------- | -------------------------------------------------- | ---------------------------------------------- |
| `signatures/signHash` hash field            | `hash: List<String>`                              | `hashes: List<String>`                        |
| `signatures/signHash` algorithm OID field   | `hashAlgo: String`                                | `hashAlgorithmOID: String`                    |
| `credentials/authorize` auth secret         | `PIN: String` + `OTP: String`                     | `authData: [{id, value}]` array               |
| `credentials/info` response auth model      | `authMode` + `PIN` + `OTP` + `multisign` + `lang` | `auth: {mode, expression, objects[]}` object  |
| `info` HTTP method                          | `GET ?lang=`                                      | `POST` body                                   |
| `signatures/signDoc` endpoint               | Not defined                                       | Defined (supports `documents` or `documentDigests`) |

### Signatures (EU DSS 6.5)

Signing uses the European Commission's DSS libraries (`dss-token`, `dss-jades`, `dss-cades`).

- **ES256 only** (ECDSA P-256 with SHA-256, the algorithm HAIP requires): every credential's key must be EC P-256, or the service does not start.
- **signHash**: the credential's key signs the client's SHA-256 digest (`SignatureTokenConnection.signDigest`); the signature is ASN.1 DER. `hashAlgorithmOID` (v2) or `hashAlgo` (v1) must be SHA-256 (`2.16.840.1.101.3.4.2.1`) or absent; anything else, or a hash that is not 32 bytes, answers 400.
- **signDoc**, `documents` mode: `signature_format` `J` returns an enveloping JAdES-B-B (compact JWS) in `DocumentWithSignature`; `C` a detached CAdES-B-B in `SignatureObject`. Only `AdES-B-B` is produced (no timestamps). Without `signature_format`, the raw signature of the document in both fields (the pre-0.7.0 behaviour). `P` and `X` answer 400.
- **signDoc**, `documentDigests` mode: signed as in signHash.

The reference OpenAPI specs are bundled in this repo at [`csc_openapi_1.0.3.0.json`](csc_openapi_1.0.3.0.json) and [`csc_openapi_2.1.0.1.yaml`](csc_openapi_2.1.0.1.yaml). The published v2.1.0.1 spec has internal inconsistencies between `required` lists and `properties` blocks (e.g. `input-signatures-signhash.required` lists `hash` but `properties` only defines `hashes`); this implementation follows `properties` consistently. See [`TD-ISSUER-CSC-V2-CONFORMANCE.md`](TD-ISSUER-CSC-V2-CONFORMANCE.md) for the Issuer-side migration plan to conformant v1/v2 request bodies.

### Observability and operations

| Method | Path                | Description                                                            |
| ------ | ------------------- | ---------------------------------------------------------------------- |
| GET    | `/health`           | Spring Boot Actuator health (cert validity + signing key + readiness)  |
| GET    | `/health/liveness`  | Kubernetes-style liveness probe                                        |
| GET    | `/health/readiness` | Readiness probe (includes the `certificate` indicator)                 |
| GET    | `/info`             | Build, Java and OS metadata                                            |
| GET    | `/v3/api-docs`      | OpenAPI 3 specification (only with `SPRINGDOC_ENABLED=true`)           |
| GET    | `/swagger-ui.html`  | Swagger UI (only with `SPRINGDOC_ENABLED=true`)                        |

## Configuration

All settings via environment variables. The container does **not** ship with any certificate inside — you must mount your own at `/certs/`.

| Variable      | Default | Description |
| ------------- | ------- | ----------- |
| `SERVER_PORT` | `9090`  | HTTP port |
| `TOKEN_TTL`   | `3600`  | Access token lifetime (seconds) |
| `SAD_TTL`     | `300`   | SAD lifetime (seconds) |
| `DSS_OAUTH_ISSUER` | | Issuer of the authorization server whose access tokens (JWT, ES256) are accepted besides the service's own; empty, none |
| `DSS_OAUTH_JWKS_URI` | | Its JWK set (required with an issuer) |
| `DSS_OAUTH_AUDIENCE` | | The audience those tokens must carry (required with an issuer) |

A token of the authorization server acts as the user whose `client-id` is its `azp`.

Users and credentials come from indexed variables, which replace the whole `dss.users` list (the default is one local development user, `mock-client` with `mock-credential-001`):

```bash
DSS_USERS_0_CLIENT_ID=fikua-issuer
DSS_USERS_0_CLIENT_SECRET=<secret>
DSS_USERS_0_CREDENTIALS_0_ID=fikua-credential-001
DSS_USERS_0_CREDENTIALS_0_PASSWORD=<password>
DSS_USERS_0_CREDENTIALS_0_CERTIFICATE_CERT_PATH=file:/certs/fikua/fikua-eseal-chain.pem
DSS_USERS_0_CREDENTIALS_0_CERTIFICATE_KEY_PATH=file:/certs/fikua/fikua-eseal.key
```

Credential ids are unique across users. Every credential key must be EC P-256 (ES256 only).

Every credential's certificate and key must be mounted read-only into the container; the image never bakes in any cert material (see [Certificates — never bake into the image](CLAUDE.md)). Secrets (`*_CLIENT_SECRET`, `*_CREDENTIAL_PASSWORD`) are only ever supplied via environment variables backed by a gitignored `.env` file (or the platform's secret store) — never hardcoded in source or compose defaults.

## Quick start

### Generate a mock certificate (local development only)

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

- **Health** at `GET /health` in `application/health+json` (fikua-docs OBS-17), statuses only. The Actuator, with its details, is on the internal management port 9091. A custom `certificate` component reports DOWN when a certificate is expired, not yet valid, or its private key is missing.
- **Structured logging**: `logstash-logback-encoder` emits JSON in production and a human-readable line in `local` / `dev` profiles. Bootstrap noise from autoconfigure, Tomcat, OpenTelemetry and Springdoc is demoted to WARN; the Spring banner is off.
- **Correlation**: every response carries an `X-Request-Id` header (honours an incoming one or generates a UUID). The same id is in the MDC alongside OTEL `trace_id` / `span_id`.
- **OpenTelemetry** (fikua-docs conv-observability.md): the OpenTelemetry Spring Boot starter exports traces, metrics and logs over OTLP/HTTP with semantic-convention names. Exporters default to `none`; the deployment sets `OTEL_EXPORTER_OTLP_ENDPOINT` and `OTEL_{TRACES,METRICS,LOGS}_EXPORTER=otlp`. `service.version` is the build's version (build-info). Log values are SLF4J key-value pairs (`log.atWarn().addKeyValue(...)`): each one becomes a log attribute. Audit events and the `dss.business.operations` counter: `AuditEvents`.
- **Security headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Strict-Transport-Security` and `Cache-Control: no-store` on every response.
- **Graceful shutdown** (30 s phase) plus a global `@RestControllerAdvice` that maps known framework exceptions and unexpected errors to a typed `ErrorResponse`.

## EU trusted lists

A local copy of the EU List of Trusted Lists and the national lists (ETSI TS 119 612, `TrustedLists`), the base for validating certificates (fikua-docs ADR 0021). After the start a background thread loads the copy from `/var/lib/dss/trusted-lists` and then downloads what changed, every hour; the first full load takes a few minutes with 1 CPU. The LoTL signature is checked against the signers announced in the Official Journal (`src/main/resources/trust/eu-lotl-signers.p12`, public certificates from the EU DSS demonstrations, OJ C/2026/1944); a list with an invalid signature or expired is not trusted. `/health` reports `trustedLists` as `warn` while the copy is missing or older than 26 h.

| Property | Default |
| --- | --- |
| `dss.trusted-lists.enabled` | `true` |
| `dss.trusted-lists.lotl-url` | `https://ec.europa.eu/tools/lotl/eu-lotl.xml` |
| `dss.trusted-lists.official-journal-url` | `https://eur-lex.europa.eu/eli/C/2026/1944/oj` |
| `dss.trusted-lists.cache-directory` | `/var/lib/dss/trusted-lists` |
| `dss.trusted-lists.refresh` | `PT1H` |
| `dss.trusted-lists.max-age` | `PT26H` |

When the Commission announces new LoTL signers in a new OJ publication, update the URL and the keystore (from the EU DSS demonstrations).

## OpenAPI / Swagger

Off by default, so production never publishes them; set `SPRINGDOC_ENABLED=true` to turn them on locally.
Spec is at [`/v3/api-docs`](http://localhost:9090/v3/api-docs); the interactive UI is at [`/swagger-ui.html`](http://localhost:9090/swagger-ui.html). The OAuth2 `client_credentials` flow is declared, so you can use the "Authorize" button in the UI to mint a token against `/oauth2/token` and call the rest of the endpoints from the browser.

## Tech stack

- Java 25 (Gradle toolchain)
- Spring Boot 4.2 + Spring Boot Actuator
- EU DSS 6.5.1 (signatures: token, JAdES, CAdES)
- BouncyCastle 1.87 (key loading, through DSS)
- Nimbus JOSE+JWT 10.10 (access token validation)
- springdoc-openapi 3.2 (OpenAPI + Swagger UI)
- OpenTelemetry Java instrumentation 2.34 (Spring Boot starter)
- Logback + logstash-logback-encoder 9.0 (JSON logs)

## Releases

- **Image:** `ghcr.io/fikua/fikua-digital-signature-service` (also on Docker Hub until ADR 0015 closes it).
- **CI:** `.github/workflows/ci.yml` (shared workflows) publishes `latest` and `sha-<short>` on every push to `main`, and `X.Y.Z` on every `vX.Y.Z` tag.
- **Version:** `version` in `build.gradle` is the release; bump it in the pull request, then tag `v<version>`. The build fails on a tag that does not match.
- **Deploy:** not from this repository. `fikua-platform-iac/projects/fikua-digital-signature-service/compose.yaml` pins a release and Dependabot proposes each new one (fikua-docs ADR 0019).
- Multi-arch: `linux/amd64` + `linux/arm64`.

## Contributing

Conventional Commits, squash-merge to `main`. PRs welcome — please keep mock-mode and (future) real-TSP paths cleanly separated.

## License

Apache-2.0. See [LICENSE](LICENSE).

## References

- CSC API v2.0 specification: <https://cloudsignatureconsortium.org/resources/>
- DSS (European Commission): <https://github.com/esig/dss>
