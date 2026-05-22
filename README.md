# Fikua Digital Signature Service

Spring Boot service implementing the [Cloud Signature Consortium (CSC) API v2.0](https://cloudsignatureconsortium.org/resources/). Initial mode is a **mock Qualified Trust Service Provider (QTSP)** for local development and CI testing of remote signing flows used by Issuer/EBW components in the EUDI Wallet stack. The roadmap is to extend it with real DSS (Digital Signature Service — European Commission) support.

> [!WARNING]
> **Mock mode is for development and testing only.** It accepts a static client secret and signs with a self-signed certificate. **Never deploy this as a real QTSP** and never feed it a production e-seal certificate.

## Endpoints

| Method | Path                            | Description                                |
| ------ | ------------------------------- | ------------------------------------------ |
| POST   | `/oauth2/token`                 | OAuth2 `client_credentials` token endpoint |
| POST   | `/csc/v2/info`                  | Service information                        |
| POST   | `/csc/v2/credentials/list`      | List available credentials                 |
| POST   | `/csc/v2/credentials/info`      | Credential and certificate info            |
| POST   | `/csc/v2/credentials/authorize` | Get SAD (Signature Activation Data)        |
| POST   | `/csc/v2/signatures/signHash`   | Sign pre-computed hash(es)                 |
| POST   | `/csc/v2/signatures/signDoc`    | Sign document(s)                           |
| GET    | `/health`                       | Health check (cert validity + signing key) |

## Configuration

All settings via environment variables. The container does **not** ship with any certificate inside — you must mount your own at `/certs/`.

| Variable              | Default                      | Description                       |
| --------------------- | ---------------------------- | --------------------------------- |
| `SERVER_PORT`         | `9090`                       | HTTP port                         |
| `CLIENT_ID`           | `mock-client`                | OAuth2 client ID                  |
| `CLIENT_SECRET`       | `mock-secret`                | OAuth2 client secret              |
| `CREDENTIAL_ID`       | `mock-credential-001`        | CSC credential identifier         |
| `CREDENTIAL_PASSWORD` | `mock-password`              | Credential authorization password |
| `CERT_PATH`           | `file:/certs/mock-eseal.crt` | X.509 certificate (PEM)           |
| `KEY_PATH`            | `file:/certs/mock-eseal.key` | Private key (PKCS#8 PEM)          |
| `TOKEN_TTL`           | `3600`                       | Access token lifetime (seconds)   |
| `SAD_TTL`             | `300`                        | SAD lifetime (seconds)            |

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
java -jar build/libs/fikua-digital-signature-service-0.3.0.jar \
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

## Tech stack

- Java 25 (Gradle toolchain)
- Spring Boot 3.4.4
- BouncyCastle 1.80 (signing primitives)
- Nimbus JOSE+JWT 9.40 (token signing)

## Releases

- **Image:** `fikua/fikua-digital-signature-service` on Docker Hub (public).
- **CI:** `.github/workflows/release.yml` builds and pushes on every push to `main` (`:latest`) and on `vX.Y.Z` tags (semver tags).
- Multi-arch: `linux/amd64` + `linux/arm64`.

## Contributing

Conventional Commits, squash-merge to `main`. PRs welcome — please keep mock-mode and (future) real-QTSP paths cleanly separated.

## License

Apache-2.0. See [LICENSE](LICENSE).

## References

- CSC API v2.0 specification: <https://cloudsignatureconsortium.org/resources/>
- DSS (European Commission): <https://github.com/esig/dss>
