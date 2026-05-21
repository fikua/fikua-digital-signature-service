# Digital Signature Service (DSS) — CSC v2 API

Spring Boot service implementing the Cloud Signature Consortium (CSC) v2 API. Initial mode is a mock Qualified Trust Service Provider (QTSP) for development and testing of remote signing flows; the roadmap is to extend it with real DSS (Digital Signature Service — European Commission) support.

**Mock mode is NOT for production use.** It signs with a static e-seal certificate provided at runtime.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth2/token` | OAuth2 client_credentials token endpoint |
| POST | `/csc/v2/info` | Service information |
| POST | `/csc/v2/credentials/list` | List available credentials |
| POST | `/csc/v2/credentials/info` | Credential and certificate info |
| POST | `/csc/v2/credentials/authorize` | Get SAD (Signature Activation Data) |
| POST | `/csc/v2/signatures/signHash` | Sign pre-computed hash(es) |
| POST | `/csc/v2/signatures/signDoc` | Sign document(s) |
| GET | `/health` | Health check |

## Configuration

All configuration via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_PORT` | `9090` | HTTP port |
| `CLIENT_ID` | `mock-client` | OAuth2 client ID |
| `CLIENT_SECRET` | `mock-secret` | OAuth2 client secret |
| `CREDENTIAL_ID` | `mock-credential-001` | CSC credential identifier |
| `CREDENTIAL_PASSWORD` | `mock-password` | Credential authorization password |
| `CERT_PATH` | `/config/certs/issuer-eseal.crt` | X.509 certificate (PEM) |
| `KEY_PATH` | `/config/certs/issuer-eseal.key` | Private key (PKCS#8 PEM) |
| `TOKEN_TTL` | `3600` | Access token lifetime (seconds) |
| `SAD_TTL` | `300` | SAD lifetime (seconds) |

## Running with Docker

Pull from Docker Hub:

```bash
docker pull fikua/digital-signature-service:latest
```

Or build locally:

1. Place the e-seal certificate and key in `./certs/`:

   ```
   certs/
     issuer-eseal.crt
     issuer-eseal.key
   ```

2. Run:

   ```bash
   docker compose up -d
   ```

The service will be available at `http://localhost:9090`.

## Building locally

```bash
./gradlew bootJar
java -jar build/libs/digital-signature-service-0.2.0.jar \
  --dss.certificate.cert-path=./certs/issuer-eseal.crt \
  --dss.certificate.key-path=./certs/issuer-eseal.key
```

## Issuer configuration

Configure the Issuer to use this service via the runtime signing config API:

```bash
curl -X PUT http://localhost:8080/internal/signing/config \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "csc-sign-hash",
    "remoteSignature": {
      "type": "cloud",
      "url": "https://mock-qtsp.altia.fikua.com",
      "clientId": "mock-client",
      "clientSecret": "mock-secret",
      "credentialId": "mock-credential-001",
      "credentialPassword": "mock-password"
    }
  }'
```

## Signing flow

```text
Client                            DSS
  │                                │
  ├─ POST /oauth2/token ──────────►│ (Basic auth, client_credentials)
  │◄─── access_token ──────────────┤
  │                                │
  ├─ POST /csc/v2/credentials/info►│ (Bearer token)
  │◄─── certificate chain + key ───┤
  │                                │
  ├─ POST /csc/v2/credentials/authorize ►│ (hash + password)
  │◄─── SAD ───────────────────────┤
  │                                │
  ├─ POST /csc/v2/signatures/signHash ►│ (SAD + hash)
  │◄─── signature ─────────────────┤
```
