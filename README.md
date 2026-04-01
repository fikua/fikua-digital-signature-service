# Mock QTSP — CSC v2 API Emulator

Mock implementation of a Qualified Trust Service Provider (QTSP) exposing the Cloud Signature Consortium (CSC) v2 API. Designed for development and testing of the EUDIStack Issuer's remote signing flow.

**NOT for production use.** This service uses the same e-seal certificate as the Issuer for signing operations.

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

1. Place the Issuer's e-seal certificate and key in `./certs/`:
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
java -jar build/libs/mock-qtsp-0.1.0.jar \
  --mock-qtsp.certificate.cert-path=./certs/issuer-eseal.crt \
  --mock-qtsp.certificate.key-path=./certs/issuer-eseal.key
```

## Issuer Configuration

Configure the Issuer to use this mock via the runtime signing config API:

```bash
curl -X PUT http://localhost:8080/internal/signing/config \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "csc-sign-hash",
    "remoteSignature": {
      "type": "cloud",
      "url": "https://mock-qtsp.your-vps.com",
      "clientId": "mock-client",
      "clientSecret": "mock-secret",
      "credentialId": "mock-credential-001",
      "credentialPassword": "mock-password"
    }
  }'
```

## Signing Flow

```
Issuer                              Mock QTSP
  │                                     │
  ├─ POST /oauth2/token ───────────────►│ (Basic auth, client_credentials)
  │◄─── access_token ──────────────────┤
  │                                     │
  ├─ POST /csc/v2/credentials/info ───►│ (Bearer token)
  │◄─── certificate chain + key info ──┤
  │                                     │
  ├─ POST /csc/v2/credentials/authorize►│ (hash + password)
  │◄─── SAD ────────────────────────────┤
  │                                     │
  ├─ POST /csc/v2/signatures/signHash ─►│ (SAD + hash)
  │◄─── signature ─────────────────────┤
  │                                     │
  └─ Assembles JWT: header.payload.sig  │
```
