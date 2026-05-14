# Mock QTSP — CSC v1 + v2 API Emulator

Mock implementation of a Qualified Trust Service Provider (QTSP) exposing both the Cloud Signature Consortium (CSC) **v1 (1.0.3.0)** and **v2 (2.1.0.1)** APIs in parallel. Designed for development and testing of the EUDIStack Issuer's remote signing flow, and as a reference contract for any CSC client.

**NOT for production use.** This service uses the same e-seal certificate as the Issuer for signing operations.

## Endpoints

The mock exposes both CSC versions side-by-side. Choose the path prefix that matches your client's CSC version.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth2/token` | OAuth2 client_credentials token endpoint (shared) |
| **CSC v1 (1.0.3.0)** | | |
| GET | `/csc/v1/info?lang=` | Service information (GET in v1) |
| POST | `/csc/v1/credentials/list` | List credentials (no `credentialInfo`/`certificates` filters) |
| POST | `/csc/v1/credentials/info` | Credential and certificate info (returns `authMode`/`PIN`/`OTP`/`multisign`/`lang`) |
| POST | `/csc/v1/credentials/authorize` | Get SAD using `PIN`+`OTP` strings (no `authData` array) |
| POST | `/csc/v1/signatures/signHash` | Sign hashes (request uses `hash`+`hashAlgo`) |
| **CSC v2 (2.1.0.1)** | | |
| POST | `/csc/v2/info` | Service information (POST in v2) |
| POST | `/csc/v2/credentials/list` | List credentials (with `credentialInfo`/`certInfo`/`onlyValid` filters) |
| POST | `/csc/v2/credentials/info` | Credential and certificate info (returns `auth` object) |
| POST | `/csc/v2/credentials/authorize` | Get SAD using `authData[{id,value}]` array |
| POST | `/csc/v2/signatures/signHash` | Sign hashes (request uses `hashes`+`hashAlgorithmOID`) |
| POST | `/csc/v2/signatures/signDoc` | Sign documents — only in v2 |

## CSC v1 vs v2 contract divergences

| Concern | v1 (1.0.3.0) | v2 (2.1.0.1) |
|---------|--------------|--------------|
| `signatures/signHash` hash field | `hash: List<String>` | `hashes: List<String>` |
| `signatures/signHash` algorithm OID field | `hashAlgo: String` | `hashAlgorithmOID: String` |
| `credentials/authorize` auth secret | `PIN: String` + `OTP: String` | `authData: [{id, value}]` array |
| `credentials/info` response auth model | `authMode` + `PIN` + `OTP` + `multisign` + `lang` | `auth: {mode, expression, objects[]}` object |
| `info` HTTP method | `GET ?lang=` | `POST` body |
| `signatures/signDoc` endpoint | **Not defined** | Defined (supports `documents` or `documentDigests`) |
| `info` response v2-only fields | — | `signAlgorithms`, `signature_formats`, `conformance_levels`, `supportsRar`, `validationInfo` |

The reference OpenAPI specs are bundled in this repo at `csc_openapi_1.0.3.0.json` and `csc_openapi_2.1.0.1.yaml`.

### Known spec inconsistencies in CSC v2.1.0.1

The published v2.1.0.1 spec has internal inconsistencies between `required` lists and `properties` blocks (e.g. `input-signatures-signhash.required` lists `hash` but `properties` only defines `hashes`). The implementation follows `properties` consistently. Documented for future migration to v2.2.

### Issuer Core compatibility status

As of this writing, `eudistack-core-issuer` sends `/csc/v2/...` paths with v1-shape bodies (`hash`/`hashAlgo`/`authData`). This is **not conformant** to either CSC version. Until the Issuer migrates to one of:
- `/csc/v1/...` with v1-pure bodies (`PIN`+`OTP`, `hash`+`hashAlgo`), or
- `/csc/v2/...` with v2-pure bodies (`authData`, `hashes`+`hashAlgorithmOID`)

the Issuer will fail against this mock's v2 endpoints (the v2 controller rejects `hash`/`hashAlgo` because they are not defined fields). Tracked as TD-Issuer-csc-conformance.

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
