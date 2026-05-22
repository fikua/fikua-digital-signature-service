# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-05-22

### Security
- **Removed embedded e-seal certificate and private key from the image.**
  Previous versions baked an Altia e-seal cert into `src/main/resources/certs/`
  and shipped it inside the published Docker image. The Docker Hub repository
  was wiped and re-created under the new image name; the embedded key is
  considered compromised and must be rotated wherever it was used.

### Changed
- **Renamed Docker image** to `fikua/fikua-digital-signature-service` (was
  `fikua/digital-signature-service`). Repository renamed to match.
- **Certificate loading is now filesystem-only.** Defaults to
  `file:/certs/mock-eseal.{crt,key}`; the host must mount its own certs
  read-only at runtime.
- `deploy.sh` now goes through Cloudflare Tunnel (`vps.fikua.com`) instead of
  raw SSH + port 49222.
- `docker-compose.yml` mounts `./certs:/certs:ro` and points at the new image
  name + filesystem defaults.

### Added
- `LICENSE` (Apache-2.0, copyright Fikua) and `NOTICE` file.
- `.dockerignore` blocking any cert/key material from being baked into images.
- `.gitignore` hardened with `**/certs/`, `*.pem`, `*.key`, `*.crt`, `*.p12`,
  `*.pfx`, `*.jks`.
- README rewritten with mock-cert quick-start and Apache-2.0 license note.

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
