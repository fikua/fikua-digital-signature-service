# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
