# Digital Signature Service — Repo Guide for Claude

> **Per-repo CLAUDE.md.** Loaded only when working inside this repo.

## Identity

Spring Boot service implementing the **Cloud Signature Consortium (CSC) API
v2.0**. Initial mode is a mock TSP (not qualified) for local development
and CI testing of signing flows (Issuer / EBW). Roadmap: incorporate real
DSS (Digital Signature Service — European Commission).

**Mock mode is dev/test only — never deploy to production as a real
(qualified) TSP.**

**Names.** The product is **Fikua Sign** (until 2026-11 "Fikua DSS"; the repository,
image, hostname, realm, audience and configuration keys keep `dss` until they are
renamed in a task of their own). "EU DSS" is the European Commission's
library and demonstrations (`esig/dss`), which this service uses and which other
systems also run on their own. Write one or the other, never "the DSS" alone,
where both can be meant.

## Users and credentials

`dss.users` is a list of users (CSC v2): each is an OAuth2 client
(client-id/secret) with one or more credentials (id, password, certificate).
`TokenService` resolves the user from the access token, never from a
client-supplied value, and `CredentialService.credential(userId, id)` only
returns a credential the user owns, so one user's token can never list,
inspect, authorize, or sign with another user's credential. See
`UserIsolationTest`. Never call them "tenants" again.

## Tech stack

- **Java 25** (Gradle toolchain)
- **Spring Boot 4.2**
- Small, self-contained service

## Architecture

Minimal hexagonal layout. Java package root: `com.fikua.dss`. Implements
the CSC API v2.0 endpoints needed by Issuer and EBW to test signing flows.

## Common commands

| Task        | Command                |
| ----------- | ---------------------- |
| Compile     | `./gradlew compileJava`|
| Tests       | `./gradlew test`       |
| Full check  | `./gradlew check`      |
| Build JAR   | `./gradlew bootJar`    |
| Run locally | `./gradlew bootRun`    |

## CSC API v2.0 endpoints implemented

- `/csc/v2/info`
- `/csc/v2/credentials/list`
- `/csc/v2/credentials/info`
- `/csc/v2/credentials/authorize`
- `/csc/v2/signatures/signHash`
- `/csc/v2/signatures/signDoc`

Use the same DTOs that real TSPs expose so tests can swap targets via
config.

## Release & deployment

- **Image:** `ghcr.io/fikua/fikua-digital-signature-service` (also Docker Hub until ADR 0015 closes it).
- **Repo:** `github.com/fikua/fikua-digital-signature-service` (public, Apache-2.0).
- **CI:** `.github/workflows/ci.yml` (shared workflows) publishes `latest`
  and `sha-<short>` on push to `main`, and `X.Y.Z` on `v*.*.*` tags.
- **VPS:** never deployed from here. `fikua-platform-iac/projects/fikua-digital-signature-service/compose.yaml`
  pins the release; Dependabot there proposes new ones (fikua-docs ADR 0019).
  Public endpoint: `dss.fikua.com`.

## Certificates — never bake into the image

- The image MUST NOT contain any cert or private key. `src/main/resources/`
  has no `certs/` folder; `.dockerignore` blocks it defensively.
- Defaults point at `file:/certs/mock-eseal.{crt,key}` (the local user); the host
  mounts its own `certs/` directory read-only into `/certs/` at runtime.
  Each credential mounts its own cert/key under its own subpath (see
  README "Configuration").
- A previous version (≤ 0.2.0) embedded an Altia e-seal key in the JAR —
  that key has been considered compromised and the Docker Hub repo was
  wiped and re-created under a new name. Do not regress.
- **Users of the configuration:** their leaves are issued under one test CA
  (`Fikua DSS Mock TSP Root CA (test)`) and their keys are mounted as files.
  Issue no new leaf under it.
- **Since 0.12.0 (fikua-docs ADR 0022, accepted; #9):** Fikua Sign creates the
  keys of the credentials of its database, gives a CSR and activates the
  credential with the certificate of an issuing CA that is outside the service.
  It never imports or returns a private key: no PKCS#12 upload, no
  `loadPrivateKey`. The credentials of the configuration are replaced, not
  migrated.
- Outside local development, never sign with a self-signed certificate. The only exception is the list
  signer (ETSI TS 119 612, clause 5.7.1), created by an operator command, not by
  the API.

## Git workflow

- **Squash merge to `main`.** Conventional Commits.

## References

- CSC API v2.0 spec: <https://cloudsignatureconsortium.org/resources/>
- DSS (European Commission): <https://github.com/esig/dss>
