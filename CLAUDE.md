# Digital Signature Service — Repo Guide for Claude

> **Per-repo CLAUDE.md.** Loaded only when working inside this repo.

## Identity

Spring Boot service implementing the **Cloud Signature Consortium (CSC) API
v2.0**. Initial mode is a mock QTSP for local development and CI testing
of signing flows (Issuer / EBW). Roadmap: incorporate real DSS (Digital
Signature Service — European Commission).

**Mock mode is dev/test only — never deploy to production as a real QTSP.**

## Tech stack

- **Java 25** (Gradle toolchain)
- **Spring Boot 3.4.4**
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

Use the same DTOs that real QTSPs expose so tests can swap targets via
config.

## Release & deployment

- **Image:** `fikua/fikua-digital-signature-service` on Docker Hub (public).
- **Repo:** `github.com/fikua/fikua-digital-signature-service` (public, Apache-2.0).
- **CI/CD:** `.github/workflows/release.yml` builds and pushes on push to
  `main` (tag `latest`) and on `v*.*.*` tags (semver tags).
- **VPS:** manual deploy via `deploy.sh` (uses `vps.fikua.com` SSH via
  Cloudflare Tunnel). Public endpoint `mock-qtsp.altia.fikua.com` (name
  kept for compatibility with existing STG seeds/configs).

## Certificates — never bake into the image

- The image MUST NOT contain any cert or private key. `src/main/resources/`
  has no `certs/` folder; `.dockerignore` blocks it defensively.
- Defaults point at `file:/certs/mock-eseal.{crt,key}`; the host mounts
  its own `certs/` directory read-only into `/certs/` at runtime.
- A previous version (≤ 0.2.0) embedded an Altia e-seal key in the JAR —
  that key has been considered compromised and the Docker Hub repo was
  wiped and re-created under a new name. Do not regress.

## Git workflow

- **Squash merge to `main`.** Conventional Commits.

## References

- CSC API v2.0 spec: <https://cloudsignatureconsortium.org/resources/>
- DSS (European Commission): <https://github.com/esig/dss>
