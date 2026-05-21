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

- **Image:** `fikua/digital-signature-service` on Docker Hub (public).
- **CI/CD:** `.github/workflows/release.yml` builds and pushes on push to
  `main` (tag `latest`) and on `v*.*.*` tags (semver tags).
- **VPS:** manual deploy via `deploy.sh` to OVH VPS, endpoint
  `mock-qtsp.altia.fikua.com` (endpoint name kept for compatibility with
  existing STG seeds/configs).

## Git workflow

- **Squash merge to `main`.** Conventional Commits.

## References

- CSC API v2.0 spec: <https://cloudsignatureconsortium.org/resources/>
- DSS (European Commission): <https://github.com/esig/dss>
