# Mock QTSP — Repo Guide for Claude

> **Per-repo CLAUDE.md.** Loaded only when working inside this repo. The
> SDD Constitution lives in `../eudistack-platform-dev/CLAUDE.md`.

## Identity

Mock Qualified Trust Service Provider (**QTSP**) implementing CSC API
v2.0 for local development and CI testing. Stands in for real QTSPs
(Altia, Sello de Tiempo, etc.) when developing signing flows in the
Issuer / EBW.

**Never deploy to production.** This is a dev/test fixture.

## Tech stack

- **Java 25** (Gradle toolchain)
- **Spring Boot 3.4.4**
- Small, self-contained service

## Architecture

Minimal hexagonal layout. Implements just the CSC API v2.0 endpoints
needed by Issuer and EBW to test signing flows.

Strict rules (apply because it's Java):
`../eudistack-platform-dev/.claude/rules/hexagonal-discipline.md`.

## Common commands

> **Runs in Docker** as part of `make up` from `eudistack-platform-dev`.

| Task | Command |
|------|---------|
| Compile | `./gradlew compileJava` |
| Tests | `./gradlew test` |
| Full check | `./gradlew check` |
| Rebuild Docker image | `cd ../eudistack-platform-dev && make rebuild-mock-qtsp` |

## CSC API v2.0 endpoints implemented

- `/csc/v2/info`
- `/csc/v2/auth/login`
- `/csc/v2/credentials/list`
- `/csc/v2/credentials/info`
- `/csc/v2/credentials/authorize`
- `/csc/v2/signatures/signHash`

Use the same DTOs that real QTSPs expose so tests can swap targets via
config.

## Where to find specs

`../eudistack-platform-dev/docs/EUDISTACK-10-qtsp-signing/`.

## Git workflow

- **Squash merge to `main`.** Conventional Commits + Story footer.

## References

- Constitution: [`../eudistack-platform-dev/CLAUDE.md`](../eudistack-platform-dev/CLAUDE.md)
- CSC API v2.0 spec: <https://cloudsignatureconsortium.org/resources/>
- Skills: `java-spring-hexagonal`, `commit-conventions`
- Rules: `hexagonal-discipline`, `protocol-compliance`
