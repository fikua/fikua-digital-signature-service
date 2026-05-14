# TD — `eudistack-core-issuer` CSC v2 conformance migration

> **Status:** pending implementation
> **Owner:** Backend team (Albert Rodríguez)
> **Blocking:** deployment of `eudistack-platform-mock-qtsp` branch `feature/csc-dual-v1-v2` to any environment hit by the production-like Issuer
> **Last audit:** 2026-05-14 (reviewer subagent, pre-deploy compatibility audit)

## Why this exists

Branch `feature/csc-dual-v1-v2` (commit `43d8da3`) of `eudistack-platform-mock-qtsp` split the CSC API into two strict version-conformant surfaces (`/csc/v1` → CSC 1.0.3.0 and `/csc/v2` → CSC 2.1.0.1). The old hybrid `CscController` was removed.

Today `eudistack-core-issuer` calls `/csc/v2/...` with a **non-conformant hybrid body** (v1-shape `hash`+`hashAlgo`, String-encoded Booleans, placeholder OIDs). It happened to work against the previous hybrid mock because both sides were equally non-conformant. Against the new strict v2 controller it will fail.

A static analysis audit estimates **5% probability of a successful end-to-end credential signing** if the new mock is deployed without first migrating the Issuer.

## Decision (already taken)

- All flows migrate to **CSC v2 conformant body** (no per-flow split between v1 and v2).
- `CscSignDocSigningProvider` is **legacy / dead code** in production (all tenants use `remote_sign_path="sign-hash"` per seed migrations) but is **fixed alongside signHash** to keep its tests green and the surface area complete.
- The Issuer rama is `feature/csc-v2-conformance` in `eudistack-core-issuer` (paralela, no se mezcla con esta).

## Blockers found

### B1 — `signHash` request: v1 field names

**File:** `src/main/java/es/in2/issuer/backend/signing/infrastructure/qtsp/signhash/QtspSignHashClient.java`

| Line | Before | After |
|------|--------|-------|
| 53 | `body.put("hash", List.of(hashB64Url));` | `body.put("hashes", List.of(hashB64Url));` |
| 54 | `body.put("hashAlgo", hashAlgoOid);` | `body.put("hashAlgorithmOID", hashAlgoOid);` |
| 101 | `body.put("hash", List.of(hashB64Url));` | `body.put("hashes", List.of(hashB64Url));` |
| 102 | `body.put("hashAlgo", hashAlgoOid);` | `body.put("hashAlgorithmOID", hashAlgoOid);` |

**Failure mode today:** Jackson silently drops unknown fields; mock's `SignHashRequest.hashes()` returns `null`; `SigningService.signHashes(null)` NPEs at the `for` loop.

### B2 — `credentials/info` request: String-encoded Booleans

**File:** `src/main/java/es/in2/issuer/backend/signing/domain/service/impl/QtspIssuerServiceImpl.java`

| Line | Before | After |
|------|--------|-------|
| 119 | `requestBody.put(CERT_INFO, "true");` | `requestBody.put(CERT_INFO, true);` |
| 120 | `requestBody.put(AUTH_INFO, "true");` | `requestBody.put(AUTH_INFO, true);` |

**Failure mode today:** the mock's `CredentialsInfoRequest` declares `Boolean certInfo` / `Boolean authInfo`. Jackson without `MapperFeature.ALLOW_COERCION_OF_SCALARS` rejects `"true"` String → `Boolean` and returns HTTP 400 `HttpMessageNotReadableException`.

> **Note:** `validateCertificate()` (same file, lines 227–228) already sends `true` as a real Boolean — no change needed there. Only `fetchCertificateInfoFromQtsp()` is wrong.

### B3 (formerly W4 + W3) — `signDoc` request + response handling

**File:** `src/main/java/es/in2/issuer/backend/signing/domain/service/impl/RemoteSignatureServiceImpl.java`

| Line | Before | After |
|------|--------|-------|
| 243 | `conformance_level: "Ades-B"` | `conformance_level: "Ades-B-B"` *(literal from CSC v2.1.0.1 example; switch to `"AdES-B-B"` only if migrating to v2.2 spec)* |
| 244 | `signAlgo: "OID_sign_algorithm"` (placeholder) | Derive from cert info, identical to `JwsSignHashServiceImpl:62` (e.g. `certificateService.getKeyAlgorithmOid()`) |
| 278–286 | `processSignatureResponse` base64-decodes `DocumentWithSignature` and calls `jwtUtils.decodePayload`, expecting a JWS (`header.payload.sig`). | The new mock returns the raw signature (no JWS wrap). Either (a) the Issuer wraps it into a JWS after receiving, or (b) the mock is changed to return a JWS — needs design decision. |

> **Open question for B3 line 278–286:** the JWS wrapping was implicitly delegated to the QTSP in the old mock. CSC v2 spec does not mandate this — the response `DocumentWithSignature` is server-format-dependent. Recommended: the Issuer wraps signature into JWS itself, mock returns raw signature only.

### W2 (lower-risk) — `lang` integer where String expected

**File:** `src/main/java/es/in2/issuer/backend/signing/domain/service/impl/QtspIssuerServiceImpl.java`

| Line | Before | After |
|------|--------|-------|
| 230 | `requestBody.put(LANG, 0);` | `requestBody.put(LANG, "en-US");` or remove |

Cosmetic. Jackson silently coerces today.

## Tests to update

After the changes above, these test classes need to be updated to assert the new shapes:

- `QtspSignHashClientTest` — expects `hashes` / `hashAlgorithmOID` in serialised body
- `CscSignHashSigningProviderTest`
- `JwsSignHashServiceImplTest`
- `CscSignDocSigningProviderTest`
- `RemoteSignatureServiceImplTest` — expects `Ades-B-B`, derived `signAlgo`, and the JWS-wrap-on-client design (see B3 open question)

## Validation plan

1. Local: `./gradlew check` in `eudistack-core-issuer` after changes.
2. Joint smoke against the new mock-qtsp `feature/csc-dual-v1-v2`:
   - Start mock-qtsp on `:9090` (java -jar) — see `README.md` of mock-qtsp repo.
   - Point Issuer's `tenant_signing_config` to `http://localhost:9090` for the sandbox tenant.
   - Trigger SD-JWT credential issuance via the Issuer's API.
   - Verify: HTTP 200 across all 4 QTSP calls (token → list → info → authorize → signHash), final JWT signature verifies against the cert in the mock's `info` response.
3. Only after #2 passes: deploy mock-qtsp to VPS.

## Out-of-scope risks (not derivable from static analysis)

- **ENV / runtime `tenant_signing_config` mismatch on VPS** — `credentialId`, `credentialPassword`, `clientId`, `clientSecret` must align between the Issuer's DB row and the mock's `MockQtspProperties`.
- **NGINX/proxy path rewriting** — verify `/csc/v2/...` is forwarded verbatim to the mock container.
- **Spring `DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES`** — if the mock's ObjectMapper is ever switched to fail-on-unknown, the v1-shape fields would 400 instead of being silently dropped. Currently does not happen (Spring Boot default is `false`), but worth noting.

## Confidence after this TD is implemented

Static-analysis estimate: **>90%** probability of successful end-to-end signing against the new mock. The remaining ~10% is reserved for the runtime/infra concerns listed above.

## References

- Mock branch: `feature/csc-dual-v1-v2` in `eudistack-platform-mock-qtsp` (commit `43d8da3`)
- CSC v1 spec: `csc_openapi_1.0.3.0.json` (bundled in mock-qtsp repo root)
- CSC v2 spec: `csc_openapi_2.1.0.1.yaml` (bundled in mock-qtsp repo root)
- Audit transcript: session 2026-05-14, reviewer subagent
