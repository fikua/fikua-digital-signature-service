package com.fikua.dss.controller;

import com.fikua.dss.dto.common.ErrorResponse;
import com.fikua.dss.dto.v2.Auth;
import com.fikua.dss.dto.v2.CertInfo;
import com.fikua.dss.dto.v2.CredentialsAuthorizeRequest;
import com.fikua.dss.dto.v2.CredentialsAuthorizeResponse;
import com.fikua.dss.dto.v2.CredentialsInfoRequest;
import com.fikua.dss.dto.v2.CredentialsInfoResponse;
import com.fikua.dss.dto.v2.CredentialsListRequest;
import com.fikua.dss.dto.v2.CredentialsListResponse;
import com.fikua.dss.dto.v2.InfoResponse;
import com.fikua.dss.dto.v2.KeyInfo;
import com.fikua.dss.dto.v2.SignDocRequest;
import com.fikua.dss.dto.v2.SignDocResponse;
import com.fikua.dss.dto.v2.SignHashRequest;
import com.fikua.dss.dto.v2.SignHashResponse;
import com.fikua.dss.service.CertificateService;
import com.fikua.dss.service.SigningService;
import com.fikua.dss.service.TokenService;
import com.fikua.dss.util.LogSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.TimeZone;

import static net.logstash.logback.argument.StructuredArguments.kv;

/**
 * CSC API v2 (2.1.0.1) — conformant implementation.
 *
 * Diverges from v1:
 *  - signHash/authorize use `hashes` + `hashAlgorithmOID` (not `hash` + `hashAlgo`).
 *  - authorize uses authData array (not PIN/OTP strings).
 *  - credentials/info response uses `auth` object (not authMode + PIN + OTP).
 *  - info is POST (not GET).
 *  - signDoc endpoint is exposed (only in v2).
 *
 * NOTE: v2.1.0.1 spec has internal inconsistencies between `required` and `properties`
 * (e.g. signHash schema lists `required:[hash]` but properties define `hashes`).
 * Implementation follows `properties` consistently.
 */
@RestController
@RequestMapping("/csc/v2")
public class CscV2Controller {

    private static final Logger log = LoggerFactory.getLogger(CscV2Controller.class);

    private final TokenService tokenService;
    private final CertificateService certificateService;
    private final SigningService signingService;

    public CscV2Controller(
            TokenService tokenService,
            CertificateService certificateService,
            SigningService signingService
    ) {
        this.tokenService = tokenService;
        this.certificateService = certificateService;
        this.signingService = signingService;
    }

    @PostMapping("/info")
    public ResponseEntity<?> info(@RequestBody(required = false) Object body) {
        log.info("POST /csc/v2/info");
        return ResponseEntity.ok(new InfoResponse(
                "2.0.0.0",
                "EUDIStack Mock TSP",
                "",
                "ES",
                "en-US",
                "Mock TSP for development and testing. NOT for production use, NOT qualified.",
                List.of("basic", "oauth2client"),
                null,
                null,
                null,
                false,
                List.of("SHA-256"),
                false,
                List.of(
                        "info",
                        "credentials/list",
                        "credentials/info",
                        "credentials/authorize",
                        "signatures/signHash",
                        "signatures/signDoc"
                ),
                false,
                null,
                List.of("PDF", "JSON"),
                new InfoResponse.SignatureFormats(
                        List.of("C", "P", "J"),
                        List.of(List.of("Detached"), List.of("Enveloped"), List.of("Detached")),
                        false),
                List.of("Ades-B-B", "Ades-B-T")
        ));
    }

    @PostMapping("/credentials/list")
    public ResponseEntity<?> credentialsList(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody(required = false) CredentialsListRequest request
    ) {
        log.info("POST /csc/v2/credentials/list");
        var tenantResult = resolveTenant(authHeader);
        if (tenantResult.error() != null) return tenantResult.error();

        return ResponseEntity.ok(new CredentialsListResponse(
                List.of(tenantResult.tenant().tenant().credentialId()), null, null));
    }

    @PostMapping("/credentials/info")
    public ResponseEntity<?> credentialsInfo(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody CredentialsInfoRequest request
    ) {
        if (log.isInfoEnabled()) {
            log.info("POST /csc/v2/credentials/info credentialID={}",
                    LogSanitizer.clean(request.credentialID()));
        }
        var tenantResult = resolveTenant(authHeader);
        if (tenantResult.error() != null) return tenantResult.error();
        var tenant = tenantResult.tenant();

        if (!tenant.tenant().credentialId().equals(request.credentialID())) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Unknown credential ID"));
        }

        var cert = tenant.certificateChain().getFirst();
        var df = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));

        var keyInfo = new KeyInfo(
                "enabled",
                List.of(tenant.getKeyAlgorithmOid()),
                tenant.getKeyLength()
        );
        var certInfo = new CertInfo(
                "valid",
                tenant.certificateChainBase64(),
                cert.getIssuerX500Principal().getName(),
                cert.getSerialNumber().toString(16),
                cert.getSubjectX500Principal().getName(),
                df.format(cert.getNotBefore()),
                df.format(cert.getNotAfter())
        );
        var auth = new Auth(
                "explicit",
                "PIN",
                List.of(new Auth.AuthObject(
                        "Password", "PIN", "N", null,
                        "PIN", "Please enter the signature PIN")));

        return ResponseEntity.ok(new CredentialsInfoResponse(
                null, null, keyInfo, certInfo, auth, "1", 1, "en-US"));
    }

    @PostMapping("/credentials/authorize")
    public ResponseEntity<?> credentialsAuthorize(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody CredentialsAuthorizeRequest request
    ) {
        if (log.isInfoEnabled()) {
            log.info("POST /csc/v2/credentials/authorize credentialID={} numSignatures={}",
                    LogSanitizer.clean(request.credentialID()), request.numSignatures());
        }
        var tenantResult = resolveTenant(authHeader);
        if (tenantResult.error() != null) return tenantResult.error();

        var password = extractPassword(request.authData());
        if (password == null) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Missing password in authData"));
        }

        try {
            var sad = tokenService.issueSad(tenantResult.tenantClientId(), request.credentialID(), password);
            return ResponseEntity.ok(new CredentialsAuthorizeResponse(sad, null));
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_request", e.getMessage()));
        }
    }

    @PostMapping("/signatures/signHash")
    public ResponseEntity<?> signHash(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody SignHashRequest request
    ) {
        if (log.isInfoEnabled()) {
            log.info("POST /csc/v2/signatures/signHash credentialID={} hashes={}",
                    LogSanitizer.clean(request.credentialID()),
                    request.hashes() != null ? request.hashes().size() : 0);
        }
        var tenantResult = resolveTenant(authHeader);
        if (tenantResult.error() != null) return tenantResult.error();

        if (!tokenService.validateSad(tenantResult.tenantClientId(), request.SAD(), request.credentialID())) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_sad", "SAD is invalid or expired"));
        }

        if (request.hashes() == null || request.hashes().isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Missing hashes in request"));
        }

        var signatures = signingService.signHashes(request.hashes(), tenantResult.tenant());
        log.info("credential.signed",
                kv("event", "credential.signed"),
                kv("credential_id", LogSanitizer.clean(request.credentialID())),
                kv("signature_count", signatures.size()),
                kv("result", "success"));
        return ResponseEntity.ok(new SignHashResponse(signatures, null));
    }

    @PostMapping("/signatures/signDoc")
    public ResponseEntity<?> signDoc(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody SignDocRequest request
    ) {
        if (log.isInfoEnabled()) {
            log.info("POST /csc/v2/signatures/signDoc credentialID={} documents={} documentDigests={}",
                    LogSanitizer.clean(request.credentialID()),
                    request.documents() != null ? request.documents().size() : 0,
                    request.documentDigests() != null ? request.documentDigests().size() : 0);
        }
        var tenantResult = resolveTenant(authHeader);
        if (tenantResult.error() != null) return tenantResult.error();

        if (!tokenService.validateSad(tenantResult.tenantClientId(), request.SAD(), request.credentialID())) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_sad", "SAD is invalid or expired"));
        }

        // CSC v2 supports two input modes: documents (full doc to sign) or documentDigests (precomputed hashes).
        // Mock implements documents mode (current Issuer behaviour); documentDigests mode would also be valid.
        if (request.documents() != null && !request.documents().isEmpty()) {
            var docs = request.documents().stream()
                    .map(doc -> Base64.getDecoder().decode(doc.document()))
                    .toList();
            var signatures = signingService.signDocuments(docs, tenantResult.tenant());

            var signedDocs = new ArrayList<>(signatures);
            log.info("credential.signed",
                    kv("event", "credential.signed"),
                    kv("credential_id", LogSanitizer.clean(request.credentialID())),
                    kv("signature_count", signedDocs.size()),
                    kv("result", "success"));
            return ResponseEntity.ok(new SignDocResponse(signedDocs, signatures, null, null));
        }

        if (request.documentDigests() != null && !request.documentDigests().isEmpty()) {
            var allHashes = new ArrayList<String>();
            for (var dd : request.documentDigests()) {
                if (dd.hashes() != null) allHashes.addAll(dd.hashes());
            }
            var signatures = signingService.signHashes(allHashes, tenantResult.tenant());
            log.info("credential.signed",
                    kv("event", "credential.signed"),
                    kv("credential_id", LogSanitizer.clean(request.credentialID())),
                    kv("signature_count", signatures.size()),
                    kv("result", "success"));
            return ResponseEntity.ok(new SignDocResponse(null, signatures, null, null));
        }

        return ResponseEntity.badRequest().body(
                new ErrorResponse("invalid_request", "Either 'documents' or 'documentDigests' must be provided"));
    }

    private TenantResolution resolveTenant(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return TenantResolution.error(ResponseEntity.status(401).body(
                    new ErrorResponse("unauthorized", "Missing Bearer token")));
        }
        var token = authHeader.substring(7);
        var tenantClientId = tokenService.resolveTenantClientId(token);
        if (tenantClientId == null) {
            return TenantResolution.error(ResponseEntity.status(401).body(
                    new ErrorResponse("unauthorized", "Invalid or expired access token")));
        }
        var tenant = certificateService.byClientId(tenantClientId);
        return TenantResolution.ok(tenantClientId, tenant);
    }

    private String extractPassword(List<CredentialsAuthorizeRequest.AuthData> authData) {
        if (authData == null) return null;
        return authData.stream()
                .filter(ad -> "password".equalsIgnoreCase(ad.id()) || "PIN".equalsIgnoreCase(ad.id()))
                .map(CredentialsAuthorizeRequest.AuthData::value)
                .findFirst()
                .orElse(null);
    }

    private record TenantResolution(
            String tenantClientId,
            CertificateService.TenantMaterial tenant,
            ResponseEntity<ErrorResponse> error
    ) {
        static TenantResolution ok(String tenantClientId, CertificateService.TenantMaterial tenant) {
            return new TenantResolution(tenantClientId, tenant, null);
        }

        static TenantResolution error(ResponseEntity<ErrorResponse> error) {
            return new TenantResolution(null, null, error);
        }
    }
}
