package com.fikua.dss.controller;

import com.fikua.dss.dto.*;
import com.fikua.dss.service.CertificateService;
import com.fikua.dss.service.SigningService;
import com.fikua.dss.service.TokenService;
import com.fikua.dss.util.LogSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.TimeZone;

import static net.logstash.logback.argument.StructuredArguments.kv;

@RestController
@RequestMapping("/csc/v2")
public class CscController {

    private static final Logger log = LoggerFactory.getLogger(CscController.class);

    private final TokenService tokenService;
    private final CertificateService certificateService;
    private final SigningService signingService;

    public CscController(
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
        return ResponseEntity.ok(new CscInfoResponse(
                "2.0.0.0",
                "EUDIStack Mock TSP",
                "",
                "ES",
                "en",
                "Mock TSP for development and testing. NOT for production use, NOT qualified.",
                List.of("basic", "oauth2client"),
                List.of(
                        "info",
                        "auth/login",
                        "auth/revoke",
                        "credentials/list",
                        "credentials/info",
                        "credentials/authorize",
                        "signatures/signHash",
                        "signatures/signDoc"
                )
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

        return ResponseEntity.ok(new CredentialsListResponse(List.of(tenantResult.tenant().tenant().credentialId())));
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

        var keyInfo = new CredentialsInfoResponse.KeyInfo(
                "enabled",
                List.of(tenant.getKeyAlgorithmOid()),
                tenant.getKeyLength()
        );

        var certInfo = new CredentialsInfoResponse.CertInfo(
                "valid",
                cert.getIssuerX500Principal().getName(),
                cert.getSubjectX500Principal().getName(),
                cert.getSerialNumber().toString(16),
                df.format(cert.getNotBefore()),
                df.format(cert.getNotAfter()),
                tenant.certificateChainBase64()
        );

        return ResponseEntity.ok(new CredentialsInfoResponse(keyInfo, certInfo));
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
            return ResponseEntity.ok(new CredentialsAuthorizeResponse(sad));
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
                    request.hash() != null ? request.hash().size() : 0);
        }
        var tenantResult = resolveTenant(authHeader);
        if (tenantResult.error() != null) return tenantResult.error();

        if (!tokenService.validateSad(tenantResult.tenantClientId(), request.SAD(), request.credentialID())) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_sad", "SAD is invalid or expired"));
        }

        var signatures = signingService.signHashes(request.hash(), tenantResult.tenant());
        log.info("credential.signed",
                kv("event", "credential.signed"),
                kv("credential_id", LogSanitizer.clean(request.credentialID())),
                kv("signature_count", signatures.size()),
                kv("result", "success"));
        return ResponseEntity.ok(new SignHashResponse(signatures));
    }

    @PostMapping("/signatures/signDoc")
    public ResponseEntity<?> signDoc(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody SignDocRequest request
    ) {
        if (log.isInfoEnabled()) {
            log.info("POST /csc/v2/signatures/signDoc credentialID={} docs={}",
                    LogSanitizer.clean(request.credentialID()),
                    request.documents() != null ? request.documents().size() : 0);
        }
        var tenantResult = resolveTenant(authHeader);
        if (tenantResult.error() != null) return tenantResult.error();

        if (!tokenService.validateSad(tenantResult.tenantClientId(), request.SAD(), request.credentialID())) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_sad", "SAD is invalid or expired"));
        }

        var documents = request.documents().stream()
                .map(doc -> Base64.getDecoder().decode(doc.document()))
                .toList();

        var signatures = signingService.signDocuments(documents, tenantResult.tenant());

        var signedDocs = new ArrayList<String>();
        for (int i = 0; i < request.documents().size(); i++) {
            signedDocs.add(signatures.get(i));
        }

        log.info("credential.signed",
                kv("event", "credential.signed"),
                kv("credential_id", LogSanitizer.clean(request.credentialID())),
                kv("signature_count", signedDocs.size()),
                kv("result", "success"));
        return ResponseEntity.ok(new SignDocResponse(signedDocs));
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
