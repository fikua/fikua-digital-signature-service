package com.fikua.dss.controller;

import com.fikua.dss.dto.common.ErrorResponse;
import com.fikua.dss.dto.v1.CredentialsAuthorizeRequest;
import com.fikua.dss.dto.v1.CredentialsAuthorizeResponse;
import com.fikua.dss.dto.v1.CredentialsInfoRequest;
import com.fikua.dss.dto.v1.CredentialsInfoResponse;
import com.fikua.dss.dto.v1.CredentialsListRequest;
import com.fikua.dss.dto.v1.CredentialsListResponse;
import com.fikua.dss.dto.v1.InfoResponse;
import com.fikua.dss.dto.v1.SignHashRequest;
import com.fikua.dss.dto.v1.SignHashResponse;
import com.fikua.dss.service.CertificateService;
import com.fikua.dss.service.SigningService;
import com.fikua.dss.service.TokenService;
import com.fikua.dss.util.LogSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.text.SimpleDateFormat;
import java.util.List;
import java.util.TimeZone;

import static net.logstash.logback.argument.StructuredArguments.kv;

/**
 * CSC API v1 (1.0.3.0) — strict conformance.
 *
 * Diverges from v2:
 *  - signHash/authorize use `hash` + `hashAlgo` (not `hashes` + `hashAlgorithmOID`).
 *  - authorize uses PIN + OTP strings (not authData array).
 *  - credentials/info response uses authMode + PIN + OTP + multisign + lang (not auth object).
 *  - info is GET ?lang= (not POST).
 *  - signDoc endpoint is NOT defined in v1.
 */
@RestController
@RequestMapping("/csc/v1")
public class CscV1Controller {

    private static final Logger log = LoggerFactory.getLogger(CscV1Controller.class);

    private final TokenService tokenService;
    private final CertificateService certificateService;
    private final SigningService signingService;

    public CscV1Controller(
            TokenService tokenService,
            CertificateService certificateService,
            SigningService signingService
    ) {
        this.tokenService = tokenService;
        this.certificateService = certificateService;
        this.signingService = signingService;
    }

    @GetMapping("/info")
    public ResponseEntity<?> info(@RequestParam(value = "lang", required = false) String lang) {
        log.info("GET /csc/v1/info lang={}", LogSanitizer.clean(lang));
        return ResponseEntity.ok(new InfoResponse(
                "1.0.3.0",
                "EUDIStack Mock TSP",
                "",
                "ES",
                lang != null ? lang : "en-US",
                "Mock TSP for development and testing. NOT for production use, NOT qualified.",
                List.of("basic", "oauth2client"),
                null,
                List.of(
                        "auth/login",
                        "auth/revoke",
                        "credentials/list",
                        "credentials/info",
                        "credentials/authorize",
                        "signatures/signHash"
                )
        ));
    }

    @PostMapping("/credentials/list")
    public ResponseEntity<?> credentialsList(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody(required = false) CredentialsListRequest request
    ) {
        log.info("POST /csc/v1/credentials/list");
        var tenantResult = resolveTenant(authHeader);
        if (tenantResult.error() != null) return tenantResult.error();

        return ResponseEntity.ok(new CredentialsListResponse(
                List.of(tenantResult.tenant().tenant().credentialId()), null));
    }

    @PostMapping("/credentials/info")
    public ResponseEntity<?> credentialsInfo(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody CredentialsInfoRequest request
    ) {
        if (log.isInfoEnabled()) {
            log.info("POST /csc/v1/credentials/info credentialID={}",
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
                tenant.certificateChainBase64(),
                cert.getIssuerX500Principal().getName(),
                cert.getSerialNumber().toString(16),
                cert.getSubjectX500Principal().getName(),
                df.format(cert.getNotBefore()),
                df.format(cert.getNotAfter())
        );
        var pin = new CredentialsInfoResponse.PinInfo("true", "PIN", "Please enter the signature PIN");
        var otp = new CredentialsInfoResponse.OtpInfo(
                "false", null, null, null, null, null, null);

        return ResponseEntity.ok(new CredentialsInfoResponse(
                null, keyInfo, certInfo, "explicit", null, pin, otp, 1, "en-US"));
    }

    @PostMapping("/credentials/authorize")
    public ResponseEntity<?> credentialsAuthorize(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody CredentialsAuthorizeRequest request
    ) {
        if (log.isInfoEnabled()) {
            log.info("POST /csc/v1/credentials/authorize credentialID={} numSignatures={}",
                    LogSanitizer.clean(request.credentialID()), request.numSignatures());
        }
        var tenantResult = resolveTenant(authHeader);
        if (tenantResult.error() != null) return tenantResult.error();

        // v1: PIN is the auth secret (OTP optional, ignored for mock)
        if (request.PIN() == null || request.PIN().isBlank()) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Missing PIN"));
        }

        try {
            var sad = tokenService.issueSad(tenantResult.tenantClientId(), request.credentialID(), request.PIN());
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
            log.info("POST /csc/v1/signatures/signHash credentialID={} hashes={}",
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
