package com.fikua.dss.controller;

import com.fikua.dss.audit.AuditEvents;
import com.fikua.dss.audit.AuditEvents.Reason;
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
import com.fikua.dss.service.SigningService;
import com.fikua.dss.service.TokenService;
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

    private final TokenService tokenService;
    private final Callers callers;
    private final SigningService signingService;
    private final AuditEvents audit;

    public CscV1Controller(
            TokenService tokenService,
            Callers callers,
            SigningService signingService,
            AuditEvents audit
    ) {
        this.tokenService = tokenService;
        this.callers = callers;
        this.signingService = signingService;
        this.audit = audit;
    }

    @GetMapping("/info")
    public ResponseEntity<?> info(@RequestParam(value = "lang", required = false) String lang) {
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
        var caller = callers.fromBearer(authHeader);
        if (caller.error() != null) return caller.error();

        return ResponseEntity.ok(new CredentialsListResponse(
                caller.user().credentialIds(), null));
    }

    @PostMapping("/credentials/info")
    public ResponseEntity<?> credentialsInfo(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody CredentialsInfoRequest request
    ) {
        var caller = callers.fromBearer(authHeader);
        if (caller.error() != null) return caller.error();
        var credential = callers.credential(caller, request.credentialID());
        if (credential == null) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Unknown credential ID"));
        }

        var cert = credential.certificateChain().getFirst();
        var df = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));

        var keyInfo = new CredentialsInfoResponse.KeyInfo(
                "enabled",
                List.of(credential.getKeyAlgorithmOid()),
                credential.getKeyLength()
        );

        var certInfo = new CredentialsInfoResponse.CertInfo(
                "valid",
                credential.certificateChainBase64(),
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
        var caller = callers.fromBearer(authHeader);
        if (caller.error() != null) return caller.error();

        // v1: PIN is the auth secret (OTP optional, ignored for mock)
        if (request.PIN() == null || request.PIN().isBlank()) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Missing PIN"));
        }

        try {
            var sad = tokenService.issueSad(caller.userId(), request.credentialID(), request.PIN());
            audit.credentialAuthorized(caller.userId(), request.credentialID());
            return ResponseEntity.ok(new CredentialsAuthorizeResponse(sad, null));
        } catch (SecurityException e) {
            audit.refused(caller.userId(), Reason.INVALID_AUTHORIZATION_DATA);
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_request", e.getMessage()));
        }
    }

    @PostMapping("/signatures/signHash")
    public ResponseEntity<?> signHash(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody SignHashRequest request
    ) {
        var caller = callers.fromBearer(authHeader);
        if (caller.error() != null) return caller.error();

        var credential = callers.authorized(caller, request.SAD(), request.credentialID());
        if (credential == null) {
            return Callers.invalidSad();
        }

        var signatures = signingService.signHashes(request.hash(), request.hashAlgo(), credential);
        audit.credentialSigned(caller.userId(), request.credentialID(), signatures.size(), "v1");
        return ResponseEntity.ok(new SignHashResponse(signatures));
    }


}
