package es.in2.mockqtsp.controller;

import es.in2.mockqtsp.config.MockQtspProperties;
import es.in2.mockqtsp.dto.common.ErrorResponse;
import es.in2.mockqtsp.dto.v1.CredentialsAuthorizeRequest;
import es.in2.mockqtsp.dto.v1.CredentialsAuthorizeResponse;
import es.in2.mockqtsp.dto.v1.CredentialsInfoRequest;
import es.in2.mockqtsp.dto.v1.CredentialsInfoResponse;
import es.in2.mockqtsp.dto.v1.CredentialsListRequest;
import es.in2.mockqtsp.dto.v1.CredentialsListResponse;
import es.in2.mockqtsp.dto.v1.InfoResponse;
import es.in2.mockqtsp.dto.v1.SignHashRequest;
import es.in2.mockqtsp.dto.v1.SignHashResponse;
import es.in2.mockqtsp.service.CertificateService;
import es.in2.mockqtsp.service.SigningService;
import es.in2.mockqtsp.service.TokenService;
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

    private final MockQtspProperties properties;
    private final TokenService tokenService;
    private final CertificateService certificateService;
    private final SigningService signingService;

    public CscV1Controller(
            MockQtspProperties properties,
            TokenService tokenService,
            CertificateService certificateService,
            SigningService signingService
    ) {
        this.properties = properties;
        this.tokenService = tokenService;
        this.certificateService = certificateService;
        this.signingService = signingService;
    }

    @GetMapping("/info")
    public ResponseEntity<?> info(@RequestParam(value = "lang", required = false) String lang) {
        log.info("GET /csc/v1/info lang={}", lang);
        return ResponseEntity.ok(new InfoResponse(
                "1.0.3.0",
                "EUDIStack Mock QTSP",
                "",
                "ES",
                lang != null ? lang : "en-US",
                "Mock QTSP for development and testing. NOT for production use.",
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
        var error = validateBearer(authHeader);
        if (error != null) return error;
        return ResponseEntity.ok(new CredentialsListResponse(List.of(properties.credentialId()), null));
    }

    @PostMapping("/credentials/info")
    public ResponseEntity<?> credentialsInfo(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody CredentialsInfoRequest request
    ) {
        log.info("POST /csc/v1/credentials/info credentialID={}", request.credentialID());
        var error = validateBearer(authHeader);
        if (error != null) return error;

        if (!properties.credentialId().equals(request.credentialID())) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Unknown credential ID"));
        }

        var cert = certificateService.getCertificateChain().getFirst();
        var df = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));

        var keyInfo = new CredentialsInfoResponse.KeyInfo(
                "enabled",
                List.of(certificateService.getKeyAlgorithmOid()),
                certificateService.getKeyLength()
        );
        var certInfo = new CredentialsInfoResponse.CertInfo(
                "valid",
                certificateService.getCertificateChainBase64(),
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
        log.info("POST /csc/v1/credentials/authorize credentialID={} numSignatures={}",
                request.credentialID(), request.numSignatures());
        var error = validateBearer(authHeader);
        if (error != null) return error;

        // v1: PIN is the auth secret (OTP optional, ignored for mock)
        if (request.PIN() == null || request.PIN().isBlank()) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Missing PIN"));
        }

        try {
            var sad = tokenService.issueSad(request.credentialID(), request.PIN());
            return ResponseEntity.ok(new CredentialsAuthorizeResponse(sad, properties.sadTtlSeconds()));
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
        log.info("POST /csc/v1/signatures/signHash credentialID={} hashes={}",
                request.credentialID(), request.hash() != null ? request.hash().size() : 0);
        var error = validateBearer(authHeader);
        if (error != null) return error;

        if (!tokenService.validateSad(request.SAD(), request.credentialID())) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_sad", "SAD is invalid or expired"));
        }

        var signatures = signingService.signHashes(request.hash());
        return ResponseEntity.ok(new SignHashResponse(signatures));
    }

    private ResponseEntity<ErrorResponse> validateBearer(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("unauthorized", "Missing Bearer token"));
        }
        var token = authHeader.substring(7);
        if (!tokenService.validateToken(token)) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("unauthorized", "Invalid or expired access token"));
        }
        return null;
    }
}
