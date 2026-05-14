package es.in2.mockqtsp.controller;

import es.in2.mockqtsp.config.MockQtspProperties;
import es.in2.mockqtsp.dto.common.ErrorResponse;
import es.in2.mockqtsp.dto.v2.Auth;
import es.in2.mockqtsp.dto.v2.CertInfo;
import es.in2.mockqtsp.dto.v2.CredentialsAuthorizeRequest;
import es.in2.mockqtsp.dto.v2.CredentialsAuthorizeResponse;
import es.in2.mockqtsp.dto.v2.CredentialsInfoRequest;
import es.in2.mockqtsp.dto.v2.CredentialsInfoResponse;
import es.in2.mockqtsp.dto.v2.CredentialsListRequest;
import es.in2.mockqtsp.dto.v2.CredentialsListResponse;
import es.in2.mockqtsp.dto.v2.InfoResponse;
import es.in2.mockqtsp.dto.v2.KeyInfo;
import es.in2.mockqtsp.dto.v2.SignDocRequest;
import es.in2.mockqtsp.dto.v2.SignDocResponse;
import es.in2.mockqtsp.dto.v2.SignHashRequest;
import es.in2.mockqtsp.dto.v2.SignHashResponse;
import es.in2.mockqtsp.service.CertificateService;
import es.in2.mockqtsp.service.SigningService;
import es.in2.mockqtsp.service.TokenService;
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

    private final MockQtspProperties properties;
    private final TokenService tokenService;
    private final CertificateService certificateService;
    private final SigningService signingService;

    public CscV2Controller(
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

    @PostMapping("/info")
    public ResponseEntity<?> info(@RequestBody(required = false) Object body) {
        log.info("POST /csc/v2/info");
        return ResponseEntity.ok(new InfoResponse(
                "2.0.0.0",
                "EUDIStack Mock QTSP",
                "",
                "ES",
                "en-US",
                "Mock QTSP for development and testing. NOT for production use.",
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
                List.of(new InfoResponse.SignAlgorithm(certificateService.getKeyAlgorithmOid())),
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
        var error = validateBearer(authHeader);
        if (error != null) return error;
        return ResponseEntity.ok(new CredentialsListResponse(
                List.of(properties.credentialId()), null, null));
    }

    @PostMapping("/credentials/info")
    public ResponseEntity<?> credentialsInfo(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody CredentialsInfoRequest request
    ) {
        log.info("POST /csc/v2/credentials/info credentialID={}", request.credentialID());
        var error = validateBearer(authHeader);
        if (error != null) return error;

        if (!properties.credentialId().equals(request.credentialID())) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Unknown credential ID"));
        }

        var cert = certificateService.getCertificateChain().getFirst();
        var df = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));

        var keyInfo = new KeyInfo(
                "enabled",
                List.of(certificateService.getKeyAlgorithmOid()),
                certificateService.getKeyLength()
        );
        var certInfo = new CertInfo(
                "valid",
                certificateService.getCertificateChainBase64(),
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
                        "PIN", "Please enter the signature PIN"))
        );

        return ResponseEntity.ok(new CredentialsInfoResponse(
                null, null, keyInfo, certInfo, auth, "1", 1, "en-US"));
    }

    @PostMapping("/credentials/authorize")
    public ResponseEntity<?> credentialsAuthorize(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody CredentialsAuthorizeRequest request
    ) {
        log.info("POST /csc/v2/credentials/authorize credentialID={} numSignatures={}",
                request.credentialID(), request.numSignatures());
        var error = validateBearer(authHeader);
        if (error != null) return error;

        var password = extractPassword(request.authData());
        if (password == null) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Missing PIN in authData"));
        }

        try {
            var sad = tokenService.issueSad(request.credentialID(), password);
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
        log.info("POST /csc/v2/signatures/signHash credentialID={} hashes={}",
                request.credentialID(), request.hashes() != null ? request.hashes().size() : 0);
        var error = validateBearer(authHeader);
        if (error != null) return error;

        if (!tokenService.validateSad(request.SAD(), request.credentialID())) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_sad", "SAD is invalid or expired"));
        }

        var signatures = signingService.signHashes(request.hashes());
        return ResponseEntity.ok(new SignHashResponse(signatures, null));
    }

    @PostMapping("/signatures/signDoc")
    public ResponseEntity<?> signDoc(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody SignDocRequest request
    ) {
        log.info("POST /csc/v2/signatures/signDoc credentialID={} documents={} documentDigests={}",
                request.credentialID(),
                request.documents() != null ? request.documents().size() : 0,
                request.documentDigests() != null ? request.documentDigests().size() : 0);
        var error = validateBearer(authHeader);
        if (error != null) return error;

        if (!tokenService.validateSad(request.SAD(), request.credentialID())) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_sad", "SAD is invalid or expired"));
        }

        // CSC v2 supports two input modes: documents (full doc to sign) or documentDigests (precomputed hashes).
        // Mock implements documents mode (current Issuer behaviour); documentDigests mode would also be valid.
        if (request.documents() != null && !request.documents().isEmpty()) {
            var docs = request.documents().stream()
                    .map(doc -> Base64.getDecoder().decode(doc.document()))
                    .toList();
            var signatures = signingService.signDocuments(docs);

            var signedDocs = new ArrayList<>(signatures);
            return ResponseEntity.ok(new SignDocResponse(signedDocs, signatures, null, null));
        }

        if (request.documentDigests() != null && !request.documentDigests().isEmpty()) {
            var allHashes = new ArrayList<String>();
            for (var dd : request.documentDigests()) {
                if (dd.hashes() != null) allHashes.addAll(dd.hashes());
            }
            var signatures = signingService.signHashes(allHashes);
            return ResponseEntity.ok(new SignDocResponse(null, signatures, null, null));
        }

        return ResponseEntity.badRequest().body(
                new ErrorResponse("invalid_request", "Either 'documents' or 'documentDigests' must be provided"));
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

    private String extractPassword(List<CredentialsAuthorizeRequest.AuthData> authData) {
        if (authData == null) return null;
        return authData.stream()
                .filter(ad -> "password".equalsIgnoreCase(ad.id()) || "PIN".equalsIgnoreCase(ad.id()))
                .map(CredentialsAuthorizeRequest.AuthData::value)
                .findFirst()
                .orElse(null);
    }
}
