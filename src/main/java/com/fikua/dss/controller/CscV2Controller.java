package com.fikua.dss.controller;

import com.fikua.dss.audit.AuditEvents;
import com.fikua.dss.audit.AuditEvents.Reason;
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
import com.fikua.dss.service.CredentialService;
import com.fikua.dss.service.SigningService;
import com.fikua.dss.web.InvalidRequestException;
import com.fikua.dss.service.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

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

    private final TokenService tokenService;
    private final Callers callers;
    private final SigningService signingService;
    private final AuditEvents audit;

    public CscV2Controller(
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

    @PostMapping("/info")
    public ResponseEntity<?> info(@RequestBody(required = false) Object body) {
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
                        List.of("C", "J"),
                        List.of(List.of("Detached"), List.of("Enveloping")),
                        false),
                List.of("AdES-B-B")
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
                caller.user().credentialIds(), null, null));
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


        var keyInfo = new KeyInfo(
                "enabled",
                List.of(credential.getKeyAlgorithmOid()),
                credential.getKeyLength()
        );
        var certInfo = new CertInfo(
                "valid",
                credential.certificateChainBase64(),
                credential.issuerName(),
                credential.serialNumberHex(),
                credential.subjectName(),
                credential.validFrom(),
                credential.validTo()
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
        var caller = callers.fromBearer(authHeader);
        if (caller.error() != null) return caller.error();

        var password = extractPassword(request.authData());
        if (password == null) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Missing password in authData"));
        }

        try {
            var sad = tokenService.issueSad(caller.userId(), request.credentialID(), password);
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

        if (request.hashes() == null || request.hashes().isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("invalid_request", "Missing hashes in request"));
        }

        var signatures = signingService.signHashes(request.hashes(), request.hashAlgorithmOID(), credential);
        audit.credentialSigned(caller.userId(), request.credentialID(), signatures.size(), "v2");
        return ResponseEntity.ok(new SignHashResponse(signatures, null));
    }

    @PostMapping("/signatures/signDoc")
    public ResponseEntity<?> signDoc(
            @RequestHeader("Authorization") String authHeader,
            @RequestBody SignDocRequest request
    ) {
        var caller = callers.fromBearer(authHeader);
        if (caller.error() != null) return caller.error();

        var credential = callers.authorized(caller, request.SAD(), request.credentialID());
        if (credential == null) {
            return Callers.invalidSad();
        }

        // CSC v2 input modes: documents (the service builds the AdES signature,
        // SigningService) or documentDigests (precomputed hashes, signed as in signHash).
        if (request.documents() != null && !request.documents().isEmpty()) {
            return signDocuments(request, caller, credential);
        }
        if (request.documentDigests() != null && !request.documentDigests().isEmpty()) {
            return signDocumentDigests(request, caller, credential);
        }

        return ResponseEntity.badRequest().body(
                new ErrorResponse("invalid_request", "Either 'documents' or 'documentDigests' must be provided"));
    }

    private ResponseEntity<SignDocResponse> signDocuments(SignDocRequest request, Callers.Caller caller,
                                                         CredentialService.Credential credential) {
        var withSignature = new ArrayList<String>();
        var signatureObjects = new ArrayList<String>();
        for (var doc : request.documents()) {
            var signed = signingService.signDocument(decodeDocument(doc.document()),
                    doc.signature_format(), doc.conformance_level(), credential);
            if (signed.documentWithSignature() != null) withSignature.add(signed.documentWithSignature());
            if (signed.signatureObject() != null) signatureObjects.add(signed.signatureObject());
        }
        audit.credentialSigned(caller.userId(), request.credentialID(),
                request.documents().size(), "v2");
        return ResponseEntity.ok(new SignDocResponse(
                withSignature.isEmpty() ? null : withSignature,
                signatureObjects.isEmpty() ? null : signatureObjects, null, null));
    }

    private ResponseEntity<SignDocResponse> signDocumentDigests(SignDocRequest request, Callers.Caller caller,
                                                               CredentialService.Credential credential) {
        var allHashes = new ArrayList<String>();
        for (var dd : request.documentDigests()) {
            if (dd.hashes() != null) allHashes.addAll(dd.hashes());
        }
        var signatures = signingService.signHashes(allHashes, request.hashAlgorithmOID(), credential);
        audit.credentialSigned(caller.userId(), request.credentialID(), signatures.size(), "v2");
        return ResponseEntity.ok(new SignDocResponse(null, signatures, null, null));
    }

    private static byte[] decodeDocument(String documentBase64) {
        try {
            return Base64.getDecoder().decode(documentBase64);
        } catch (IllegalArgumentException | NullPointerException _) {
            throw new InvalidRequestException("Document is not base64");
        }
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
