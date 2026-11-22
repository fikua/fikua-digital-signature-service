package com.fikua.dss.controller;

import com.fikua.dss.audit.AuditEvents;
import com.fikua.dss.audit.AuditEvents.Reason;
import com.fikua.dss.dto.common.ErrorResponse;
import com.fikua.dss.service.CredentialService;
import com.fikua.dss.service.CredentialService.Credential;
import com.fikua.dss.service.CredentialService.User;
import com.fikua.dss.service.TokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * Who is calling a CSC endpoint, from its bearer token, and which of its
 * credentials a SAD authorizes. Shared by the v1 and v2 controllers.
 */
@Component
class Callers {

    private final TokenService tokenService;
    private final CredentialService credentials;
    private final AuditEvents audit;

    Callers(TokenService tokenService, CredentialService credentials, AuditEvents audit) {
        this.tokenService = tokenService;
        this.credentials = credentials;
        this.audit = audit;
    }

    /** The user of the bearer token, or the 401 to answer. */
    Caller fromBearer(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return Caller.error(ResponseEntity.status(401).body(
                    new ErrorResponse("unauthorized", "Missing Bearer token")));
        }
        var user = credentials.user(tokenService.resolveUserId(authHeader.substring(7)));
        if (user == null) {
            audit.authRejected(null, Reason.INVALID_TOKEN);
            return Caller.error(ResponseEntity.status(401).body(
                    new ErrorResponse("unauthorized", "Invalid or expired access token")));
        }
        return Caller.of(user);
    }

    /** One of the caller's credentials, or null when it is not theirs. */
    Credential credential(Caller caller, String credentialId) {
        return credentials.credential(caller.userId(), credentialId);
    }

    /**
     * The credential a valid SAD of this caller authorizes (the SAD is spent),
     * or null; a refusal is audited.
     */
    Credential authorized(Caller caller, String sad, String credentialId) {
        var credential = credential(caller, credentialId);
        if (credential == null || !tokenService.validateSad(caller.userId(), sad, credentialId)) {
            audit.authRejected(caller.userId(), Reason.INVALID_SAD);
            return null;
        }
        return credential;
    }

    static ResponseEntity<ErrorResponse> invalidSad() {
        return ResponseEntity.status(401).body(new ErrorResponse("invalid_sad", "SAD is invalid or expired"));
    }

    /** The authenticated user of a request, or the error response when there is none. */
    record Caller(User user, ResponseEntity<ErrorResponse> error) {
        static Caller of(User user) {
            return new Caller(user, null);
        }

        static Caller error(ResponseEntity<ErrorResponse> error) {
            return new Caller(null, error);
        }

        String userId() {
            return user.id();
        }
    }
}
