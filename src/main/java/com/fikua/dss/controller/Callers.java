package com.fikua.dss.controller;

import com.fikua.dss.audit.AuditEvents;
import com.fikua.dss.audit.AuditEvents.Reason;
import com.fikua.dss.dto.common.ErrorResponse;
import com.fikua.dss.service.AccessTokens;
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
    private final AccessTokens accessTokens;
    private final CredentialService credentials;
    private final AuditEvents audit;

    Callers(TokenService tokenService, AccessTokens accessTokens, CredentialService credentials, AuditEvents audit) {
        this.tokenService = tokenService;
        this.accessTokens = accessTokens;
        this.credentials = credentials;
        this.audit = audit;
    }

    /** The user of the bearer token, or the 401 (503 when its issuer does not answer) to answer. */
    Caller fromBearer(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return Caller.error(ResponseEntity.status(401).body(
                    new ErrorResponse("unauthorized", "Missing Bearer token")));
        }
        User user;
        try {
            user = credentials.user(userId(authHeader.substring(7)));
        } catch (AccessTokens.Unavailable e) {
            return Caller.error(ResponseEntity.status(503).body(
                    new ErrorResponse("temporarily_unavailable", "The access token cannot be checked now")));
        }
        if (user == null) {
            audit.refused(null, Reason.INVALID_TOKEN);
            return Caller.error(ResponseEntity.status(401).body(
                    new ErrorResponse("unauthorized", "Invalid or expired access token")));
        }
        return Caller.of(user);
    }

    /** The user of a token of this service or, if it is not one, of the authorization server. */
    private String userId(String token) {
        var own = tokenService.resolveUserId(token);
        return own != null ? own : accessTokens.clientId(token);
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
            audit.refused(caller.userId(), Reason.INVALID_SAD);
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
