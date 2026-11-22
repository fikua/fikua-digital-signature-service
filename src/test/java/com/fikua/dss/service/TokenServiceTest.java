package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties;
import com.fikua.dss.config.DssProperties.CertificateProperties;
import com.fikua.dss.config.DssProperties.CredentialProperties;
import com.fikua.dss.config.DssProperties.UserProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Tokens per user and SADs per credential, with a user that owns two credentials. */
class TokenServiceTest {

    static final String USER = "mock-client";
    static final String OTHER_USER = "other-client";

    private TokenService service;

    /** mock-client owns mock-credential-001 and mock-credential-002; other-client owns other-credential. */
    static DssProperties properties() {
        var a = new CertificateProperties("file:build/test-certs/mock-eseal.crt", "file:build/test-certs/mock-eseal.key");
        var b = new CertificateProperties("file:build/test-certs/other-eseal.crt", "file:build/test-certs/other-eseal.key");
        return new DssProperties(List.of(
                new UserProperties(USER, "mock-secret", List.of(
                        new CredentialProperties("mock-credential-001", "mock-password", a),
                        new CredentialProperties("mock-credential-002", "second-password", b))),
                new UserProperties(OTHER_USER, "other-secret", List.of(
                        new CredentialProperties("other-credential", "other-password", b)))),
                3600, 300);
    }

    @BeforeEach
    void setUp() {
        var credentials = new CredentialService(properties());
        credentials.init();
        service = new TokenService(properties(), credentials);
    }

    @Test
    void issueAccessTokenReturnsATokenOfTheUser() {
        var token = service.issueAccessToken(USER, "mock-secret");
        assertNotNull(token);
        assertEquals(USER, service.resolveUserId(token));
    }

    @Test
    void issueAccessTokenRejectsAnUnknownUser() {
        assertThrows(SecurityException.class, () -> service.issueAccessToken("nobody", "mock-secret"));
    }

    @Test
    void issueAccessTokenRejectsAWrongSecret() {
        assertThrows(SecurityException.class, () -> service.issueAccessToken(USER, "wrong"));
        assertThrows(SecurityException.class, () -> service.issueAccessToken(USER, null));
    }

    @Test
    void anUnknownTokenResolvesToNoUser() {
        assertNull(service.resolveUserId("not-a-real-token"));
    }

    @Test
    void aRevokedTokenResolvesToNoUser() {
        var token = service.issueAccessToken(USER, "mock-secret");
        service.revokeToken(token);
        assertNull(service.resolveUserId(token));
    }

    @Test
    void aSadIsValidOnceForItsUserAndCredential() {
        var sad = service.issueSad(USER, "mock-credential-001", "mock-password");
        assertTrue(service.validateSad(USER, sad, "mock-credential-001"));
        assertFalse(service.validateSad(USER, sad, "mock-credential-001"), "single use");
    }

    @Test
    void eachCredentialOfAUserHasItsOwnPassword() {
        var sad = service.issueSad(USER, "mock-credential-002", "second-password");
        assertTrue(service.validateSad(USER, sad, "mock-credential-002"));
        assertThrows(SecurityException.class,
                () -> service.issueSad(USER, "mock-credential-002", "mock-password"));
    }

    @Test
    void aUserCannotAuthorizeAnotherUsersCredential() {
        assertThrows(SecurityException.class,
                () -> service.issueSad(USER, "other-credential", "other-password"));
    }

    @Test
    void issueSadRejectsAnUnknownCredential() {
        assertThrows(SecurityException.class, () -> service.issueSad(USER, "nope", "mock-password"));
    }

    @Test
    void aSadIsNotValidForAnotherCredentialOrUser() {
        var sad = service.issueSad(USER, "mock-credential-001", "mock-password");
        assertFalse(service.validateSad(USER, sad, "mock-credential-002"));
        assertFalse(service.validateSad(OTHER_USER, sad, "mock-credential-001"));
        assertFalse(service.validateSad(USER, "no-sad", "mock-credential-001"));
        assertFalse(service.validateSad(USER, null, "mock-credential-001"));
    }
}
