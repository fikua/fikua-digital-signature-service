package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties;
import com.fikua.dss.config.DssProperties.CertificateProperties;
import com.fikua.dss.config.DssProperties.TenantProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TokenServiceTest {

    private static final String TENANT_CLIENT_ID = "mock-client";

    private TokenService service;

    @BeforeEach
    void setUp() {
        var tenant = new TenantProperties(
                TENANT_CLIENT_ID,
                "mock-secret",
                "mock-credential-001",
                "mock-password",
                new CertificateProperties("file:/dev/null", "file:/dev/null")
        );
        var props = new DssProperties(List.of(tenant), 3600, 300);
        service = new TokenService(props);
    }

    @Test
    void issueAccessTokenReturnsTokenForValidCredentials() {
        var token = service.issueAccessToken("mock-client", "mock-secret");
        assertNotNull(token);
        assertTrue(service.validateToken(token));
    }

    @Test
    void issueAccessTokenRejectsWrongClientId() {
        assertThrows(SecurityException.class,
                () -> service.issueAccessToken("nope", "mock-secret"));
    }

    @Test
    void issueAccessTokenRejectsWrongSecret() {
        assertThrows(SecurityException.class,
                () -> service.issueAccessToken("mock-client", "nope"));
    }

    @Test
    void validateTokenReturnsFalseForUnknownToken() {
        assertFalse(service.validateToken("not-a-real-token"));
    }

    @Test
    void revokeTokenInvalidatesIt() {
        var token = service.issueAccessToken("mock-client", "mock-secret");
        service.revokeToken(token);
        assertFalse(service.validateToken(token));
    }

    @Test
    void issueSadReturnsSadForValidCredentialAndPassword() {
        var sad = service.issueSad(TENANT_CLIENT_ID, "mock-credential-001", "mock-password");
        assertNotNull(sad);
        // SAD is single-use: first validation succeeds, second fails.
        assertTrue(service.validateSad(TENANT_CLIENT_ID, sad, "mock-credential-001"));
        assertFalse(service.validateSad(TENANT_CLIENT_ID, sad, "mock-credential-001"));
    }

    @Test
    void issueSadRejectsUnknownCredentialId() {
        assertThrows(SecurityException.class,
                () -> service.issueSad(TENANT_CLIENT_ID, "unknown-credential", "mock-password"));
    }

    @Test
    void issueSadRejectsWrongPassword() {
        assertThrows(SecurityException.class,
                () -> service.issueSad(TENANT_CLIENT_ID, "mock-credential-001", "wrong"));
    }

    @Test
    void validateSadReturnsFalseForUnknownSad() {
        assertFalse(service.validateSad(TENANT_CLIENT_ID, "no-sad", "mock-credential-001"));
    }

    @Test
    void validateSadReturnsFalseWhenCredentialIdMismatches() {
        var sad = service.issueSad(TENANT_CLIENT_ID, "mock-credential-001", "mock-password");
        assertFalse(service.validateSad(TENANT_CLIENT_ID, sad, "other-credential"));
    }

    @Test
    void validateSadReturnsFalseWhenTenantMismatches() {
        var sad = service.issueSad(TENANT_CLIENT_ID, "mock-credential-001", "mock-password");
        assertFalse(service.validateSad("other-tenant", sad, "mock-credential-001"));
    }
}
