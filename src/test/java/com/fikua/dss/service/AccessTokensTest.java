package com.fikua.dss.service;

import com.fikua.dss.config.OAuthProperties;
import com.fikua.dss.support.FakeAuthorizationServer;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;

import static com.fikua.dss.support.FakeAuthorizationServer.AUDIENCE;
import static com.fikua.dss.support.FakeAuthorizationServer.ISSUER;
import static com.fikua.dss.support.FakeAuthorizationServer.claims;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AccessTokensTest {

    private FakeAuthorizationServer server;
    private AccessTokens tokens;

    @BeforeEach
    void setUp() {
        server = new FakeAuthorizationServer();
        tokens = new AccessTokens(new OAuthProperties(
                ISSUER, server.jwksUri(), AUDIENCE, Duration.ofMinutes(5), Duration.ofHours(4)));
    }

    @AfterEach
    void tearDown() {
        server.close();
    }

    @Test
    void aValidTokenIsItsClients() {
        assertEquals("user-a", tokens.clientId(server.token("user-a")));
    }

    @Test
    void rejectsATokenSignedWithAnotherKey() {
        var sameId = FakeAuthorizationServer.newKey("key-1");
        var unknownId = FakeAuthorizationServer.newKey("key-2");
        assertNull(tokens.clientId(FakeAuthorizationServer.sign(claims("user-a").build(), sameId)));
        // Repeated: an unknown key id is always a refusal, never an outage.
        for (int i = 0; i < 5; i++) {
            assertNull(tokens.clientId(FakeAuthorizationServer.sign(claims("user-a").build(), unknownId)));
        }
    }

    @Test
    void rejectsOtherAlgorithms() throws Exception {
        assertNull(tokens.clientId(new PlainJWT(claims("user-a").build()).serialize()));
        var hmac = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("key-1").build(),
                claims("user-a").build());
        hmac.sign(new MACSigner(new byte[32]));
        assertNull(tokens.clientId(hmac.serialize()));
    }

    @Test
    void rejectsAnotherIssuer() {
        assertNull(tokens.clientId(server.sign(
                claims("user-a").issuer("https://auth.example.test/realms/fikua").build())));
    }

    @Test
    void rejectsAnotherAudienceOrNone() {
        assertNull(tokens.clientId(server.sign(claims("user-a").audience("account").build())));
        assertNull(tokens.clientId(server.sign(claims("user-a").audience((String) null).build())));
    }

    @Test
    void rejectsAnExpiredTokenOrOneWithoutExpiry() {
        assertNull(tokens.clientId(server.sign(
                claims("user-a").expirationTime(Date.from(Instant.now().minusSeconds(120))).build())));
        assertNull(tokens.clientId(server.sign(claims("user-a").expirationTime(null).build())));
    }

    @Test
    void rejectsATokenWithoutClient() {
        assertNull(tokens.clientId(server.sign(claims(null).build())));
    }

    @Test
    void rejectsWhatIsNotAJwt() {
        assertNull(tokens.clientId("not-a-token"));
        assertNull(tokens.clientId(""));
    }

    @Test
    void theLastKeysAreUsedWhileTheServerDoesNotAnswer() {
        var token = server.token("user-a");
        assertEquals("user-a", tokens.clientId(token));
        server.close();
        // An unknown key id asks for the keys again: the outage falls back to the last ones.
        var forged = FakeAuthorizationServer.sign(claims("user-a").build(), FakeAuthorizationServer.newKey("key-2"));
        assertNull(tokens.clientId(forged));
        assertEquals("user-a", tokens.clientId(token));
    }

    @Test
    void withoutKeysATokenCannotBeJudged() {
        var token = server.token("user-a");
        server.close();
        assertThrows(AccessTokens.Unavailable.class, () -> tokens.clientId(token));
        assertThrows(AccessTokens.Unavailable.class, () -> tokens.clientId(token));
    }

    @Test
    void withoutAnIssuerNoTokenIsAccepted() {
        var off = new AccessTokens(new OAuthProperties("", "", "", Duration.ofMinutes(5), Duration.ofHours(4)));
        assertNull(off.clientId(server.token("user-a")));
    }

    @Test
    void anIssuerNeedsItsKeysAndAudience() {
        var cache = Duration.ofMinutes(5);
        var outage = Duration.ofHours(4);
        var noAudience = new OAuthProperties(ISSUER, server.jwksUri(), "", cache, outage);
        var noKeys = new OAuthProperties(ISSUER, null, AUDIENCE, cache, outage);
        var notAUrl = new OAuthProperties(ISSUER, "keys", AUDIENCE, cache, outage);
        assertThrows(IllegalStateException.class, () -> new AccessTokens(noAudience));
        assertThrows(IllegalStateException.class, () -> new AccessTokens(noKeys));
        assertThrows(IllegalStateException.class, () -> new AccessTokens(notAUrl));
    }
}
