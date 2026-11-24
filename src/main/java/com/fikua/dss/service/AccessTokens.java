package com.fikua.dss.service;

import com.fikua.dss.config.OAuthProperties;
import com.nimbusds.jose.JWSAlgorithm;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Set;

/**
 * Access tokens of the authorization server (a JWT signed with ES256): checks
 * the signature, the issuer, the audience and the expiry. The user is the
 * client the token was issued to ({@code azp}); whether it exists here is the
 * caller's check.
 */
@Service
public class AccessTokens {

    private static final String CLIENT = "azp";

    private final JwtVerifier verifier;

    public AccessTokens(OAuthProperties properties) {
        this.verifier = properties.enabled()
                ? new JwtVerifier(properties.issuer(), properties.jwksUri(), properties.audience(),
                        Set.of(JWSAlgorithm.ES256), Set.of("exp", CLIENT),
                        new JwtVerifier.Caching(properties.jwksCache(), properties.jwksOutage()))
                : null;
    }

    /**
     * The client the token was issued to, or null when the token is not a valid
     * one of the authorization server.
     *
     * @throws Unavailable when its keys cannot be obtained, so the token cannot be judged
     */
    public String clientId(String token) {
        if (verifier == null) return null;
        return verifier.verify(token).map(claims -> {
            try {
                return claims.getStringClaim(CLIENT);
            } catch (ParseException _) {
                return null;
            }
        }).orElse(null);
    }

    /** The authorization server's keys cannot be obtained. */
    public static class Unavailable extends RuntimeException {
        Unavailable(Throwable cause) {
            super(cause);
        }
    }
}
