package com.fikua.dss.service;

import com.fikua.dss.config.OAuthProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.MalformedURLException;
import java.net.URI;
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

    private static final Logger log = LoggerFactory.getLogger(AccessTokens.class);
    private static final String CLIENT = "azp";

    private final DefaultJWTProcessor<SecurityContext> processor;

    public AccessTokens(OAuthProperties properties) {
        this.processor = properties.enabled() ? processor(properties) : null;
    }

    /**
     * The client the token was issued to, or null when the token is not a valid
     * one of the authorization server.
     *
     * @throws Unavailable when its keys cannot be obtained, so the token cannot be judged
     */
    public String clientId(String token) {
        if (processor == null) return null;
        try {
            return processor.process(token, null).getStringClaim(CLIENT);
        } catch (KeySourceException e) {
            log.atWarn().setMessage("authorization server keys unavailable").setCause(e).log();
            throw new Unavailable(e);
        } catch (ParseException | BadJOSEException | JOSEException e) {
            return null;
        }
    }

    private static DefaultJWTProcessor<SecurityContext> processor(OAuthProperties properties) {
        if (isBlank(properties.jwksUri()) || isBlank(properties.audience())) {
            throw new IllegalStateException("dss.oauth.issuer needs dss.oauth.jwks-uri and dss.oauth.audience");
        }
        try {
            var keys = JWKSourceBuilder.create(URI.create(properties.jwksUri()).toURL())
                    .cache(properties.jwksCache().toMillis(), JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT)
                    // A forged key id costs one request to the key set (Traefik limits the
                    // callers); with the limiter it could not be told from an outage.
                    .rateLimited(false)
                    .retrying(true)
                    .outageTolerant(properties.jwksOutage().toMillis())
                    .build();
            var processor = new DefaultJWTProcessor<SecurityContext>();
            processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.ES256, keys));
            processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                    properties.audience(),
                    new JWTClaimsSet.Builder().issuer(properties.issuer()).build(),
                    Set.of("exp", CLIENT)));
            return processor;
        } catch (MalformedURLException | IllegalArgumentException e) {
            throw new IllegalStateException("dss.oauth.jwks-uri is not a URL", e);
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /** The authorization server's keys cannot be obtained. */
    public static class Unavailable extends RuntimeException {
        Unavailable(Throwable cause) {
            super(cause);
        }
    }
}
