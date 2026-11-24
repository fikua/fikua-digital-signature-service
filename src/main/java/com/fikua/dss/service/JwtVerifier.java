package com.fikua.dss.service;

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

import java.net.MalformedURLException;
import java.net.URI;
import java.text.ParseException;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

/** Checks JWTs of one issuer for one audience: signature, issuer, audience, expiry and required claims. */
public final class JwtVerifier {

    private static final Logger log = LoggerFactory.getLogger(JwtVerifier.class);

    private final DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

    /** How long the keys are kept, and how long the last ones are used while the issuer does not answer. */
    public record Caching(Duration cache, Duration outage) {}

    public JwtVerifier(String issuer, String jwksUri, String audience, Set<JWSAlgorithm> algorithms,
                       Set<String> requiredClaims, Caching caching) {
        if (isBlank(issuer) || isBlank(jwksUri) || isBlank(audience)) {
            throw new IllegalStateException("An issuer needs its jwks-uri and an audience");
        }
        try {
            var keys = JWKSourceBuilder.create(URI.create(jwksUri).toURL())
                    .cache(caching.cache().toMillis(), JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT)
                    // A forged key id costs one request to the key set (Traefik limits the
                    // callers); with the limiter it could not be told from an outage.
                    .rateLimited(false)
                    .retrying(true)
                    .outageTolerant(caching.outage().toMillis())
                    .build();
            processor.setJWSKeySelector(new JWSVerificationKeySelector<>(algorithms, keys));
            processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                    audience, new JWTClaimsSet.Builder().issuer(issuer).build(), requiredClaims));
        } catch (MalformedURLException | IllegalArgumentException e) {
            throw new IllegalStateException("jwks-uri is not a URL", e);
        }
    }

    /**
     * The claims of a valid token; empty when it is not.
     *
     * @throws AccessTokens.Unavailable when the keys cannot be obtained, so the token cannot be judged
     */
    public Optional<JWTClaimsSet> verify(String token) {
        try {
            return Optional.of(processor.process(token, null));
        } catch (KeySourceException e) {
            log.atWarn().setMessage("authorization server keys unavailable").setCause(e).log();
            throw new AccessTokens.Unavailable(e);
        } catch (ParseException | BadJOSEException | JOSEException _) {
            return Optional.empty();
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
