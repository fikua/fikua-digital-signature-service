package com.fikua.dss.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * The authorization server whose access tokens this service accepts: its issuer
 * identifier, its JWK set and the audience its tokens must carry for this
 * service. Without an issuer, only this service's own tokens are accepted.
 */
@ConfigurationProperties(prefix = "dss.oauth")
public record OAuthProperties(
        String issuer,
        String jwksUri,
        String audience,
        // The keys are asked again after this; a token with an unknown key asks sooner.
        @DefaultValue("PT5M") Duration jwksCache,
        // While the authorization server does not answer, the last keys are still used.
        @DefaultValue("PT4H") Duration jwksOutage
) {
    public boolean enabled() {
        return issuer != null && !issuer.isBlank();
    }
}
