package com.fikua.dss.admin;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * The administration API, off without a port. It listens only there, and asks
 * for a token of {@code issuer} with this audience and group.
 */
@ConfigurationProperties(prefix = "dss.admin")
public record AdminProperties(
        Integer port,
        String issuer,
        String jwksUri,
        String audience,
        @DefaultValue("dss-admins") String group,
        Keycloak keycloak
) {
    /** The service account that manages the machine clients of a realm. */
    public record Keycloak(
            String url,
            @DefaultValue("dss") String realm,
            @DefaultValue("fikua-sign-admin") String clientId,
            String clientSecret
    ) {}

    public boolean enabled() {
        return port != null;
    }
}
