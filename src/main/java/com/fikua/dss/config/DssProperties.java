package com.fikua.dss.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * The service's users and their credentials (CSC v2): a user is an OAuth2
 * client (client_credentials) and owns one or more credentials, each a
 * certificate with its private key, unlocked with its own password.
 */
@ConfigurationProperties(prefix = "dss")
public record DssProperties(
        List<UserProperties> users,
        int tokenTtlSeconds,
        int sadTtlSeconds
) {
    public record UserProperties(
            String clientId,
            String clientSecret,
            List<CredentialProperties> credentials
    ) {}

    public record CredentialProperties(
            String id,
            String password,
            CertificateProperties certificate
    ) {}

    public record CertificateProperties(String certPath, String keyPath) {}
}
