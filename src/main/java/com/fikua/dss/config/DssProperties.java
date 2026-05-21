package com.fikua.dss.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "dss")
public record DssProperties(
        String clientId,
        String clientSecret,
        String credentialId,
        String credentialPassword,
        CertificateProperties certificate,
        int tokenTtlSeconds,
        int sadTtlSeconds
) {
    public record CertificateProperties(String certPath, String keyPath) {}
}