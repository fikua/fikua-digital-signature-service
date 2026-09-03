package com.fikua.dss.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties(prefix = "dss")
public record DssProperties(
        List<TenantProperties> tenants,
        int tokenTtlSeconds,
        int sadTtlSeconds
) {
    public record TenantProperties(
            String clientId,
            String clientSecret,
            String credentialId,
            String credentialPassword,
            CertificateProperties certificate
    ) {}

    public record CertificateProperties(String certPath, String keyPath) {}
}
