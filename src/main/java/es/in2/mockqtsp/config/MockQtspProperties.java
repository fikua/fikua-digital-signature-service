package es.in2.mockqtsp.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "mock-qtsp")
public record MockQtspProperties(
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