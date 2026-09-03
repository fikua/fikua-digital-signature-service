package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties;
import com.fikua.dss.config.DssProperties.TenantProperties;
import com.fikua.dss.util.LogSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static net.logstash.logback.argument.StructuredArguments.kv;

@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    private final DssProperties properties;
    private final Map<String, TokenEntry> activeTokens = new ConcurrentHashMap<>();
    private final Map<String, SadEntry> activeSads = new ConcurrentHashMap<>();

    public TokenService(DssProperties properties) {
        this.properties = properties;
    }

    public String issueAccessToken(String clientId, String clientSecret) {
        var tenant = findTenantByClientId(clientId);
        if (tenant == null || !tenant.clientSecret().equals(clientSecret)) {
            throw new SecurityException("Invalid client credentials");
        }
        var token = UUID.randomUUID().toString();
        var expiry = Instant.now().plusSeconds(properties.tokenTtlSeconds());
        activeTokens.put(token, new TokenEntry(tenant.clientId(), expiry));
        log.info("Issued access token for tenant {}, expires at {}",
                LogSanitizer.clean(tenant.clientId()), expiry,
                kv("event", "token.authorized"), kv("result", "success"));
        return token;
    }

    public boolean validateToken(String token) {
        return resolveTenantClientId(token) != null;
    }

    /**
     * Returns the client-id of the tenant the token was issued for, or null
     * if the token is missing, expired, or already removed.
     */
    public String resolveTenantClientId(String token) {
        var entry = activeTokens.get(token);
        if (entry == null) return null;
        if (Instant.now().isAfter(entry.expiry())) {
            activeTokens.remove(token);
            return null;
        }
        return entry.tenantClientId();
    }

    public String issueSad(String tenantClientId, String credentialId, String password) {
        var tenant = findTenantByClientId(tenantClientId);
        if (tenant == null || !tenant.credentialId().equals(credentialId)) {
            throw new SecurityException("Unknown credential ID: " + credentialId);
        }
        if (!tenant.credentialPassword().equals(password)) {
            throw new SecurityException("Invalid credential password");
        }
        var sad = UUID.randomUUID().toString();
        var expiry = Instant.now().plusSeconds(properties.sadTtlSeconds());
        activeSads.put(sad, new SadEntry(tenantClientId, credentialId, expiry));
        if (log.isInfoEnabled()) {
            log.info("Issued SAD for credential {}, expires at {}",
                    LogSanitizer.clean(credentialId), expiry,
                    kv("event", "credential.authorized"),
                    kv("credential_id", credentialId),
                    kv("result", "success"));
        }
        return sad;
    }

    public boolean validateSad(String tenantClientId, String sad, String credentialId) {
        var entry = activeSads.get(sad);
        if (entry == null) return false;
        if (Instant.now().isAfter(entry.expiry())) {
            activeSads.remove(sad);
            return false;
        }
        if (!entry.tenantClientId().equals(tenantClientId) || !entry.credentialId().equals(credentialId)) {
            return false;
        }
        activeSads.remove(sad);
        return true;
    }

    public void revokeToken(String token) {
        activeTokens.remove(token);
    }

    private TenantProperties findTenantByClientId(String clientId) {
        if (properties.tenants() == null) return null;
        return properties.tenants().stream()
                .filter(t -> t.clientId().equals(clientId))
                .findFirst()
                .orElse(null);
    }

    private record TokenEntry(String tenantClientId, Instant expiry) {}

    private record SadEntry(String tenantClientId, String credentialId, Instant expiry) {}
}
