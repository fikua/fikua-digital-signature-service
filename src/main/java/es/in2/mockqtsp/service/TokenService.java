package es.in2.mockqtsp.service;

import es.in2.mockqtsp.config.MockQtspProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);

    private final MockQtspProperties properties;
    private final Map<String, Instant> activeTokens = new ConcurrentHashMap<>();
    private final Map<String, SadEntry> activeSads = new ConcurrentHashMap<>();

    public TokenService(MockQtspProperties properties) {
        this.properties = properties;
    }

    public String issueAccessToken(String clientId, String clientSecret) {
        if (!properties.clientId().equals(clientId) || !properties.clientSecret().equals(clientSecret)) {
            throw new SecurityException("Invalid client credentials");
        }
        var token = UUID.randomUUID().toString();
        var expiry = Instant.now().plusSeconds(properties.tokenTtlSeconds());
        activeTokens.put(token, expiry);
        log.info("Issued access token, expires at {}", expiry);
        return token;
    }

    public boolean validateToken(String token) {
        var expiry = activeTokens.get(token);
        if (expiry == null) return false;
        if (Instant.now().isAfter(expiry)) {
            activeTokens.remove(token);
            return false;
        }
        return true;
    }

    public String issueSad(String credentialId, String password) {
        if (!properties.credentialId().equals(credentialId)) {
            throw new SecurityException("Unknown credential ID: " + credentialId);
        }
        if (!properties.credentialPassword().equals(password)) {
            throw new SecurityException("Invalid credential password");
        }
        var sad = UUID.randomUUID().toString();
        var expiry = Instant.now().plusSeconds(properties.sadTtlSeconds());
        activeSads.put(sad, new SadEntry(credentialId, expiry));
        log.info("Issued SAD for credential {}, expires at {}", credentialId, expiry);
        return sad;
    }

    public boolean validateSad(String sad, String credentialId) {
        var entry = activeSads.get(sad);
        if (entry == null) return false;
        if (Instant.now().isAfter(entry.expiry())) {
            activeSads.remove(sad);
            return false;
        }
        if (!entry.credentialId().equals(credentialId)) return false;
        activeSads.remove(sad);
        return true;
    }

    public void revokeToken(String token) {
        activeTokens.remove(token);
    }

    private record SadEntry(String credentialId, Instant expiry) {}
}
