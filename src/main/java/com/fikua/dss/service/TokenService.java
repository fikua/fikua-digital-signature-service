package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Access tokens (one per authenticated user) and SADs (one per authorized
 * credential, single use), both in memory.
 */
@Service
public class TokenService {

    private final DssProperties properties;
    private final CredentialService credentials;
    private final Map<String, TokenEntry> activeTokens = new ConcurrentHashMap<>();
    private final Map<String, SadEntry> activeSads = new ConcurrentHashMap<>();

    public TokenService(DssProperties properties, CredentialService credentials) {
        this.properties = properties;
        this.credentials = credentials;
    }

    public String issueAccessToken(String clientId, String clientSecret) {
        var user = credentials.user(clientId);
        if (user == null || !matches(user.clientSecret(), clientSecret)) {
            throw new SecurityException("Invalid client credentials");
        }
        var token = UUID.randomUUID().toString();
        activeTokens.put(token, new TokenEntry(user.id(), Instant.now().plusSeconds(properties.tokenTtlSeconds())));
        return token;
    }

    /** The user the token was issued to, or null if it is unknown or expired. */
    public String resolveUserId(String token) {
        var entry = activeTokens.get(token);
        if (entry == null) return null;
        if (Instant.now().isAfter(entry.expiry())) {
            activeTokens.remove(token);
            return null;
        }
        return entry.userId();
    }

    public String issueSad(String userId, String credentialId, String password) {
        var credential = credentials.credential(userId, credentialId);
        if (credential == null) {
            throw new SecurityException("Unknown credential ID");
        }
        if (!matches(credential.password(), password)) {
            throw new SecurityException("Invalid credential password");
        }
        var sad = UUID.randomUUID().toString();
        activeSads.put(sad, new SadEntry(userId, credentialId, Instant.now().plusSeconds(properties.sadTtlSeconds())));
        return sad;
    }

    /** True once for a SAD this user obtained for this credential and that has not expired. */
    public boolean validateSad(String userId, String sad, String credentialId) {
        var entry = sad == null ? null : activeSads.get(sad);
        if (entry == null) return false;
        if (Instant.now().isAfter(entry.expiry())) {
            activeSads.remove(sad);
            return false;
        }
        if (!entry.userId().equals(userId) || !entry.credentialId().equals(credentialId)) {
            return false;
        }
        activeSads.remove(sad);
        return true;
    }

    public void revokeToken(String token) {
        activeTokens.remove(token);
    }

    /** Constant-time comparison of a configured secret with the one presented. */
    private static boolean matches(String expected, String presented) {
        return expected != null && presented != null && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), presented.getBytes(StandardCharsets.UTF_8));
    }

    private record TokenEntry(String userId, Instant expiry) {}

    private record SadEntry(String userId, String credentialId, Instant expiry) {}
}
