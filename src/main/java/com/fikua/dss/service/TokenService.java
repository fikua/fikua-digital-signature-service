package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties;
import com.fikua.dss.web.InvalidRequestException;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.List;
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
        if (user == null || !CredentialService.matches(user.clientSecret(), clientSecret)) {
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

    /**
     * @param numSignatures how many signatures it authorizes
     * @param hashes        the only hashes it authorizes; empty when the client did not say (SCAL 1)
     */
    public String issueSad(String userId, String credentialId, String password, int numSignatures,
                           List<byte[]> hashes) {
        var credential = credentials.credential(userId, credentialId);
        if (credential == null) {
            throw new SecurityException("Unknown credential ID");
        }
        if (!credential.password().test(password)) {
            throw new SecurityException("Invalid credential password");
        }
        var sad = UUID.randomUUID().toString();
        activeSads.put(sad, new SadEntry(userId, credentialId, Instant.now().plusSeconds(properties.sadTtlSeconds()),
                numSignatures, List.copyOf(hashes)));
        return sad;
    }

    /**
     * Spends a valid SAD, once, for this many signatures.
     *
     * @param hashes the hashes to sign; null when the service computes them (documents)
     * @throws InvalidRequestException when it does not authorize them; it is not spent
     */
    public boolean spendSad(String userId, String sad, String credentialId, int signatures, List<byte[]> hashes) {
        var entry = sad(userId, sad, credentialId);
        if (entry == null) return false;
        if (signatures > entry.numSignatures()) {
            throw new InvalidRequestException("The SAD authorizes fewer signatures");
        }
        if (hashes != null && !entry.hashes().isEmpty()
                && !hashes.stream().allMatch(h -> entry.hashes().stream().anyMatch(a -> MessageDigest.isEqual(a, h)))) {
            throw new InvalidRequestException("The SAD does not authorize this hash");
        }
        return activeSads.remove(sad, entry);
    }

    private SadEntry sad(String userId, String sad, String credentialId) {
        var entry = sad == null ? null : activeSads.get(sad);
        if (entry == null) return null;
        if (Instant.now().isAfter(entry.expiry())) {
            activeSads.remove(sad);
            return null;
        }
        return entry.userId().equals(userId) && entry.credentialId().equals(credentialId) ? entry : null;
    }

    public int sadTtlSeconds() {
        return properties.sadTtlSeconds();
    }

    public void revokeToken(String token) {
        activeTokens.remove(token);
    }

    private record TokenEntry(String userId, Instant expiry) {}

    private record SadEntry(String userId, String credentialId, Instant expiry, int numSignatures,
                            List<byte[]> hashes) {}
}
