package com.fikua.dss.admin;

import java.time.Instant;
import java.util.List;

/** What the administration API answers. The secrets only in the answer that creates them. */
public final class Views {

    private Views() {}

    /** @param managed whether it can be changed here; one of the configuration has to be adopted first */
    public record User(String clientId, String customer, String environment, String description, boolean active,
                       boolean managed, List<Credential> credentials) {}

    /** @param key {@code service}, created here, or {@code file}, of the configuration */
    public record Credential(String id, String clientId, String status, String key, Instant passwordRotatedAt,
                             Certificate certificate) {}

    public record Certificate(String subject, String issuer, String serialNumber, Instant notBefore, Instant notAfter,
                              String sha256) {}

    public record NewUser(String clientId, String customer, String environment, String description) {}

    public record CreatedUser(String clientId, String clientSecret, String credentialId, String credentialPassword) {}

    public record ClientSecret(String clientId, String clientSecret) {}

    public record CredentialPassword(String credentialId, String credentialPassword) {}

    public record Active(Boolean active) {}

    /** @param overlapHours how long the old password is still accepted */
    public record Rotation(Integer overlapHours) {}
}
