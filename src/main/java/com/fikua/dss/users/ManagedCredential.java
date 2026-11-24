package com.fikua.dss.users;

import java.time.Instant;

/** A credential kept in the database, without its password. */
public record ManagedCredential(String id, String clientId, Status status, Instant passwordRotatedAt) {

    public enum Status { PENDING, ACTIVE, REVOKED }
}
