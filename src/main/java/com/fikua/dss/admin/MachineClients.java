package com.fikua.dss.admin;

/** The OAuth2 clients of the users, in the authorization server. */
public interface MachineClients {

    /** A new client; returns its secret, which is not kept here. */
    String create(String clientId, String description);

    /** A new secret; the old one stops at once, the tokens already issued last until they expire. */
    String rotateSecret(String clientId);

    void setEnabled(String clientId, boolean enabled);

    void delete(String clientId);

    /** The authorization server does not answer, or refuses. */
    class Unavailable extends RuntimeException {
        public Unavailable(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
