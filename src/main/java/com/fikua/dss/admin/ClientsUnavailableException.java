package com.fikua.dss.admin;

/** The authorization server does not answer, or refuses. */
public class ClientsUnavailableException extends RuntimeException {
    public ClientsUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
