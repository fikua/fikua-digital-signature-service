package com.fikua.dss.admin;

/** What the request names does not exist. */
public class NotFoundException extends RuntimeException {
    public NotFoundException(String message) {
        super(message);
    }
}
