package com.fikua.dss.web;

/**
 * A request the service understood but cannot honour (an unsupported
 * algorithm, format or level, a malformed hash): 400 invalid_request with this
 * message, which never carries request values.
 */
public class InvalidRequestException extends RuntimeException {

    public InvalidRequestException(String message) {
        super(message);
    }
}
