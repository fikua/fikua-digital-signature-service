package com.fikua.dss.web;

import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Pure unit tests for the @ExceptionHandler methods to cover every branch
 * (not all of them are reachable through MockMvc without extra wiring).
 */
class GlobalExceptionHandlerUnitTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handlesMalformedJson() {
        var input = new MockHttpInputMessage(new byte[0]);
        var ex = new HttpMessageNotReadableException(
                "broken", new RuntimeException("bad token"), input);
        var resp = handler.handleUnreadable(ex);
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertNotNull(resp.getBody());
        assertEquals("invalid_request", resp.getBody().error());
    }

    @Test
    void handlesMissingServletParam() {
        var ex = new MissingServletRequestParameterException("grant_type", "String");
        var resp = handler.handleMissingParam(ex);
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertEquals("invalid_request", resp.getBody().error());
    }

    @Test
    void handlesMissingHeader() throws Exception {
        var method = Sample.class.getDeclaredMethod("take", String.class);
        var param = new MethodParameter(method, 0);
        var ex = new MissingRequestHeaderException("X-Whatever", param);
        var resp = handler.handleMissingHeader(ex);
        assertEquals(HttpStatus.BAD_REQUEST, resp.getStatusCode());
        assertEquals("invalid_request", resp.getBody().error());
    }

    @Test
    void handlesNoHandlerFound() {
        var ex = new NoHandlerFoundException("GET", "/nope", new org.springframework.http.HttpHeaders());
        var resp = handler.handleNotFound(ex);
        assertEquals(HttpStatus.NOT_FOUND, resp.getStatusCode());
        assertEquals("not_found", resp.getBody().error());
    }

    @Test
    void handlesSecurityException() {
        var resp = handler.handleSecurity(new SecurityException("bad creds"));
        assertEquals(HttpStatus.UNAUTHORIZED, resp.getStatusCode());
        assertEquals("invalid_client", resp.getBody().error());
    }

    @Test
    void handlesUnexpectedException() {
        var resp = handler.handleUnexpected(new RuntimeException("kaboom"));
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, resp.getStatusCode());
        assertEquals("server_error", resp.getBody().error());
    }

    @SuppressWarnings("unused")
    private static final class Sample {
        void take(String header) {}
    }
}
