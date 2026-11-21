package com.fikua.dss.web;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;

import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * The log records of the error handler follow the observability convention:
 * a stable message, the values as key-value pairs (OBS-08) and nothing from the
 * request body (OBS-05).
 */
class GlobalExceptionHandlerLogTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();
    private final Logger logger = (Logger) LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach
    void attach() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detach() {
        logger.detachAppender(appender);
    }

    @Test
    void unhandledErrorCarriesTheErrorFields() {
        handler.handleUnexpected(new IllegalStateException("x".repeat(500)));

        var event = appender.list.getFirst();
        var pairs = pairs(event);
        assertEquals("unhandled error", event.getFormattedMessage());
        assertEquals("server_error", pairs.get("error.type"));
        assertEquals("IllegalStateException", pairs.get("exception.type"));
        assertEquals(GlobalExceptionHandler.MAX_ERROR_MESSAGE, pairs.get("error.message").length());
        assertNotNull(event.getThrowableProxy());
    }

    @Test
    void malformedBodyIsNotLogged() {
        var ex = new HttpMessageNotReadableException(
                "broken", new RuntimeException("Unrecognized token 'secret-value'"),
                new MockHttpInputMessage(new byte[0]));

        handler.handleUnreadable(ex);

        var event = appender.list.getFirst();
        assertEquals("malformed request body", event.getFormattedMessage());
        assertEquals("invalid_request", pairs(event).get("error.type"));
        assertFalse(event.toString().contains("secret-value"));
        assertFalse(pairs(event).values().stream().anyMatch(v -> v.contains("secret-value")));
    }

    @Test
    void errorMessageIsSanitizedAndCut() {
        assertEquals("a_b", GlobalExceptionHandler.errorMessage(new RuntimeException("a\nb")));
        assertEquals("", GlobalExceptionHandler.errorMessage(new RuntimeException()));
    }

    private static Map<String, String> pairs(ILoggingEvent event) {
        return event.getKeyValuePairs().stream()
                .collect(Collectors.toMap(p -> p.key, p -> String.valueOf(p.value)));
    }
}
