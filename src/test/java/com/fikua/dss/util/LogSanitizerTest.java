package com.fikua.dss.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LogSanitizerTest {

    @Test
    void cleanReturnsNullWhenInputIsNull() {
        assertNull(LogSanitizer.clean(null));
    }

    @Test
    void cleanLeavesNormalAsciiUntouched() {
        assertEquals("client_credentials", LogSanitizer.clean("client_credentials"));
    }

    @Test
    void cleanReplacesNewlinesAndCarriageReturns() {
        var injected = "value\r\nFAKE LOG ENTRY admin";
        var cleaned = LogSanitizer.clean(injected);
        assertEquals("value__FAKE LOG ENTRY admin", cleaned);
    }

    @Test
    void cleanReplacesTabAndOtherControlChars() {
        // \b (backspace, U+0008) is a control char; the literal space stays.
        var input = "a\tb\bc d";
        assertEquals("a_b_c d", LogSanitizer.clean(input));
    }

    @Test
    void cleanCapsLengthAt200Chars() {
        var input = "x".repeat(250);
        var cleaned = LogSanitizer.clean(input);
        assertTrue(cleaned.endsWith("…"), "should mark truncation with ellipsis");
        assertEquals(201, cleaned.length(), "200 chars plus the ellipsis marker");
    }

    @Test
    void cleanLeaves200CharsUntouched() {
        var input = "x".repeat(200);
        assertEquals(input, LogSanitizer.clean(input));
    }

    @Test
    void cleanHandlesEmptyString() {
        assertEquals("", LogSanitizer.clean(""));
    }
}
