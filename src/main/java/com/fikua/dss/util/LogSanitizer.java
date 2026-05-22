package com.fikua.dss.util;

/**
 * Defends log messages against CRLF/log-injection (CWE-117 / Sonar S5145):
 * strips control characters and caps length on values that originated from
 * untrusted request input before they are written to a logger.
 */
public final class LogSanitizer {

    private static final int MAX_LENGTH = 200;

    private LogSanitizer() {}

    public static String clean(String value) {
        if (value == null) {
            return null;
        }
        var stripped = value.replaceAll("[\\r\\n\\t\\p{Cntrl}]", "_");
        return stripped.length() > MAX_LENGTH ? stripped.substring(0, MAX_LENGTH) + "…" : stripped;
    }
}
