package com.fikua.dss.web;

import com.fikua.dss.dto.ErrorResponse;
import com.fikua.dss.util.LogSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

/**
 * Last-mile error mapper so internal exceptions never bleed implementation
 * details to clients. Logs the original cause server-side (sanitized).
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private static final String INVALID_REQUEST = "invalid_request";

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException e) {
        if (log.isWarnEnabled()) {
            log.warn("Malformed request body: {}",
                    LogSanitizer.clean(e.getMostSpecificCause().getMessage()));
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(INVALID_REQUEST, "Malformed request body"));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ErrorResponse> handleMissingParam(MissingServletRequestParameterException e) {
        var safeName = LogSanitizer.clean(e.getParameterName());
        if (log.isWarnEnabled()) {
            log.warn("Missing required parameter: {}", safeName);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(INVALID_REQUEST,
                        "Missing required parameter: " + safeName));
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<ErrorResponse> handleMissingHeader(MissingRequestHeaderException e) {
        var safeName = LogSanitizer.clean(e.getHeaderName());
        if (log.isWarnEnabled()) {
            log.warn("Missing required header: {}", safeName);
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(INVALID_REQUEST,
                        "Missing required header: " + safeName));
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(NoHandlerFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse("not_found", "No handler for requested resource"));
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<ErrorResponse> handleSecurity(SecurityException e) {
        if (log.isWarnEnabled()) {
            log.warn("Security violation: {}", LogSanitizer.clean(e.getMessage()));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("invalid_client", e.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception e) {
        log.error("Unhandled error", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse("server_error", "Internal server error"));
    }
}
