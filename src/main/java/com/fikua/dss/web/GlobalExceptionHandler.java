package com.fikua.dss.web;

import com.fikua.dss.dto.common.ErrorResponse;
import com.fikua.dss.util.LogSanitizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

/**
 * Last-mile error mapper so internal exceptions never bleed implementation
 * details to clients. Logs the original cause server-side (sanitized).
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private static final String INVALID_REQUEST = "invalid_request";
    static final String ERROR_TYPE = "error.type";
    static final String ERROR_MESSAGE = "error.message";
    /** OBS-08: error.message is cut at 280 characters. */
    static final int MAX_ERROR_MESSAGE = 280;

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException e) {
        // The parser's message quotes the body, so it is not logged (OBS-05).
        log.atWarn().setMessage("malformed request body")
                .addKeyValue(ERROR_TYPE, INVALID_REQUEST)
                .log();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(INVALID_REQUEST, "Malformed request body"));
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ErrorResponse> handleMissingParam(MissingServletRequestParameterException e) {
        var safeName = LogSanitizer.clean(e.getParameterName());
        log.atWarn().setMessage("missing request parameter")
                .addKeyValue(ERROR_TYPE, INVALID_REQUEST)
                .addKeyValue("parameter", safeName)
                .log();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(INVALID_REQUEST,
                        "Missing required parameter: " + safeName));
    }

    @ExceptionHandler(MissingRequestHeaderException.class)
    public ResponseEntity<ErrorResponse> handleMissingHeader(MissingRequestHeaderException e) {
        var safeName = LogSanitizer.clean(e.getHeaderName());
        log.atWarn().setMessage("missing request header")
                .addKeyValue(ERROR_TYPE, INVALID_REQUEST)
                .addKeyValue("header", safeName)
                .log();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(INVALID_REQUEST,
                        "Missing required header: " + safeName));
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(NoHandlerFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse("not_found", "No handler for requested resource"));
    }

    // An unknown path (scanners, probes) is a 404 like any other, not an
    // unhandled error with a stack trace.
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResource(NoResourceFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ErrorResponse("not_found", "No handler for requested resource"));
    }

    /** The database of users cannot be read: nobody can be told apart now. */
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ErrorResponse> handleDatabase(DataAccessException e) {
        log.atError().setMessage("database unavailable").setCause(e).log();
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(new ErrorResponse("temporarily_unavailable", "The service cannot answer now"));
    }

    @ExceptionHandler(InvalidRequestException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRequest(InvalidRequestException e) {
        log.atWarn().setMessage("request refused")
                .addKeyValue(ERROR_TYPE, INVALID_REQUEST)
                .addKeyValue(ERROR_MESSAGE, e.getMessage())
                .log();
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(INVALID_REQUEST, e.getMessage()));
    }

    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<ErrorResponse> handleSecurity(SecurityException e) {
        log.atWarn().setMessage("client refused")
                .addKeyValue(ERROR_TYPE, "invalid_client")
                .addKeyValue(ERROR_MESSAGE, errorMessage(e))
                .log();
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorResponse("invalid_client", e.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpected(Exception e) {
        // error.type is the stable code the metrics use too, so a log record and
        // its metric join on one key (fikua-docs conv-observability.md, OBS-08).
        log.atError().setMessage("unhandled error")
                .addKeyValue(ERROR_TYPE, "server_error")
                .addKeyValue("exception.type", e.getClass().getSimpleName())
                .addKeyValue(ERROR_MESSAGE, errorMessage(e))
                .setCause(e)
                .log();
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new ErrorResponse("server_error", "Internal server error"));
    }

    static String errorMessage(Throwable e) {
        // Control characters out (CWE-117), as LogSanitizer does, with OBS-08's length.
        var message = e.getMessage() == null ? "" : e.getMessage().replaceAll("\\p{Cntrl}", "_");
        return message.length() > MAX_ERROR_MESSAGE ? message.substring(0, MAX_ERROR_MESSAGE) : message;
    }
}
