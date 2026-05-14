package es.in2.mockqtsp.dto.common;

public record TokenRequest(
        String grant_type,
        String scope,
        String authorization_details
) {}
