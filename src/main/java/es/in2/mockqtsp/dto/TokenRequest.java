package es.in2.mockqtsp.dto;

public record TokenRequest(
        String grant_type,
        String scope,
        String authorization_details
) {}