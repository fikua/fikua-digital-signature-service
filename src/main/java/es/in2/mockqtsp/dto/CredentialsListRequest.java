package es.in2.mockqtsp.dto;

public record CredentialsListRequest(
        String userID,
        Boolean credentialInfo,
        String certificates,
        Boolean certInfo,
        Boolean authInfo,
        Boolean onlyValid
) {}
