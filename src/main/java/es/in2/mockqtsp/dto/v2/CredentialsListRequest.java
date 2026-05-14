package es.in2.mockqtsp.dto.v2;

public record CredentialsListRequest(
        String userID,
        Boolean credentialInfo,
        String certificates,
        Boolean certInfo,
        Boolean authInfo,
        Boolean onlyValid,
        String lang,
        String clientData
) {}
