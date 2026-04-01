package es.in2.mockqtsp.dto;

public record CredentialsInfoRequest(
        String credentialID,
        String certificates,
        String certInfo,
        String authInfo
) {}
