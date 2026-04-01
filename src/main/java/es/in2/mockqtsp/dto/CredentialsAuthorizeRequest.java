package es.in2.mockqtsp.dto;

import java.util.List;

public record CredentialsAuthorizeRequest(
        String credentialID,
        int numSignatures,
        List<String> hash,
        String hashAlgo,
        List<AuthData> authData
) {
    public record AuthData(String id, String value) {}
}
