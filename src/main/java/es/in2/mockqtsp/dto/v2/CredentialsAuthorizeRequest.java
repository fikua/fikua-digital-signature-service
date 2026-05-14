package es.in2.mockqtsp.dto.v2;

import java.util.List;

public record CredentialsAuthorizeRequest(
        String credentialID,
        int numSignatures,
        List<String> hashes,
        String hashAlgorithmOID,
        List<AuthData> authData,
        String description,
        String clientData
) {
    public record AuthData(String id, String value) {}
}
