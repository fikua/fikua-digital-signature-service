package com.fikua.dss.dto.v2;

import com.fasterxml.jackson.annotation.JsonAlias;

import java.util.List;

public record CredentialsAuthorizeRequest(
        String credentialID,
        int numSignatures,
        // EUDIStack's issuer still sends the v1 names.
        @JsonAlias("hash") List<String> hashes,
        @JsonAlias("hashAlgo") String hashAlgorithmOID,
        List<AuthData> authData,
        String description,
        String clientData
) {
    public record AuthData(String id, String value) {}
}
