package com.fikua.dss.dto.v1;

public record CredentialsInfoRequest(
        String credentialID,
        String certificates,
        Boolean certInfo,
        Boolean authInfo,
        String lang,
        String clientData
) {}
