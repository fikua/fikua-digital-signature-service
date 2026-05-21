package com.fikua.dss.dto;

public record CredentialsInfoRequest(
        String credentialID,
        String certificates,
        String certInfo,
        String authInfo
) {}
