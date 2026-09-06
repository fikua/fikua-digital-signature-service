package com.fikua.dss.dto.v1;

import java.util.List;

public record CredentialsAuthorizeRequest(
        String credentialID,
        int numSignatures,
        List<String> hash,
        String PIN,
        String OTP,
        String description,
        String clientData
) {}
