package com.fikua.dss.dto.v2;

public record CredentialsInfoResponse(
        String description,
        String signatureQualifier,
        KeyInfo key,
        CertInfo cert,
        Auth auth,
        String SCAL,
        Integer multisign,
        String lang
) {}
