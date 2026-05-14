package es.in2.mockqtsp.dto.v2;

import java.util.List;

public record CredentialsListResponse(
        List<String> credentialIDs,
        List<CredentialInfo> credentialInfos,
        Boolean onlyValid
) {
    public record CredentialInfo(
            String credentialID,
            KeyInfo key,
            CertInfo cert,
            Auth auth,
            Integer multisign,
            String lang
    ) {}
}
