package es.in2.mockqtsp.dto;

import java.util.List;

public record CredentialsInfoResponse(
        KeyInfo key,
        CertInfo cert
) {
    public record KeyInfo(String status, List<String> algo, int len) {}

    public record CertInfo(
            String status,
            String issuerDN,
            String subjectDN,
            String serialNumber,
            String validFrom,
            String validTo,
            List<String> certificates
    ) {}
}
