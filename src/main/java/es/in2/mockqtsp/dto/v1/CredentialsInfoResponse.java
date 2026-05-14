package es.in2.mockqtsp.dto.v1;

import java.util.List;

public record CredentialsInfoResponse(
        String description,
        KeyInfo key,
        CertInfo cert,
        String authMode,
        String SCAL,
        PinInfo PIN,
        OtpInfo OTP,
        Integer multisign,
        String lang
) {
    public record KeyInfo(String status, List<String> algo, int len) {}

    public record CertInfo(
            String status,
            List<String> certificates,
            String issuerDN,
            String serialNumber,
            String subjectDN,
            String validFrom,
            String validTo
    ) {}

    public record PinInfo(String presence, String label, String description) {}

    public record OtpInfo(
            String presence,
            String type,
            String ID,
            String provider,
            String format,
            String label,
            String description
    ) {}
}
