package es.in2.mockqtsp.dto.v2;

import java.util.List;

public record CertInfo(
        String status,
        List<String> certificates,
        String issuerDN,
        String serialNumber,
        String subjectDN,
        String validFrom,
        String validTo
) {}
