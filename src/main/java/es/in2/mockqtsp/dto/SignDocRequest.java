package es.in2.mockqtsp.dto;

import java.util.List;

public record SignDocRequest(
        String credentialID,
        String SAD,
        String signatureQualifier,
        List<Document> documents
) {
    public record Document(
            String document,
            String signature_format,
            String conformance_level,
            String signAlgo
    ) {}
}
