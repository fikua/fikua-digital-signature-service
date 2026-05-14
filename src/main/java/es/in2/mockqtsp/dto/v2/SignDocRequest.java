package es.in2.mockqtsp.dto.v2;

import java.util.List;

public record SignDocRequest(
        String credentialID,
        String signatureQualifier,
        String SAD,
        List<DocumentDigest> documentDigests,
        List<Document> documents,
        String hashAlgorithmOID,
        String operationMode,
        String validity_period,
        String response_uri,
        String clientData,
        Boolean returnValidationInfo
) {
    public record DocumentDigest(
            List<String> hashes,
            String signature_format,
            String conformance_level,
            String signAlgo,
            String signAlgoParams
    ) {}

    public record Document(
            String document,
            String signature_format,
            String conformance_level,
            String signAlgo,
            String signAlgoParams
    ) {}
}
