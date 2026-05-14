package es.in2.mockqtsp.dto.v2;

import java.util.List;

public record SignHashRequest(
        String credentialID,
        String SAD,
        List<String> hashes,
        String hashAlgorithmOID,
        String signAlgo,
        String signAlgoParams,
        String operationMode,
        String validity_period,
        String response_uri,
        String clientData
) {}
