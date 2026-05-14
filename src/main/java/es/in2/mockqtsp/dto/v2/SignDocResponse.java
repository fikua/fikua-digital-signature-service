package es.in2.mockqtsp.dto.v2;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record SignDocResponse(
        @JsonProperty("DocumentWithSignature") List<String> documentWithSignature,
        @JsonProperty("SignatureObject") List<String> signatureObject,
        String responseID,
        ValidationInfo validationInfo
) {
    public record ValidationInfo(
            List<String> ocsp,
            List<String> crl,
            List<String> certificates
    ) {}
}
