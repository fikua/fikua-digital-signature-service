package es.in2.mockqtsp.dto.v2;

import java.util.List;

public record InfoResponse(
        String specs,
        String name,
        String logo,
        String region,
        String lang,
        String description,
        List<String> authType,
        List<Oauth2Server> oauth2Servers,
        String oauth2,
        String oauth2Issuer,
        Boolean supportsRar,
        List<String> supportedHashTypes,
        Boolean asynchronousOperationMode,
        List<String> methods,
        Boolean validationInfo,
        List<SignAlgorithm> signAlgorithms,
        List<String> documentTypes,
        SignatureFormats signature_formats,
        List<String> conformance_levels
) {
    public record Oauth2Server(String issuer) {}

    public record SignAlgorithm(String algorithm) {}

    public record SignatureFormats(
            List<String> formats,
            List<List<String>> envelope_properties,
            Boolean allowMix
    ) {}
}
