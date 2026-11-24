package com.fikua.dss.service;

import com.fikua.dss.web.InvalidRequestException;
import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

/**
 * Signs with the EU DSS libraries (European Commission, DSS 6.5).
 *
 * <ul>
 *   <li>{@code signHash}: the client computed the SHA-256 digest; the
 *       credential's P-256 key signs it ({@link CredentialService.DigestSigner}),
 *       ES256 with the signature in ASN.1 DER, as before. Any other hash
 *       algorithm is refused ({@link Es256}).</li>
 *   <li>{@code signDoc}: an AdES signature of the document, JAdES (J) or CAdES
 *       (C), baseline B. Without a {@code signature_format} the raw signature
 *       of the document is returned, as before.</li>
 * </ul>
 */
@Service
public class SigningService {

    /** CSC signature_format values this service produces. */
    public enum SignatureFormat {
        /** No signature_format: the raw signature of the document (legacy). */
        RAW,
        JADES,
        CADES;

        static SignatureFormat of(String value) {
            if (value == null || value.isBlank()) {
                return RAW;
            }
            return switch (value.trim().toUpperCase(Locale.ROOT)) {
                case "J" -> JADES;
                case "C" -> CADES;
                default -> throw new InvalidRequestException("Unsupported signature_format: only J and C");
            };
        }
    }

    /** The result of signing one document: the signed document, or the detached signature. */
    public record SignedDocument(String documentWithSignature, String signatureObject) {}

    /** ES256: SHA-256 digests only ({@link Es256}). */
    private static final DigestAlgorithm DEFAULT_DIGEST = DigestAlgorithm.SHA256;

    private final JAdESService jades = new JAdESService(new CommonCertificateVerifier());
    private final CAdESService cades = new CAdESService(new CommonCertificateVerifier());

    /** signHash: each hash signed with the credential's key; Base64 results (CSC). */
    public List<String> signHashes(List<String> hashesBase64, String hashAlgorithmOid,
                                   CredentialService.Credential credential) {
        Es256.requireP256(credential.leaf());
        var digestAlgorithm = digestAlgorithm(hashAlgorithmOid);
        var signatures = new ArrayList<String>();
        for (var hashB64 : hashesBase64) {
            var hash = decode(hashB64);
            if (hash.length != digestAlgorithm.getSaltLength()) {
                throw new InvalidRequestException("Hash length does not match hashAlgorithmOID");
            }
            signatures.add(base64(credential.signer().sign(hash)));
        }
        return signatures;
    }

    /** signDoc, documents mode: one signature per document, in the requested format. */
    public SignedDocument signDocument(byte[] document, String signatureFormat, String conformanceLevel,
                                       CredentialService.Credential credential) {
        Es256.requireP256(credential.leaf());
        var format = SignatureFormat.of(signatureFormat);
        return switch (format) {
            case RAW -> {
                // Legacy: both fields carried the raw signature before 0.7.0.
                var raw = base64(credential.signer().sign(DSSUtils.digest(DEFAULT_DIGEST, document)));
                yield new SignedDocument(raw, raw);
            }
            case JADES -> {
                requireBaselineB(conformanceLevel);
                var parameters = new JAdESSignatureParameters();
                parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
                parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
                parameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
                parameters.setDigestAlgorithm(DEFAULT_DIGEST);
                parameters.setSigningCertificate(new CertificateToken(credential.leaf()));
                parameters.setCertificateChain(credential.certificateChain().stream().map(CertificateToken::new).toList());
                var toSign = new InMemoryDocument(document);
                var value = sign(jades.getDataToSign(toSign, parameters), credential);
                yield new SignedDocument(base64(bytes(jades.signDocument(toSign, parameters, value))), null);
            }
            case CADES -> {
                requireBaselineB(conformanceLevel);
                var parameters = new CAdESSignatureParameters();
                parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
                parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
                parameters.setDigestAlgorithm(DEFAULT_DIGEST);
                parameters.setSigningCertificate(new CertificateToken(credential.leaf()));
                parameters.setCertificateChain(credential.certificateChain().stream().map(CertificateToken::new).toList());
                var toSign = new InMemoryDocument(document);
                var value = sign(cades.getDataToSign(toSign, parameters), credential);
                yield new SignedDocument(null, base64(bytes(cades.signDocument(toSign, parameters, value))));
            }
        };
    }

    private static SignatureValue sign(ToBeSigned data, CredentialService.Credential credential) {
        return new SignatureValue(SignatureAlgorithm.ECDSA_SHA256,
                credential.signer().sign(DSSUtils.digest(DEFAULT_DIGEST, data.getBytes())));
    }

    static DigestAlgorithm digestAlgorithm(String oid) {
        if (oid == null || oid.isBlank()) {
            return DEFAULT_DIGEST;
        }
        if (!Es256.SHA256_OID.equals(oid.trim())) {
            throw new InvalidRequestException("Only ES256: hashAlgorithmOID must be SHA-256 (" + Es256.SHA256_OID + ")");
        }
        return DEFAULT_DIGEST;
    }

    private static void requireBaselineB(String conformanceLevel) {
        if (conformanceLevel != null && !conformanceLevel.isBlank()
                && !"ades-b-b".equalsIgnoreCase(conformanceLevel.trim())
                && !"ades-b".equalsIgnoreCase(conformanceLevel.trim())) {
            throw new InvalidRequestException("Unsupported conformance_level: only AdES-B-B");
        }
    }

    /** The hashes of a request: Base64 (CSC) or base64url, which EUDIStack's issuer sends. */
    public static List<byte[]> decodeAll(List<String> hashes) {
        return hashes == null ? List.of() : hashes.stream().map(SigningService::decode).toList();
    }

    private static byte[] decode(String hashB64) {
        if (hashB64 == null) {
            throw new InvalidRequestException("Hash is not base64");
        }
        try {
            return Base64.getUrlDecoder().decode(hashB64);
        } catch (IllegalArgumentException _) {
            try {
                return Base64.getDecoder().decode(hashB64);
            } catch (IllegalArgumentException _) {
                throw new InvalidRequestException("Hash is not base64");
            }
        }
    }

    private static byte[] bytes(DSSDocument document) {
        try (var in = document.openStream()) {
            return in.readAllBytes();
        } catch (java.io.IOException e) {
            throw new IllegalStateException("Failed to read the signed document", e);
        }
    }

    private static String base64(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }
}
