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
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KeyStoreSignatureTokenConnection;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Signs with the EU DSS libraries (European Commission, DSS 6.5).
 *
 * <ul>
 *   <li>{@code signHash}: the client computed the digest; the credential's key
 *       signs it ({@link SignatureTokenConnection#signDigest}). ECDSA signatures
 *       are ASN.1 DER, RSA ones PKCS#1 v1.5 with the DigestInfo of the digest
 *       algorithm, as before.</li>
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

    private static final DigestAlgorithm DEFAULT_DIGEST = DigestAlgorithm.SHA256;

    private final Map<String, SigningKey> keys = new ConcurrentHashMap<>();
    private final JAdESService jades = new JAdESService(new CommonCertificateVerifier());
    private final CAdESService cades = new CAdESService(new CommonCertificateVerifier());

    /** signHash: each hash (base64url) signed with the credential's key; base64url results. */
    public List<String> signHashes(List<String> hashesBase64, String hashAlgorithmOid,
                                   CertificateService.TenantMaterial credential) {
        var digestAlgorithm = digestAlgorithm(hashAlgorithmOid);
        var key = key(credential);
        var signatureAlgorithm = SignatureAlgorithm.getAlgorithm(key.entry().getEncryptionAlgorithm(), digestAlgorithm);
        var signatures = new ArrayList<String>();
        for (var hashB64 : hashesBase64) {
            var hash = decode(hashB64);
            if (hash.length != digestAlgorithm.getSaltLength()) {
                throw new InvalidRequestException("Hash length does not match hashAlgorithmOID");
            }
            var value = key.token().signDigest(new Digest(digestAlgorithm, hash), signatureAlgorithm, key.entry());
            signatures.add(Base64.getUrlEncoder().withoutPadding().encodeToString(value.getValue()));
        }
        return signatures;
    }

    /** signDoc, documents mode: one signature per document, in the requested format. */
    public SignedDocument signDocument(byte[] document, String signatureFormat, String conformanceLevel,
                                       CertificateService.TenantMaterial credential) {
        var format = SignatureFormat.of(signatureFormat);
        var key = key(credential);
        return switch (format) {
            case RAW -> {
                // Legacy: both fields carried the raw signature before 0.7.0.
                var raw = base64(key.token().sign(new ToBeSigned(document), DEFAULT_DIGEST, key.entry()).getValue());
                yield new SignedDocument(raw, raw);
            }
            case JADES -> {
                requireBaselineB(conformanceLevel);
                var parameters = new JAdESSignatureParameters();
                parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
                parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
                parameters.setJwsSerializationType(JWSSerializationType.COMPACT_SERIALIZATION);
                parameters.setDigestAlgorithm(DEFAULT_DIGEST);
                parameters.setSigningCertificate(key.entry().getCertificate());
                parameters.setCertificateChain(key.entry().getCertificateChain());
                var toSign = new InMemoryDocument(document);
                var value = key.token().sign(jades.getDataToSign(toSign, parameters), DEFAULT_DIGEST, key.entry());
                yield new SignedDocument(base64(bytes(jades.signDocument(toSign, parameters, value))), null);
            }
            case CADES -> {
                requireBaselineB(conformanceLevel);
                var parameters = new CAdESSignatureParameters();
                parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
                parameters.setSignaturePackaging(SignaturePackaging.DETACHED);
                parameters.setDigestAlgorithm(DEFAULT_DIGEST);
                parameters.setSigningCertificate(key.entry().getCertificate());
                parameters.setCertificateChain(key.entry().getCertificateChain());
                var toSign = new InMemoryDocument(document);
                var value = key.token().sign(cades.getDataToSign(toSign, parameters), DEFAULT_DIGEST, key.entry());
                yield new SignedDocument(null, base64(bytes(cades.signDocument(toSign, parameters, value))));
            }
        };
    }

    static DigestAlgorithm digestAlgorithm(String oid) {
        if (oid == null || oid.isBlank()) {
            return DEFAULT_DIGEST;
        }
        try {
            return DigestAlgorithm.forOID(oid.trim());
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Unsupported hashAlgorithmOID");
        }
    }

    private static void requireBaselineB(String conformanceLevel) {
        if (conformanceLevel != null && !conformanceLevel.isBlank()
                && !"ades-b-b".equalsIgnoreCase(conformanceLevel.trim())
                && !"ades-b".equalsIgnoreCase(conformanceLevel.trim())) {
            throw new InvalidRequestException("Unsupported conformance_level: only AdES-B-B");
        }
    }

    private static byte[] decode(String hashB64) {
        try {
            return Base64.getUrlDecoder().decode(hashB64);
        } catch (IllegalArgumentException e) {
            try {
                return Base64.getDecoder().decode(hashB64);
            } catch (IllegalArgumentException e2) {
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

    private SigningKey key(CertificateService.TenantMaterial credential) {
        return keys.computeIfAbsent(credential.tenant().credentialId(), id -> SigningKey.of(credential));
    }

    /** A DSS token over an in-memory PKCS#12 holding the credential's key and chain. */
    record SigningKey(SignatureTokenConnection token, DSSPrivateKeyEntry entry) {

        static SigningKey of(CertificateService.TenantMaterial credential) {
            try {
                // Never leaves the process: it only protects the in-memory PKCS#12.
                var seed = new byte[16];
                new SecureRandom().nextBytes(seed);
                var password = HexFormat.of().formatHex(seed).toCharArray();
                var keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, null);
                keyStore.setKeyEntry("credential", credential.privateKey(), password,
                        credential.certificateChain().toArray(new Certificate[0]));
                var out = new ByteArrayOutputStream();
                keyStore.store(out, password);
                var token = new KeyStoreSignatureTokenConnection(out.toByteArray(), "PKCS12",
                        new KeyStore.PasswordProtection(password));
                return new SigningKey(token, token.getKeys().getFirst());
            } catch (Exception e) {
                throw new IllegalStateException("Failed to load the signing key of a credential", e);
            }
        }
    }
}
