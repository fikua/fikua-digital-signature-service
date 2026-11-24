package com.fikua.dss.service;

import com.fikua.dss.web.InvalidRequestException;

import java.security.AlgorithmParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;

/**
 * The only signature algorithm this service offers: ES256 (RFC 7518, section
 * 3.4), ECDSA on the P-256 curve over a SHA-256 digest. It is the algorithm
 * HAIP requires for credentials and attestations; every credential's key must
 * be P-256, and every hash a client sends must be SHA-256.
 */
public final class Es256 {

    /** ecdsa-with-SHA256, the signature algorithm CSC credentials/info announces. */
    public static final String SIGNATURE_OID = "1.2.840.10045.4.3.2";
    /** SHA-256, the only hashAlgorithmOID signHash accepts. */
    public static final String SHA256_OID = "2.16.840.1.101.3.4.2.1";
    public static final int KEY_LENGTH = 256;

    private static final ECParameterSpec P256 = p256();

    private Es256() {}

    /** Refuses a signature algorithm other than ES256, or none when it is required. */
    public static void requireSignAlgo(String signAlgo, boolean required) {
        var missing = signAlgo == null || signAlgo.isBlank();
        if (missing ? required : !SIGNATURE_OID.equals(signAlgo.trim())) {
            throw new InvalidRequestException("Only ES256: signAlgo must be " + SIGNATURE_OID);
        }
    }

    /** Refuses a certificate whose key is not EC P-256: the credential could not sign ES256. */
    public static void requireP256(X509Certificate certificate) {
        if (!(certificate.getPublicKey() instanceof ECPublicKey key) || !isP256(key.getParams())) {
            throw new IllegalStateException("Credential key is not EC P-256 (ES256 only)");
        }
    }

    static boolean isP256(ECParameterSpec params) {
        return params.getOrder().equals(P256.getOrder())
                && params.getGenerator().equals(P256.getGenerator())
                && params.getCurve().equals(P256.getCurve());
    }

    private static ECParameterSpec p256() {
        try {
            var parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new ECGenParameterSpec("secp256r1"));
            return parameters.getParameterSpec(ECParameterSpec.class);
        } catch (Exception e) {
            throw new IllegalStateException("P-256 parameters unavailable", e);
        }
    }
}
