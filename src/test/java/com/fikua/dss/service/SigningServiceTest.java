package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties.CertificateProperties;
import com.fikua.dss.config.DssProperties.TenantProperties;
import com.fikua.dss.service.CertificateService.TenantMaterial;
import com.fikua.dss.web.InvalidRequestException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Signatures made with the EU DSS libraries: signHash keeps the format clients
 * verify today (ECDSA in DER, RSA PKCS#1 v1.5), and signDoc's JAdES and CAdES
 * signatures pass DSS's own validation.
 */
class SigningServiceTest {

    private static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    private static final String SHA384 = "2.16.840.1.101.3.4.2.2";
    private static final byte[] DATA = "a document to sign".getBytes(StandardCharsets.UTF_8);

    private static TenantMaterial ec;
    private static TenantMaterial rsa;

    private final SigningService service = new SigningService();

    @BeforeAll
    static void credentials() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        ec = credential("ec", "EC", 256, "SHA256withECDSA");
        rsa = credential("rsa", "RSA", 2048, "SHA256withRSA");
    }

    @Test
    void signHashEcdsaIsDerAndVerifies() throws Exception {
        var signature = signHash(ec, "SHA-256", SHA256);
        assertTrue(verify("SHA256withECDSA", ec, signature), "ECDSA signature (DER) verifies");
    }

    @Test
    void signHashRsaIsPkcs1AndVerifies() throws Exception {
        var signature = signHash(rsa, "SHA-256", SHA256);
        assertTrue(verify("SHA256withRSA", rsa, signature), "RSA PKCS#1 v1.5 signature verifies");
    }

    @Test
    void signHashFollowsTheHashAlgorithm() throws Exception {
        var signature = signHash(ec, "SHA-384", SHA384);
        assertTrue(verify("SHA384withECDSA", ec, signature));
    }

    @Test
    void signHashWithoutAlgorithmIsSha256() throws Exception {
        var signature = signHash(ec, "SHA-256", null);
        assertTrue(verify("SHA256withECDSA", ec, signature));
    }

    @Test
    void signHashRefusesAHashOfTheWrongLength() throws Exception {
        var sha384 = b64url(MessageDigest.getInstance("SHA-384").digest(DATA));
        assertThrows(InvalidRequestException.class,
                () -> service.signHashes(List.of(sha384), SHA256, ec));
    }

    @Test
    void signHashRefusesAnUnknownAlgorithm() {
        assertThrows(InvalidRequestException.class,
                () -> service.signHashes(List.of("aGVsbG8"), "1.2.3.4", ec));
    }

    @Test
    void signDocJadesIsAValidJadesBaselineB() {
        var signed = service.signDocument(DATA, "J", "AdES-B-B", ec);

        assertNotNull(signed.documentWithSignature());
        assertNull(signed.signatureObject());
        var jws = Base64.getDecoder().decode(signed.documentWithSignature());
        assertEquals(3, new String(jws, StandardCharsets.US_ASCII).split("\\.").length, "compact JWS");
        assertValid(jws, SignatureLevel.JAdES_BASELINE_B);
    }

    @Test
    void signDocCadesIsAValidDetachedCadesBaselineB() {
        var signed = service.signDocument(DATA, "C", null, rsa);

        assertNull(signed.documentWithSignature());
        assertNotNull(signed.signatureObject());
        assertValid(Base64.getDecoder().decode(signed.signatureObject()), SignatureLevel.CAdES_BASELINE_B);
    }

    @Test
    void signDocWithoutFormatKeepsTheRawSignature() throws Exception {
        var signed = service.signDocument(DATA, null, null, ec);

        assertEquals(signed.documentWithSignature(), signed.signatureObject());
        var sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(ec.certificateChain().getFirst());
        sig.update(DATA);
        assertTrue(sig.verify(Base64.getDecoder().decode(signed.signatureObject())));
    }

    @Test
    void signDocRefusesUnsupportedFormatsAndLevels() {
        assertThrows(InvalidRequestException.class, () -> service.signDocument(DATA, "P", null, ec));
        assertThrows(InvalidRequestException.class, () -> service.signDocument(DATA, "J", "AdES-B-T", ec));
    }

    private byte[] signHash(TenantMaterial credential, String jcaDigest, String oid) throws Exception {
        var hash = b64url(MessageDigest.getInstance(jcaDigest).digest(DATA));
        var signatures = service.signHashes(List.of(hash), oid, credential);
        assertEquals(1, signatures.size());
        return Base64.getUrlDecoder().decode(signatures.getFirst());
    }

    private static boolean verify(String algorithm, TenantMaterial credential, byte[] signature) throws Exception {
        var sig = Signature.getInstance(algorithm);
        sig.initVerify(credential.certificateChain().getFirst());
        sig.update(DATA);
        return sig.verify(signature);
    }

    private static void assertValid(byte[] signature, SignatureLevel level) {
        var validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(signature));
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        if (level == SignatureLevel.CAdES_BASELINE_B) {
            validator.setDetachedContents(List.of(new InMemoryDocument(DATA)));
        }
        var diagnostic = validator.validateDocument().getDiagnosticData();
        var id = diagnostic.getFirstSignatureId();
        assertNotNull(id, "one signature");
        assertTrue(diagnostic.isBLevelTechnicallyValid(id), "signature value and references intact");
        assertEquals(level, diagnostic.getSignatureFormat(id));
    }

    private static String b64url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static TenantMaterial credential(String id, String algorithm, int size, String certAlgorithm)
            throws Exception {
        var generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(size);
        KeyPair pair = generator.generateKeyPair();
        var name = new X500Name("CN=Test " + id + ",O=Fikua,C=ES");
        var now = Instant.now();
        var holder = new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(1, ChronoUnit.DAYS)), Date.from(now.plus(365, ChronoUnit.DAYS)),
                name, pair.getPublic())
                .build(new JcaContentSignerBuilder(certAlgorithm).build(pair.getPrivate()));
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(holder);
        var properties = new TenantProperties("client-" + id, "s", id, "p",
                new CertificateProperties("file:/dev/null", "file:/dev/null"));
        return new TenantMaterial(properties, List.of(certificate),
                List.of(Base64.getEncoder().encodeToString(certificate.getEncoded())), pair.getPrivate());
    }
}
