package com.fikua.dss.support;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

/** A throwaway CA that certifies public keys, as the PKI does with a CSR. */
public class TestCa {

    private final KeyPair pair = newPair("secp256r1");
    public final X509Certificate certificate;
    private final String name;

    public TestCa(String name) {
        this.name = name;
        this.certificate = build(name, name, pair.getPublic(), pair, true,
                Instant.now().minusSeconds(60), Instant.now().plus(Duration.ofDays(30)), KeyUsage.keyCertSign);
    }

    public X509Certificate issue(PublicKey key) {
        return issue(key, false, Instant.now().minusSeconds(60), Instant.now().plus(Duration.ofDays(10)),
                KeyUsage.nonRepudiation);
    }

    public X509Certificate issue(PublicKey key, boolean ca, Instant from, Instant to, int usage) {
        return build("CN=Leaf " + System.nanoTime(), name, key, pair, ca, from, to, usage);
    }

    public static X509Certificate selfSigned(KeyPair pair) {
        return build("CN=Self", "CN=Self", pair.getPublic(), pair, false, Instant.now().minusSeconds(60),
                Instant.now().plus(Duration.ofDays(10)), KeyUsage.nonRepudiation);
    }

    public static KeyPair newPair(String curve) {
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static String pem(Object... objects) {
        try {
            var out = new StringWriter();
            try (var writer = new JcaPEMWriter(out)) {
                for (var object : objects) {
                    writer.writeObject(object);
                }
            }
            return out.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate build(String subject, String issuer, PublicKey key, KeyPair signer, boolean ca,
                                         Instant from, Instant to, int usage) {
        try {
            var builder = new X509v3CertificateBuilder(new X500Name(issuer), BigInteger.valueOf(System.nanoTime()),
                    Date.from(from), Date.from(to), new X500Name(subject),
                    SubjectPublicKeyInfo.getInstance(key.getEncoded()));
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
            return new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
