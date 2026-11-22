package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties;
import com.fikua.dss.config.DssProperties.CertificateProperties;
import com.fikua.dss.config.DssProperties.CredentialProperties;
import com.fikua.dss.config.DssProperties.UserProperties;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** A credential whose key is not EC P-256 stops the start (ES256 only). */
class CredentialServiceEs256Test {

    @Test
    void refusesAnRsaCredential(@TempDir Path dir) throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        var name = new X500Name("CN=RSA test");
        var now = Instant.now();
        var cert = new JcaX509v3CertificateBuilder(name, BigInteger.ONE, Date.from(now),
                Date.from(now.plus(1, ChronoUnit.DAYS)), name, pair.getPublic())
                .build(new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate()));
        var crt = dir.resolve("rsa.crt");
        var key = dir.resolve("rsa.key");
        Files.writeString(crt, pem("CERTIFICATE", cert.getEncoded()));
        Files.writeString(key, pem("PRIVATE KEY", pair.getPrivate().getEncoded()));

        var service = new CredentialService(new DssProperties(List.of(new UserProperties("c", "s",
                List.of(new CredentialProperties("id", "p", new CertificateProperties("file:" + crt, "file:" + key))))),
                3600, 300));

        var error = assertThrows(IllegalStateException.class, service::init);
        assertTrue(error.getMessage().contains("P-256"), error.getMessage());
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n" + Base64.getMimeEncoder().encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }
}
