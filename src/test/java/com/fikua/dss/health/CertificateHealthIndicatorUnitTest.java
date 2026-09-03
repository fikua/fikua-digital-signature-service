package com.fikua.dss.health;

import com.fikua.dss.config.DssProperties;
import com.fikua.dss.config.DssProperties.CertificateProperties;
import com.fikua.dss.config.DssProperties.TenantProperties;
import com.fikua.dss.service.CertificateService;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Status;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Pure unit tests for the indicator. We generate real X.509 certificates
 * with BouncyCastle instead of mocking, because Mockito's inline mock maker
 * cannot mock JDK 25 system classes such as X509Certificate / PrivateKey.
 */
class CertificateHealthIndicatorUnitTest {

    private static final Instant NOW = Instant.parse("2026-06-01T00:00:00Z");
    private static final String TENANT_CLIENT_ID = "c";
    private final Clock fixed = Clock.fixed(NOW, ZoneOffset.UTC);

    @BeforeAll
    static void registerBc() {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static KeyPair ecKeyPair() throws Exception {
        var gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    private static X509Certificate selfSigned(KeyPair kp, Instant notBefore, Instant notAfter) throws Exception {
        var subject = new X500Principal("CN=Fikua Test e-Seal,O=Fikua,C=ES");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.nanoTime()),
                Date.from(notBefore),
                Date.from(notAfter),
                subject,
                kp.getPublic());
        var signer = new JcaContentSignerBuilder("SHA256withECDSA")
                .setProvider("BC")
                .build(kp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(builder.build(signer));
    }

    /** Stub of CertificateService that bypasses @PostConstruct file IO. */
    private static final class StubCertificateService extends CertificateService {
        private final Map<String, TenantMaterial> tenants;
        private final RuntimeException toThrow;

        StubCertificateService(List<X509Certificate> chain, PrivateKey key, RuntimeException toThrow) {
            super(new DssProperties(List.of(new TenantProperties("c", "s", "id", "p",
                    new CertificateProperties("file:/dev/null", "file:/dev/null"))),
                    3600, 300));
            this.toThrow = toThrow;
            if (chain == null) {
                this.tenants = Map.of();
            } else {
                var chainBase64 = chain.stream().map(c -> {
                    try { return Base64.getEncoder().encodeToString(c.getEncoded()); }
                    catch (Exception e) { throw new IllegalStateException(e); }
                }).toList();
                var material = new TenantMaterial(
                        new TenantProperties("c", "s", "id", "p",
                                new CertificateProperties("file:/dev/null", "file:/dev/null")),
                        chain, chainBase64, key);
                var map = new LinkedHashMap<String, TenantMaterial>();
                map.put(TENANT_CLIENT_ID, material);
                this.tenants = map;
            }
        }

        @Override public Map<String, TenantMaterial> allTenants() {
            if (toThrow != null) throw toThrow;
            return tenants;
        }
    }

    @Test
    void downWhenNoTenants() {
        var svc = new StubCertificateService(null, null, null);
        var h = new CertificateHealthIndicator(svc, fixed).health();
        assertEquals(Status.DOWN, h.getStatus());
        assertEquals("no tenants configured", h.getDetails().get("reason"));
    }

    @Test
    void downWhenCertNotYetValid() throws Exception {
        var kp = ecKeyPair();
        var cert = selfSigned(kp, NOW.plusSeconds(3600), NOW.plusSeconds(7200));
        var svc = new StubCertificateService(List.of(cert), kp.getPrivate(), null);
        var h = new CertificateHealthIndicator(svc, fixed).health();
        assertEquals(Status.DOWN, h.getStatus());
        assertEquals("certificate not yet valid for tenant " + TENANT_CLIENT_ID, h.getDetails().get("reason"));
    }

    @Test
    void downWhenCertExpired() throws Exception {
        var kp = ecKeyPair();
        var cert = selfSigned(kp, NOW.minusSeconds(7200), NOW.minusSeconds(3600));
        var svc = new StubCertificateService(List.of(cert), kp.getPrivate(), null);
        var h = new CertificateHealthIndicator(svc, fixed).health();
        assertEquals(Status.DOWN, h.getStatus());
        assertEquals("certificate expired for tenant " + TENANT_CLIENT_ID, h.getDetails().get("reason"));
    }

    @Test
    void upWhenCertAndKeyAreValid() throws Exception {
        var kp = ecKeyPair();
        var cert = selfSigned(kp, NOW.minusSeconds(3600), NOW.plusSeconds(3600));
        var svc = new StubCertificateService(List.of(cert), kp.getPrivate(), null);
        var h = new CertificateHealthIndicator(svc, fixed).health();
        assertEquals(Status.UP, h.getStatus());
    }

    @Test
    void downWhenCertificateServiceThrows() {
        var svc = new StubCertificateService(null, null, new RuntimeException("boom"));
        var h = new CertificateHealthIndicator(svc, fixed).health();
        assertEquals(Status.DOWN, h.getStatus());
    }
}
