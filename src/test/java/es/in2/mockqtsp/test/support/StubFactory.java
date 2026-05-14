package es.in2.mockqtsp.test.support;

import es.in2.mockqtsp.config.MockQtspProperties;
import es.in2.mockqtsp.service.CertificateService;
import es.in2.mockqtsp.service.SigningService;
import es.in2.mockqtsp.service.TokenService;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Plain Java stubs for controller tests. No Mockito / no Spring context needed —
 * keeps tests Java-25-friendly and ~10× faster than @WebMvcTest.
 */
public final class StubFactory {

    private StubFactory() {}

    public static MockQtspProperties props() {
        return new MockQtspProperties(
                "client-id", "client-secret",
                "cred-1", "mock-password",
                new MockQtspProperties.CertificateProperties("cert", "key"),
                3600, 300);
    }

    public static TokenService tokens() {
        return new TokenService(props()) {
            @Override public boolean validateToken(String token) { return true; }
            @Override public String issueSad(String credentialId, String password) {
                if (!"mock-password".equals(password)) throw new SecurityException("bad pwd");
                return "SAD-STUB";
            }
            @Override public boolean validateSad(String sad, String credentialId) {
                return "SAD-STUB".equals(sad);
            }
        };
    }

    public static CertificateService certs() {
        return new CertificateService(props()) {
            @Override public java.security.PrivateKey getPrivateKey() { return null; }
            @Override public List<X509Certificate> getCertificateChain() {
                return List.of(new StubCert());
            }
            @Override public List<String> getCertificateChainBase64() { return List.of("BASE64CERT"); }
            @Override public String getKeyAlgorithmOid() { return "1.2.840.113549.1.1.11"; }
            @Override public int getKeyLength() { return 2048; }
            @Override public String getSignatureAlgorithm() { return "SHA256withRSA"; }
        };
    }

    public static SigningService signing() {
        return new SigningService(certs()) {
            @Override public List<String> signHashes(List<String> hashesBase64) {
                return List.of("sig-stub");
            }
            @Override public List<String> signDocuments(List<byte[]> documents) {
                return List.of("docsig-stub");
            }
        };
    }

    /**
     * Minimal X509Certificate stub — only overrides the methods the controllers call.
     * Avoids Mockito (incompatible with Java 25 + record DTOs out-of-the-box).
     */
    private static final class StubCert extends X509Certificate {
        private static final X500Principal ISSUER = new X500Principal("CN=Issuer");
        private static final X500Principal SUBJECT = new X500Principal("CN=Subject");

        @Override public X500Principal getIssuerX500Principal() { return ISSUER; }
        @Override public X500Principal getSubjectX500Principal() { return SUBJECT; }
        @Override public BigInteger getSerialNumber() { return BigInteger.valueOf(0xABCDL); }
        @Override public Date getNotBefore() { return new Date(0); }
        @Override public Date getNotAfter() { return new Date(0); }

        @Override public void checkValidity() {}
        @Override public void checkValidity(Date date) {}
        @Override public int getVersion() { return 3; }
        @Override public java.security.Principal getIssuerDN() { return null; }
        @Override public java.security.Principal getSubjectDN() { return null; }
        @Override public boolean[] getIssuerUniqueID() { return null; }
        @Override public boolean[] getSubjectUniqueID() { return null; }
        @Override public boolean[] getKeyUsage() { return null; }
        @Override public int getBasicConstraints() { return -1; }
        @Override public byte[] getEncoded() { return new byte[0]; }
        @Override public void verify(java.security.PublicKey key) {}
        @Override public void verify(java.security.PublicKey key, String sigProvider) {}
        @Override public String toString() { return "StubCert"; }
        @Override public java.security.PublicKey getPublicKey() { return null; }
        @Override public byte[] getTBSCertificate() { return new byte[0]; }
        @Override public byte[] getSignature() { return new byte[0]; }
        @Override public String getSigAlgName() { return "SHA256withRSA"; }
        @Override public String getSigAlgOID() { return "1.2.840.113549.1.1.11"; }
        @Override public byte[] getSigAlgParams() { return null; }
        @Override public boolean hasUnsupportedCriticalExtension() { return false; }
        @Override public java.util.Set<String> getCriticalExtensionOIDs() { return null; }
        @Override public java.util.Set<String> getNonCriticalExtensionOIDs() { return null; }
        @Override public byte[] getExtensionValue(String oid) { return null; }
    }
}
