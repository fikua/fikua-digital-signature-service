package es.in2.mockqtsp.service;

import es.in2.mockqtsp.config.MockQtspProperties;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Service
public class CertificateService {

    private static final Logger log = LoggerFactory.getLogger(CertificateService.class);

    private final MockQtspProperties properties;
    private final ResourceLoader resourceLoader = new DefaultResourceLoader();
    private PrivateKey privateKey;
    private List<X509Certificate> certificateChain;
    private List<String> certificateChainBase64;

    public CertificateService(MockQtspProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
        loadCertificate();
        loadPrivateKey();
        log.info("Certificate loaded: subject={}, issuer={}, algo={}",
                certificateChain.getFirst().getSubjectX500Principal(),
                certificateChain.getFirst().getIssuerX500Principal(),
                privateKey.getAlgorithm());
    }

    public PrivateKey getPrivateKey() { return privateKey; }
    public List<X509Certificate> getCertificateChain() { return certificateChain; }
    public List<String> getCertificateChainBase64() { return certificateChainBase64; }

    private InputStream openResource(String path) {
        try {
            var resource = resourceLoader.getResource(path);
            return resource.getInputStream();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to open resource: " + path, e);
        }
    }

    private void loadCertificate() {
        var certPath = properties.certificate().certPath();
        try (var certInputStream = openResource(certPath)) {
            var certFactory = CertificateFactory.getInstance("X.509");
            certificateChain = new ArrayList<>();
            var certs = certFactory.generateCertificates(certInputStream);
            for (var cert : certs) {
                certificateChain.add((X509Certificate) cert);
            }
            if (certificateChain.isEmpty()) {
                throw new IllegalStateException("No certificates found in " + certPath);
            }
            certificateChainBase64 = certificateChain.stream()
                    .map(cert -> {
                        try {
                            return Base64.getEncoder().encodeToString(cert.getEncoded());
                        } catch (Exception e) {
                            throw new IllegalStateException("Failed to encode certificate", e);
                        }
                    })
                    .toList();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load certificate from " + certPath, e);
        }
    }

    private void loadPrivateKey() {
        var keyPath = properties.certificate().keyPath();
        try (var keyInputStream = openResource(keyPath)) {
            var keyPem = new String(keyInputStream.readAllBytes(), StandardCharsets.UTF_8);
            var keyBase64 = keyPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN EC PRIVATE KEY-----", "")
                    .replace("-----END EC PRIVATE KEY-----", "")
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            var keyBytes = Base64.getDecoder().decode(keyBase64);
            var keySpec = new PKCS8EncodedKeySpec(keyBytes);
            var pubKeyAlgo = certificateChain.getFirst().getPublicKey().getAlgorithm();
            var keyFactory = KeyFactory.getInstance(pubKeyAlgo, "BC");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load private key from " + keyPath, e);
        }
    }

    public String getKeyAlgorithmOid() {
        var algo = certificateChain.getFirst().getPublicKey().getAlgorithm();
        return switch (algo) {
            case "EC" -> "1.2.840.10045.4.3.2";
            case "RSA" -> "1.2.840.113549.1.1.11";
            default -> throw new IllegalStateException("Unsupported key algorithm: " + algo);
        };
    }

    public int getKeyLength() {
        var algo = certificateChain.getFirst().getPublicKey().getAlgorithm();
        return switch (algo) {
            case "EC" -> 256;
            case "RSA" -> 2048;
            default -> 256;
        };
    }

    public String getSignatureAlgorithm() {
        var algo = privateKey.getAlgorithm();
        return switch (algo) {
            case "EC" -> "SHA256withECDSA";
            case "RSA" -> "SHA256withRSA";
            default -> throw new IllegalStateException("Unsupported algorithm: " + algo);
        };
    }
}
