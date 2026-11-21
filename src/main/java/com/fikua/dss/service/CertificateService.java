package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class CertificateService {

    private static final Logger log = LoggerFactory.getLogger(CertificateService.class);

    private final DssProperties properties;
    private final ResourceLoader resourceLoader = new DefaultResourceLoader();
    private final Map<String, TenantMaterial> tenantsByClientId = new LinkedHashMap<>();
    private final Map<String, TenantMaterial> tenantsByCredentialId = new LinkedHashMap<>();

    public CertificateService(DssProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
        if (properties.tenants() == null || properties.tenants().isEmpty()) {
            throw new IllegalStateException("No tenants configured under dss.tenants");
        }
        for (var tenant : properties.tenants()) {
            var certChain = loadCertificate(tenant.certificate().certPath());
            // ES256 only: a credential whose key is not EC P-256 stops the start.
            Es256.requireP256(certChain.getFirst());
            var privateKey = loadPrivateKey(tenant.certificate().keyPath(), certChain);
            var material = new TenantMaterial(tenant, certChain, toBase64(certChain), privateKey);

            if (tenantsByClientId.putIfAbsent(tenant.clientId(), material) != null) {
                throw new IllegalStateException("Duplicate tenant client-id: " + tenant.clientId());
            }
            if (tenantsByCredentialId.putIfAbsent(tenant.credentialId(), material) != null) {
                throw new IllegalStateException("Duplicate tenant credential-id: " + tenant.credentialId());
            }
            // No subject: once credentials hold personal certificates it is a name (OBS-05).
            log.atInfo().setMessage("credential certificate loaded")
                    .addKeyValue("credential.id", tenant.credentialId())
                    .addKeyValue("certificate.issuer", certChain.getFirst().getIssuerX500Principal().getName())
                    .addKeyValue("certificate.not_after", certChain.getFirst().getNotAfter().toInstant().toString())
                    .addKeyValue("key.algorithm", privateKey.getAlgorithm())
                    .log();
        }
    }

    public TenantMaterial byClientId(String clientId) {
        return tenantsByClientId.get(clientId);
    }

    public TenantMaterial byCredentialId(String credentialId) {
        return tenantsByCredentialId.get(credentialId);
    }

    public Map<String, TenantMaterial> allTenants() {
        return tenantsByClientId;
    }

    private InputStream openResource(String path) {
        try {
            var resource = resourceLoader.getResource(path);
            return resource.getInputStream();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to open resource: " + path, e);
        }
    }

    private List<X509Certificate> loadCertificate(String certPath) {
        try (var certInputStream = openResource(certPath)) {
            var certFactory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certificateChain = new ArrayList<>();
            var certs = certFactory.generateCertificates(certInputStream);
            for (var cert : certs) {
                certificateChain.add((X509Certificate) cert);
            }
            if (certificateChain.isEmpty()) {
                throw new IllegalStateException("No certificates found in " + certPath);
            }
            return certificateChain;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load certificate from " + certPath, e);
        }
    }

    private List<String> toBase64(List<X509Certificate> certificateChain) {
        return certificateChain.stream()
                .map(cert -> {
                    try {
                        return Base64.getEncoder().encodeToString(cert.getEncoded());
                    } catch (Exception e) {
                        throw new IllegalStateException("Failed to encode certificate", e);
                    }
                })
                .toList();
    }

    private PrivateKey loadPrivateKey(String keyPath, List<X509Certificate> certificateChain) {
        try (var keyInputStream = openResource(keyPath)) {
            var keyPem = new String(keyInputStream.readAllBytes(), StandardCharsets.UTF_8);
            var keyBase64 = keyPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN EC PRIVATE KEY-----", "")
                    .replace("-----END EC PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            var keyBytes = Base64.getDecoder().decode(keyBase64);
            var keySpec = new PKCS8EncodedKeySpec(keyBytes);
            var pubKeyAlgo = certificateChain.getFirst().getPublicKey().getAlgorithm();
            var keyFactory = KeyFactory.getInstance(pubKeyAlgo, "BC");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load private key from " + keyPath, e);
        }
    }

    public record TenantMaterial(
            DssProperties.TenantProperties tenant,
            List<X509Certificate> certificateChain,
            List<String> certificateChainBase64,
            PrivateKey privateKey
    ) {
        /** The signature algorithm credentials/info announces: ecdsa-with-SHA256 (ES256). */
        public String getKeyAlgorithmOid() {
            return Es256.SIGNATURE_OID;
        }

        public int getKeyLength() {
            return Es256.KEY_LENGTH;
        }
    }
}
