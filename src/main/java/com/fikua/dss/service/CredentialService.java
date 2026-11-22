package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties;
import com.fikua.dss.config.DssProperties.CredentialProperties;
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
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The users of the service and their credentials (CSC v2), loaded at start
 * from {@code dss.users}. A user is the OAuth2 client that authenticates; it
 * only ever sees and uses its own credentials.
 */
@Service
public class CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    private final DssProperties properties;
    private final ResourceLoader resourceLoader = new DefaultResourceLoader();
    private final Map<String, User> users = new LinkedHashMap<>();
    private final Map<String, Credential> credentials = new LinkedHashMap<>();

    public CredentialService(DssProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
        if (properties.users() == null || properties.users().isEmpty()) {
            throw new IllegalStateException("No users configured under dss.users");
        }
        for (var userProperties : properties.users()) {
            var userId = userProperties.clientId();
            if (userProperties.credentials() == null || userProperties.credentials().isEmpty()) {
                throw new IllegalStateException("User without credentials: " + userId);
            }
            var owned = new ArrayList<Credential>();
            for (var credentialProperties : userProperties.credentials()) {
                var credential = load(userId, credentialProperties);
                // A credential id is global: the SAD and the audit trail name it alone.
                if (credentials.putIfAbsent(credential.id(), credential) != null) {
                    throw new IllegalStateException("Duplicate credential id: " + credential.id());
                }
                owned.add(credential);
            }
            if (users.putIfAbsent(userId, new User(userId, userProperties.clientSecret(), List.copyOf(owned))) != null) {
                throw new IllegalStateException("Duplicate user client-id: " + userId);
            }
        }
    }

    /** The user with this client id, or null. */
    public User user(String userId) {
        return userId == null ? null : users.get(userId);
    }

    /** The credential with this id when it belongs to this user; null otherwise. */
    public Credential credential(String userId, String credentialId) {
        var credential = credentialId == null ? null : credentials.get(credentialId);
        return credential != null && credential.userId().equals(userId) ? credential : null;
    }

    public Collection<Credential> allCredentials() {
        return credentials.values();
    }

    private Credential load(String userId, CredentialProperties properties) {
        var chain = loadCertificate(properties.certificate().certPath());
        // ES256 only: a credential whose key is not EC P-256 stops the start.
        Es256.requireP256(chain.getFirst());
        var privateKey = loadPrivateKey(properties.certificate().keyPath(), chain);
        // No subject: once credentials hold personal certificates it is a name (OBS-05).
        log.atInfo().setMessage("credential certificate loaded")
                .addKeyValue("user.id", userId)
                .addKeyValue("credential.id", properties.id())
                .addKeyValue("certificate.issuer", chain.getFirst().getIssuerX500Principal().getName())
                .addKeyValue("certificate.not_after", chain.getFirst().getNotAfter().toInstant().toString())
                .addKeyValue("key.algorithm", privateKey.getAlgorithm())
                .log();
        return new Credential(properties.id(), userId, properties.password(), chain, toBase64(chain), privateKey);
    }

    private InputStream openResource(String path) {
        try {
            return resourceLoader.getResource(path).getInputStream();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to open resource: " + path, e);
        }
    }

    private List<X509Certificate> loadCertificate(String certPath) {
        try (var in = openResource(certPath)) {
            var chain = new ArrayList<X509Certificate>();
            for (var cert : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                chain.add((X509Certificate) cert);
            }
            if (chain.isEmpty()) {
                throw new IllegalStateException("No certificates found in " + certPath);
            }
            return chain;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load certificate from " + certPath, e);
        }
    }

    private static List<String> toBase64(List<X509Certificate> chain) {
        return chain.stream().map(cert -> {
            try {
                return Base64.getEncoder().encodeToString(cert.getEncoded());
            } catch (Exception e) {
                throw new IllegalStateException("Failed to encode certificate", e);
            }
        }).toList();
    }

    private PrivateKey loadPrivateKey(String keyPath, List<X509Certificate> chain) {
        try (var in = openResource(keyPath)) {
            var pem = new String(in.readAllBytes(), StandardCharsets.UTF_8)
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN EC PRIVATE KEY-----", "")
                    .replace("-----END EC PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            var keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem));
            return KeyFactory.getInstance(chain.getFirst().getPublicKey().getAlgorithm(), "BC").generatePrivate(keySpec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load private key from " + keyPath, e);
        }
    }

    /** A user: the OAuth2 client and the credentials it owns. */
    public record User(String id, String clientSecret, List<Credential> credentials) {
        public List<String> credentialIds() {
            return credentials.stream().map(Credential::id).toList();
        }
    }

    /** A credential: its certificate chain (leaf first) and private key, unlocked with its password. */
    public record Credential(
            String id,
            String userId,
            String password,
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
