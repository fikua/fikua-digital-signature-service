package com.fikua.dss.service;

import com.fikua.dss.config.DssProperties;
import com.fikua.dss.config.DssProperties.CredentialProperties;
import com.fikua.dss.keys.CredentialCertificates;
import com.fikua.dss.keys.CredentialKeyStore;
import com.fikua.dss.users.ManagedUsers;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * The users of the service and their credentials (CSC v2): those loaded at start
 * from {@code dss.users} and, when there is a database, those in it. A user is the OAuth2 client that authenticates; it
 * only ever sees and uses its own credentials.
 */
@Service
public class CredentialService {

    private static final Logger log = LoggerFactory.getLogger(CredentialService.class);

    private final DssProperties properties;
    private final ManagedUsers managed;
    private final CredentialKeyStore keys;
    private final ResourceLoader resourceLoader = new DefaultResourceLoader();
    private final Map<String, User> users = new LinkedHashMap<>();
    private final Map<String, Credential> credentials = new LinkedHashMap<>();

    @Autowired
    public CredentialService(DssProperties properties, ObjectProvider<ManagedUsers> managed,
                             ObjectProvider<CredentialKeyStore> keys) {
        this(properties, managed.getIfAvailable(), keys.getIfAvailable());
    }

    /** Only the users of the configuration. */
    public CredentialService(DssProperties properties) {
        this(properties, (ManagedUsers) null, null);
    }

    private CredentialService(DssProperties properties, ManagedUsers managed, CredentialKeyStore keys) {
        this.properties = properties;
        this.managed = managed;
        this.keys = keys;
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

    /** Signs a SHA-256 digest with a credential's key: ES256, ASN.1 DER. */
    @FunctionalInterface
    public interface DigestSigner {
        byte[] sign(byte[] digest);
    }

    /** The user with this client id, or null when there is none or it is not active. */
    public User user(String userId) {
        if (userId == null) return null;
        var configured = users.get(userId);
        if (managed == null) return configured;
        var row = managed.user(userId);
        // The database decides whether a user is active, also one of the configuration.
        if (row.isPresent() && !row.get().active()) return null;
        if (row.isEmpty()) return configured;
        var all = new ArrayList<>(configured == null ? List.<Credential>of() : configured.credentials());
        managed.credentials(userId).stream().map(c -> managedCredential(userId, c.id()))
                .filter(Objects::nonNull).forEach(all::add);
        return new User(userId, configured == null ? null : configured.clientSecret(), List.copyOf(all));
    }

    /** The credential with this id when it belongs to this user; null otherwise. */
    public Credential credential(String userId, String credentialId) {
        var credential = credentialId == null ? null : credentials.get(credentialId);
        if (credential != null) {
            return credential.userId().equals(userId) ? credential : null;
        }
        return managedCredential(userId, credentialId);
    }

    /** An active credential of the database, of this user and with its key here; null otherwise. */
    private Credential managedCredential(String userId, String credentialId) {
        if (managed == null || keys == null || userId == null || credentialId == null) return null;
        if (managed.credential(credentialId).filter(c -> c.clientId().equals(userId)).isEmpty()) return null;
        return managed.certificateChain(credentialId).map(CredentialCertificates::parse)
                .map(chain -> new Credential(credentialId, userId,
                        presented -> managed.passwordMatches(credentialId, presented), chain, toBase64(chain),
                        digest -> keys.sign(credentialId, digest)))
                .orElse(null);
    }

    /** Constant-time comparison of a configured secret with the one presented. */
    static boolean matches(String expected, String presented) {
        return expected != null && presented != null && MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), presented.getBytes(StandardCharsets.UTF_8));
    }

    /** Those of the configuration. */
    public Collection<Credential> allCredentials() {
        return credentials.values();
    }

    private Credential load(String userId, CredentialProperties properties) {
        var chain = loadCertificate(properties.certificate().certPath());
        // ES256 only: a credential whose key is not EC P-256 stops the start.
        Es256.requireP256(chain.getFirst());
        var privateKey = loadPrivateKey(properties.certificate().keyPath());
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

    /** A PKCS#8 or SEC1 ("EC PRIVATE KEY") PEM private key. */
    private PrivateKey loadPrivateKey(String keyPath) {
        try (var reader = new PEMParser(new InputStreamReader(openResource(keyPath), StandardCharsets.UTF_8))) {
            var converter = new JcaPEMKeyConverter().setProvider("BC");
            var object = reader.readObject();
            if (object instanceof PrivateKeyInfo info) {
                return converter.getPrivateKey(info);
            }
            if (object instanceof PEMKeyPair pair) {
                return converter.getKeyPair(pair).getPrivate();
            }
            throw new IllegalStateException("No private key found in " + keyPath);
        } catch (IOException e) {
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
            Predicate<String> password,
            List<X509Certificate> certificateChain,
            List<String> certificateChainBase64,
            DigestSigner signer
    ) {
        /** One of the configuration: its password and key are in the process. */
        public Credential(String id, String userId, String password, List<X509Certificate> certificateChain,
                          List<String> certificateChainBase64, PrivateKey privateKey) {
            this(id, userId, presented -> matches(password, presented), certificateChain, certificateChainBase64,
                    digest -> sign(privateKey, digest));
        }

        private static byte[] sign(PrivateKey privateKey, byte[] digest) {
            try {
                var signature = Signature.getInstance("NONEwithECDSA");
                signature.initSign(privateKey);
                signature.update(digest);
                return signature.sign();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Failed to sign", e);
            }
        }

        private static final DateTimeFormatter CSC_TIME =
                DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

        /** The leaf certificate, as credentials/info describes it. */
        public X509Certificate leaf() {
            return certificateChain.getFirst();
        }

        public String issuerName() {
            return leaf().getIssuerX500Principal().getName();
        }

        public String subjectName() {
            return leaf().getSubjectX500Principal().getName();
        }

        public String serialNumberHex() {
            return leaf().getSerialNumber().toString(16);
        }

        /** Validity in the CSC GeneralizedTime form (yyyyMMddHHmmssZ, UTC). */
        public String validFrom() {
            return CSC_TIME.format(leaf().getNotBefore().toInstant());
        }

        public String validTo() {
            return CSC_TIME.format(leaf().getNotAfter().toInstant());
        }

        /** The signature algorithm credentials/info announces: ecdsa-with-SHA256 (ES256). */
        /** CSC cert.status. */
        public String certificateStatus() {
            return java.time.Instant.now().isAfter(certificateChain().getFirst().getNotAfter().toInstant())
                    ? "expired" : "valid";
        }

        public String getKeyAlgorithmOid() {
            return Es256.SIGNATURE_OID;
        }

        public int getKeyLength() {
            return Es256.KEY_LENGTH;
        }
    }
}
