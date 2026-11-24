package com.fikua.dss.keys;

import com.fikua.dss.service.Es256;
import com.fikua.dss.web.InvalidRequestException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** The CSR of a credential's key and the checks of the certificate the CA returns for it. */
public class CredentialCertificates {

    private final CredentialKeyStore keys;
    private final Set<TrustAnchor> anchors;
    private final Clock clock;

    /** @param acceptedCas the CAs whose certificates are installed */
    public CredentialCertificates(CredentialKeyStore keys, Collection<X509Certificate> acceptedCas, Clock clock) {
        this.keys = keys;
        this.anchors = acceptedCas.stream().map(ca -> new TrustAnchor(ca, null)).collect(Collectors.toSet());
        this.clock = clock;
    }

    /** PKCS#10, PEM, signed with the credential's key. The CA decides the certificate's final subject. */
    public String csr(String credentialId, String subject) {
        try {
            var publicKey = SubjectPublicKeyInfo.getInstance(keys.publicKey(credentialId).getEncoded());
            var request = new PKCS10CertificationRequestBuilder(new X500Name(subject), publicKey)
                    .build(new KeyStoreContentSigner(keys, credentialId));
            var body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                    .encodeToString(request.getEncoded());
            return "-----BEGIN CERTIFICATE REQUEST-----\n" + body + "\n-----END CERTIFICATE REQUEST-----\n";
        } catch (IllegalArgumentException _) {
            throw new InvalidRequestException("Invalid subject");
        } catch (IOException e) {
            throw new IllegalStateException("Failed to build a CSR", e);
        }
    }

    /**
     * The chain of a credential, leaf first, when the leaf is of its key and valid
     * and leads to an accepted CA.
     *
     * @param pem the certificate and, when its issuer is not an accepted CA, the ones in between
     */
    public List<X509Certificate> accept(String credentialId, String pem) {
        if (pem != null && pem.contains("PRIVATE KEY")) {
            throw new InvalidRequestException("Only the certificate: private keys are never imported");
        }
        var chain = parse(pem);
        var leaf = chain.getFirst();
        if (!Arrays.equals(leaf.getPublicKey().getEncoded(), keys.publicKey(credentialId).getEncoded())) {
            throw new InvalidRequestException("The certificate is of another key");
        }
        try {
            Es256.requireP256(leaf);
        } catch (IllegalStateException _) {
            throw new InvalidRequestException("The certificate is not P-256");
        }
        var now = clock.instant();
        if (now.isBefore(leaf.getNotBefore().toInstant()) || now.isAfter(leaf.getNotAfter().toInstant())) {
            throw new InvalidRequestException("The certificate is not valid now");
        }
        if (leaf.getBasicConstraints() != -1) {
            throw new InvalidRequestException("It is the certificate of a CA");
        }
        if (leaf.getSubjectX500Principal().equals(leaf.getIssuerX500Principal())) {
            throw new InvalidRequestException("The certificate is self-signed");
        }
        var usage = leaf.getKeyUsage();
        if (usage == null || !(usage[0] || usage[1])) {
            throw new InvalidRequestException("The certificate is not for signing (keyUsage)");
        }
        requireAcceptedCa(chain);
        return chain;
    }

    private void requireAcceptedCa(List<X509Certificate> chain) {
        if (anchors.isEmpty()) {
            throw new InvalidRequestException("No accepted CA is configured");
        }
        try {
            var path = chain.stream().filter(c -> anchors.stream().noneMatch(a -> a.getTrustedCert().equals(c))).toList();
            var parameters = new PKIXParameters(anchors);
            // The CRLs of the PKI are for whoever trusts a signature (ADR 0022, section 5).
            parameters.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX")
                    .validate(CertificateFactory.getInstance("X.509").generateCertPath(path), parameters);
        } catch (GeneralSecurityException _) {
            throw new InvalidRequestException("The certificate does not lead to an accepted CA");
        }
    }

    public static List<X509Certificate> parse(String pem) {
        try {
            var chain = new ArrayList<X509Certificate>();
            for (var certificate : CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream((pem == null ? "" : pem).getBytes(StandardCharsets.UTF_8)))) {
                chain.add((X509Certificate) certificate);
            }
            if (chain.isEmpty()) {
                throw new InvalidRequestException("No certificate in PEM");
            }
            return chain;
        } catch (CertificateException _) {
            throw new InvalidRequestException("No certificate in PEM");
        }
    }
}
