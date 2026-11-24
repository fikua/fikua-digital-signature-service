package com.fikua.dss.users;

import com.fikua.dss.keys.CredentialKeyStore;
import com.fikua.dss.keys.KeyStoreContentSigner;
import com.fikua.dss.web.InvalidRequestException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.springframework.transaction.support.TransactionOperations;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.function.Predicate;

/**
 * The credentials that sign trusted lists (fikua-docs ADR 0022): the only ones
 * with a self-signed certificate, of a fixed profile (ETSI TS 119 612, 5.7.1).
 * Only the operator's command creates them, never the API.
 */
public class ListSigners {

    /** id-tsl-kp-tslSigning. */
    static final String TSL_SIGNING = "0.4.0.2231.3.0";
    private static final int YEARS = 5;
    private static final int SERIAL_BITS = 128;

    private final ManagedUsers users;
    private final CredentialKeyStore keys;
    private final TransactionOperations transaction;
    private final Predicate<String> taken;
    private final Clock clock;

    public ListSigners(ManagedUsers users, CredentialKeyStore keys, TransactionOperations transaction,
                       Predicate<String> taken, Clock clock) {
        this.users = users;
        this.keys = keys;
        this.transaction = transaction;
        this.taken = taken;
        this.clock = clock;
    }

    /** Country and organisation are the lists' scheme territory and operator name. */
    public record Subject(String country, String organisation, String commonName) {}

    /** Creates the credential, active, with its key and certificate. */
    public X509Certificate create(String credentialId, String clientId, String password, Subject subject) {
        if (taken.test(credentialId)) {
            throw new InvalidRequestException("There is a credential with that id");
        }
        if (users.user(clientId).isEmpty()) {
            throw new InvalidRequestException("Unknown user");
        }
        return transaction.execute(_ -> {
            users.createCredential(credentialId, clientId, password);
            var certificate = certificate(credentialId, keys.generate(credentialId), subject);
            users.installCertificate(credentialId, List.of(certificate));
            return certificate;
        });
    }

    private X509Certificate certificate(String credentialId, PublicKey publicKey, Subject subject) {
        try {
            var name = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.C, subject.country())
                    .addRDN(BCStyle.O, subject.organisation())
                    .addRDN(BCStyle.CN, subject.commonName()).build();
            var key = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            var from = clock.instant().truncatedTo(ChronoUnit.SECONDS);
            var to = from.atZone(ZoneOffset.UTC).plusYears(YEARS).toInstant();
            var builder = new X509v3CertificateBuilder(name, new BigInteger(SERIAL_BITS, new SecureRandom()).setBit(0),
                    Date.from(from), Date.from(to), name, key)
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true,
                            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation))
                    .addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(
                            KeyPurposeId.getInstance(new ASN1ObjectIdentifier(TSL_SIGNING))))
                    .addExtension(Extension.subjectKeyIdentifier, false,
                            new BcX509ExtensionUtils().createSubjectKeyIdentifier(key));
            return new JcaX509CertificateConverter()
                    .getCertificate(builder.build(new KeyStoreContentSigner(keys, credentialId)));
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException("Failed to build the certificate of a list signer", e);
        }
    }
}
