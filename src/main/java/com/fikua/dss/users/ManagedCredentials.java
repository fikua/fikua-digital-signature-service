package com.fikua.dss.users;

import com.fikua.dss.keys.CredentialCertificates;
import com.fikua.dss.keys.CredentialKeyStore;
import com.fikua.dss.users.ManagedCredential.Status;
import com.fikua.dss.web.InvalidRequestException;
import org.springframework.transaction.support.TransactionOperations;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Predicate;

/**
 * The life of a credential: created with its key, pending until it has a
 * certificate, active, renewed with another certificate of the same key, and
 * revoked, which destroys the key.
 */
public class ManagedCredentials {

    private final ManagedUsers users;
    private final CredentialKeyStore keys;
    private final CredentialCertificates certificates;
    private final TransactionOperations transaction;
    private final Predicate<String> taken;

    /** @param taken whether an id is of a credential outside the database */
    public ManagedCredentials(ManagedUsers users, CredentialKeyStore keys, CredentialCertificates certificates,
                              TransactionOperations transaction, Predicate<String> taken) {
        this.users = users;
        this.keys = keys;
        this.certificates = certificates;
        this.transaction = transaction;
        this.taken = taken;
    }

    public void create(String id, String clientId, String password) {
        if (taken.test(id)) {
            throw new InvalidRequestException("There is a credential with that id");
        }
        transaction.executeWithoutResult(_ -> {
            users.createCredential(id, clientId, password);
            keys.generate(id);
        });
    }

    public String csr(String id, String subject) {
        require(id);
        return certificates.csr(id, subject);
    }

    /** Activates a pending credential or renews an active one. */
    public List<X509Certificate> install(String id, String pem) {
        require(id);
        var chain = certificates.accept(id, pem);
        transaction.executeWithoutResult(_ -> {
            if (!users.installCertificate(id, chain)) {
                throw new InvalidRequestException("The credential is revoked");
            }
        });
        return chain;
    }

    public void revoke(String id) {
        transaction.executeWithoutResult(_ -> {
            users.revoke(id);
            keys.destroy(id);
        });
    }

    private void require(String id) {
        var credential = users.credential(id)
                .orElseThrow(() -> new InvalidRequestException("Unknown credential"));
        if (credential.status() == Status.REVOKED) {
            throw new InvalidRequestException("The credential is revoked");
        }
    }
}
