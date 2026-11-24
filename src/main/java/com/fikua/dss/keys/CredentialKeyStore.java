package com.fikua.dss.keys;

import java.security.PublicKey;

/**
 * The private keys of the credentials. A key is created inside and never comes
 * in or out, so an HSM or a KMS can implement this (fikua-docs ADR 0022).
 */
public interface CredentialKeyStore {

    /** Creates the credential's P-256 key. */
    PublicKey generate(String credentialId);

    /** ES256 signature (ASN.1 DER) of a SHA-256 digest. */
    byte[] sign(String credentialId, byte[] digest);

    PublicKey publicKey(String credentialId);

    /** For ever. Does nothing when there is no key. */
    void destroy(String credentialId);
}
