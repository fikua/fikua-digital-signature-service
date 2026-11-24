package com.fikua.dss.keys;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

/** Signs what BouncyCastle writes with a credential's key, which stays in the key store. */
public final class KeyStoreContentSigner implements ContentSigner {

    private final CredentialKeyStore keys;
    private final String credentialId;
    private final ByteArrayOutputStream content = new ByteArrayOutputStream();

    public KeyStoreContentSigner(CredentialKeyStore keys, String credentialId) {
        this.keys = keys;
        this.credentialId = credentialId;
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withECDSA");
    }

    @Override
    public OutputStream getOutputStream() {
        return content;
    }

    @Override
    public byte[] getSignature() {
        try {
            return keys.sign(credentialId, MessageDigest.getInstance("SHA-256").digest(content.toByteArray()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
