package com.fikua.dss.keys;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The master keys (256 bits, Base64): the current one encrypts; a previous one
 * only decrypts what it had encrypted, until it is encrypted again. A key's id
 * is a fingerprint of it.
 */
public final class MasterKeys {

    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final Map<String, SecretKeySpec> keys = new LinkedHashMap<>();
    private final String currentId;
    private final SecureRandom random = new SecureRandom();

    /** @param previous null or blank when the master key is not being changed */
    public MasterKeys(String current, String previous) {
        currentId = add(current);
        if (previous != null && !previous.isBlank()) {
            add(previous);
        }
    }

    /** A class and not a record: two are never compared. */
    public static final class Encrypted {
        private final byte[] nonce;
        private final byte[] data;

        Encrypted(byte[] nonce, byte[] data) {
            this.nonce = nonce;
            this.data = data;
        }

        byte[] nonce() {
            return nonce;
        }

        byte[] data() {
            return data;
        }
    }

    public String currentId() {
        return currentId;
    }

    Encrypted encrypt(byte[] plain, String context) {
        return encrypt(keys.get(currentId), plain, context);
    }

    byte[] decrypt(String keyId, Encrypted encrypted, String context) {
        var key = keys.get(keyId);
        if (key == null) {
            throw new IllegalStateException("Unknown master key " + keyId);
        }
        return decrypt(key, encrypted, context);
    }

    /** @param context what the data belongs to: it does not decrypt as anything else */
    Encrypted encrypt(SecretKeySpec key, byte[] plain, String context) {
        try {
            var nonce = bytes(NONCE_BYTES);
            return new Encrypted(nonce, cipher(Cipher.ENCRYPT_MODE, key, nonce, context).doFinal(plain));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    byte[] decrypt(SecretKeySpec key, Encrypted encrypted, String context) {
        try {
            return cipher(Cipher.DECRYPT_MODE, key, encrypted.nonce(), context).doFinal(encrypted.data());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }

    byte[] newDataKey() {
        return bytes(KEY_BYTES);
    }

    static SecretKeySpec aes(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    private byte[] bytes(int length) {
        var value = new byte[length];
        random.nextBytes(value);
        return value;
    }

    private static Cipher cipher(int mode, SecretKeySpec key, byte[] nonce, String context)
            throws GeneralSecurityException {
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, key, new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
        return cipher;
    }

    private String add(String base64) {
        byte[] key;
        try {
            key = Base64.getDecoder().decode(base64 == null ? "" : base64.trim());
        } catch (IllegalArgumentException _) {
            // Without the cause: its message could carry part of the key.
            throw new IllegalStateException("The master key is not Base64");
        }
        if (key.length != KEY_BYTES) {
            throw new IllegalStateException("The master key must be 32 bytes in Base64");
        }
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            digest.update("dss-master-key".getBytes(StandardCharsets.UTF_8));
            var id = HexFormat.of().formatHex(digest.digest(key), 0, 8);
            keys.put(id, aes(key));
            return id;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
