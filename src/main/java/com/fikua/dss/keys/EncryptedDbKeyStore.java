package com.fikua.dss.keys;

import com.fikua.dss.keys.MasterKeys.Encrypted;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Optional;

/**
 * The keys in the database with envelope encryption (AES-256-GCM). It is not an
 * HSM: a key is in the process memory while it signs.
 */
public class EncryptedDbKeyStore implements CredentialKeyStore {

    private static final int SHA256_BYTES = 32;

    private final JdbcClient jdbc;
    private final MasterKeys masterKeys;

    public EncryptedDbKeyStore(JdbcClient jdbc, MasterKeys masterKeys) {
        this.jdbc = jdbc;
        this.masterKeys = masterKeys;
    }

    @Override
    public PublicKey generate(String credentialId) {
        byte[] dek = null;
        byte[] encoded = null;
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            var pair = generator.generateKeyPair();
            encoded = pair.getPrivate().getEncoded();
            dek = masterKeys.newDataKey();
            var key = masterKeys.encrypt(MasterKeys.aes(dek), encoded, keyContext(credentialId));
            var wrapped = masterKeys.encrypt(dek, dekContext(credentialId));
            jdbc.sql("""
                            insert into dss_credential_key (credential_id, kek_id, encrypted_dek, dek_nonce,
                                                            encrypted_key, key_nonce, public_key)
                            values (:id, :kek, :dek, :dekNonce, :key, :keyNonce, :public)""")
                    .param("id", credentialId).param("kek", masterKeys.currentId())
                    .param("dek", wrapped.data()).param("dekNonce", wrapped.nonce())
                    .param("key", key.data()).param("keyNonce", key.nonce())
                    .param("public", pair.getPublic().getEncoded()).update();
            return pair.getPublic();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to create a key", e);
        } finally {
            wipe(dek);
            wipe(encoded);
        }
    }

    @Override
    public byte[] sign(String credentialId, byte[] digest) {
        if (digest.length != SHA256_BYTES) {
            throw new IllegalArgumentException("Not a SHA-256 digest");
        }
        var row = row(credentialId).orElseThrow(() -> new IllegalStateException("No key for " + credentialId));
        byte[] dek = null;
        byte[] encoded = null;
        try {
            dek = masterKeys.decrypt(row.kekId(), row.dek(), dekContext(credentialId));
            encoded = masterKeys.decrypt(MasterKeys.aes(dek), row.key(), keyContext(credentialId));
            var signature = Signature.getInstance("NONEwithECDSA");
            signature.initSign(KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encoded)));
            signature.update(digest);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign", e);
        } finally {
            wipe(dek);
            wipe(encoded);
        }
    }

    @Override
    public PublicKey publicKey(String credentialId) {
        return row(credentialId).orElseThrow(() -> new IllegalStateException("No key for " + credentialId)).publicKey();
    }

    @Override
    public void destroy(String credentialId) {
        jdbc.sql("delete from dss_credential_key where credential_id = :id").param("id", credentialId).update();
    }

    /** Encrypts with the current master key what a previous one still encrypts; the keys do not change. */
    public int rewrap() {
        var ids = jdbc.sql("select credential_id from dss_credential_key where kek_id <> :kek")
                .param("kek", masterKeys.currentId()).query(String.class).list();
        var done = 0;
        for (var id : ids) {
            var row = row(id);
            if (row.isEmpty()) continue;
            var dek = masterKeys.decrypt(row.get().kekId(), row.get().dek(), dekContext(id));
            try {
                var wrapped = masterKeys.encrypt(dek, dekContext(id));
                done += jdbc.sql("""
                                update dss_credential_key set kek_id = :kek, encrypted_dek = :dek, dek_nonce = :nonce
                                where credential_id = :id and kek_id = :old""")
                        .param("kek", masterKeys.currentId()).param("dek", wrapped.data())
                        .param("nonce", wrapped.nonce()).param("id", id).param("old", row.get().kekId()).update();
            } finally {
                wipe(dek);
            }
        }
        return done;
    }

    private record Row(String kekId, Encrypted dek, Encrypted key, PublicKey publicKey) {}

    private Optional<Row> row(String credentialId) {
        return jdbc.sql("""
                        select kek_id, encrypted_dek, dek_nonce, encrypted_key, key_nonce, public_key
                        from dss_credential_key where credential_id = :id""")
                .param("id", credentialId).query(EncryptedDbKeyStore::toRow).optional();
    }

    private static Row toRow(ResultSet rs, int number) throws SQLException {
        return new Row(rs.getString("kek_id"),
                new Encrypted(rs.getBytes("dek_nonce"), rs.getBytes("encrypted_dek")),
                new Encrypted(rs.getBytes("key_nonce"), rs.getBytes("encrypted_key")),
                publicKey(rs.getBytes("public_key")));
    }

    private static PublicKey publicKey(byte[] encoded) {
        try {
            return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to read a public key", e);
        }
    }

    private static String dekContext(String credentialId) {
        return "dek:" + credentialId;
    }

    private static String keyContext(String credentialId) {
        return "key:" + credentialId;
    }

    private static void wipe(byte[] value) {
        if (value != null) {
            Arrays.fill(value, (byte) 0);
        }
    }
}
