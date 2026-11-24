package com.fikua.dss.keys;

import com.fikua.dss.support.TestCa;
import com.fikua.dss.users.ManagedCredential.Status;
import com.fikua.dss.users.ManagedCredentials;
import com.fikua.dss.users.ManagedUser;
import com.fikua.dss.users.ManagedUser.Environment;
import com.fikua.dss.users.ManagedUsers;
import com.fikua.dss.users.Postgres;
import com.fikua.dss.web.InvalidRequestException;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.StringReader;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static com.fikua.dss.support.TestCa.pem;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyStoreTest {

    private static final String SCHEMA = "key_store_test";
    private static final String ID = "altia-dev-002";

    private final TestCa ca = new TestCa("CN=Accepted CA");
    private JdbcClient jdbc;
    private ManagedUsers users;
    private EncryptedDbKeyStore keys;
    private ManagedCredentials credentials;

    @BeforeEach
    void setUp() {
        var dataSource = new DriverManagerDataSource(
                Postgres.url(SCHEMA), Postgres.SERVER.getUsername(), Postgres.SERVER.getPassword());
        var flyway = Flyway.configure().dataSource(dataSource).schemas(SCHEMA).cleanDisabled(false).load();
        flyway.clean();
        flyway.migrate();
        jdbc = JdbcClient.create(dataSource);
        users = new ManagedUsers(jdbc, Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(), Clock.systemUTC());
        keys = new EncryptedDbKeyStore(jdbc, new MasterKeys(MasterKeysTest.key(1), null));
        credentials = new ManagedCredentials(users, keys,
                new CredentialCertificates(keys, List.of(ca.certificate), Clock.systemUTC()),
                new TransactionTemplate(new DataSourceTransactionManager(dataSource)), "taken-001"::equals);
        users.create(new ManagedUser("altia-dev", "Altia", Environment.DEV, "", true));
        credentials.create(ID, "altia-dev", "secret");
    }

    private static byte[] digest() throws Exception {
        return MessageDigest.getInstance("SHA-256").digest("data".getBytes());
    }

    private static boolean verifies(PublicKey key, byte[] signature) throws Exception {
        var verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(key);
        verifier.update("data".getBytes());
        return verifier.verify(signature);
    }

    private Status status() {
        return users.credential(ID).orElseThrow().status();
    }

    private void refused(String pem, String why) {
        var error = assertThrows(InvalidRequestException.class, () -> credentials.install(ID, pem));
        assertTrue(error.getMessage().contains(why), error.getMessage());
        assertEquals(Status.PENDING, status());
    }

    // -- the key never goes in or out ------------------------------------------

    @Test
    void noOperationTakesOrReturnsAPrivateKey() {
        for (var type : List.of(CredentialKeyStore.class, EncryptedDbKeyStore.class, ManagedCredentials.class,
                CredentialCertificates.class)) {
            for (var method : type.getDeclaredMethods()) {
                if (method.isSynthetic()) continue;
                assertFalse(PrivateKey.class.isAssignableFrom(method.getReturnType()), method.toString());
                assertFalse(Arrays.stream(method.getParameterTypes()).anyMatch(PrivateKey.class::isAssignableFrom),
                        method.toString());
            }
        }
    }

    @Test
    void theDatabaseHasNoKeyInClear() {
        var row = jdbc.sql("select encode(encrypted_key, 'hex') from dss_credential_key").query(String.class).single();
        // The DER header of a P-256 PKCS#8 key.
        assertFalse(row.contains("301306072a8648ce3d0201"), row);
    }

    // -- signing ---------------------------------------------------------------

    @Test
    void signsWithTheCredentialsKey() throws Exception {
        assertTrue(verifies(keys.publicKey(ID), keys.sign(ID, digest())));
        assertThrows(IllegalArgumentException.class, () -> keys.sign(ID, new byte[20]));
        assertThrows(IllegalStateException.class, () -> keys.sign("nope", digest()));
    }

    @Test
    void eachCredentialHasItsOwnKey() {
        credentials.create("altia-dev-003", "altia-dev", "secret");
        assertNotEquals(keys.publicKey(ID), keys.publicKey("altia-dev-003"));
    }

    @Test
    void anAlteredOrMovedKeyDoesNotSign() {
        credentials.create("altia-dev-003", "altia-dev", "secret");
        jdbc.sql("""
                update dss_credential_key a set encrypted_dek = b.encrypted_dek, dek_nonce = b.dek_nonce,
                    encrypted_key = b.encrypted_key, key_nonce = b.key_nonce
                from dss_credential_key b where a.credential_id = :a and b.credential_id = :b""")
                .param("a", ID).param("b", "altia-dev-003").update();
        assertThrows(IllegalStateException.class, () -> keys.sign(ID, digest()));

        jdbc.sql("update dss_credential_key set encrypted_key = set_byte(encrypted_key, 5, 255 - get_byte(encrypted_key, 5)) "
                + "where credential_id = 'altia-dev-003'").update();
        assertThrows(IllegalStateException.class, () -> keys.sign("altia-dev-003", digest()));
    }

    @Test
    void theMasterKeyIsChangedWithoutChangingTheKeys() throws Exception {
        var before = keys.publicKey(ID);
        var changing = new EncryptedDbKeyStore(jdbc, new MasterKeys(MasterKeysTest.key(2), MasterKeysTest.key(1)));
        assertEquals(1, changing.rewrap());
        assertEquals(0, changing.rewrap());

        var after = new EncryptedDbKeyStore(jdbc, new MasterKeys(MasterKeysTest.key(2), null));
        assertArrayEquals(before.getEncoded(), after.publicKey(ID).getEncoded());
        assertTrue(verifies(before, after.sign(ID, digest())));
        assertThrows(IllegalStateException.class, () -> keys.sign(ID, digest()));
    }

    // -- CSR and certificate ---------------------------------------------------

    @Test
    void theCsrIsOfTheCredentialsKeyAndSignedWithIt() throws Exception {
        var pem = credentials.csr(ID, "C=ES,O=Altia,CN=altia-dev");
        try (var parser = new PEMParser(new StringReader(pem))) {
            var csr = (PKCS10CertificationRequest) parser.readObject();
            assertTrue(csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(keys.publicKey(ID))));
            assertArrayEquals(keys.publicKey(ID).getEncoded(), csr.getSubjectPublicKeyInfo().getEncoded());
        }
        assertThrows(InvalidRequestException.class, () -> credentials.csr(ID, "not a name"));
        assertThrows(InvalidRequestException.class, () -> credentials.csr("nope", "CN=x"));
    }

    @Test
    void theCertificateOfItsKeyActivatesTheCredential() {
        assertEquals(Status.PENDING, status());
        assertFalse(users.passwordMatches(ID, "secret"));
        credentials.install(ID, pem(ca.issue(keys.publicKey(ID))));
        assertEquals(Status.ACTIVE, status());
        assertTrue(users.passwordMatches(ID, "secret"));
    }

    @Test
    void anotherCertificateOfTheSameKeyRenewsIt() {
        credentials.install(ID, pem(ca.issue(keys.publicKey(ID))));
        var renewed = ca.issue(keys.publicKey(ID));
        credentials.install(ID, pem(renewed));
        assertEquals(renewed, CredentialCertificates.parse(users.certificateChain(ID).orElseThrow()).getFirst());
        assertEquals(2, jdbc.sql("select count(*) from dss_credential_certificate").query(Integer.class).single());
    }

    @Test
    void otherCertificatesAreRefused() {
        var key = keys.publicKey(ID);
        var now = Instant.now();
        var day = Duration.ofDays(1);
        refused(pem(ca.issue(TestCa.newPair("secp256r1").getPublic())), "another key");
        refused(pem(ca.issue(key, true, now.minus(day), now.plus(day), KeyUsage.keyCertSign)), "of a CA");
        refused(pem(ca.issue(key, false, now.minus(day), now.minusSeconds(60), KeyUsage.nonRepudiation)), "not valid now");
        refused(pem(ca.issue(key, false, now.plusSeconds(600), now.plus(day), KeyUsage.nonRepudiation)), "not valid now");
        refused(pem(ca.issue(key, false, now.minus(day), now.plus(day), KeyUsage.keyAgreement)), "keyUsage");
        refused(pem(new TestCa("CN=Other CA").issue(key)), "accepted CA");
        // The same name as the accepted CA, but not its key.
        refused(pem(new TestCa("CN=Accepted CA").issue(key)), "accepted CA");
        refused("nothing", "No certificate");
        refused(null, "No certificate");
        var pair = TestCa.newPair("secp256r1");
        refused(pem(TestCa.selfSigned(pair)), "another key");
        refused(pem(ca.issue(key)) + pem(pair.getPrivate()), "private keys are never imported");
    }

    @Test
    void withoutAcceptedCasNothingIsInstalled() {
        var none = new CredentialCertificates(keys, List.of(), Clock.systemUTC());
        var certificate = pem(ca.issue(keys.publicKey(ID)));
        assertThrows(InvalidRequestException.class, () -> none.accept(ID, certificate));
    }

    // -- life ------------------------------------------------------------------

    @Test
    void revokingDestroysTheKey() {
        credentials.install(ID, pem(ca.issue(keys.publicKey(ID))));
        credentials.revoke(ID);
        assertEquals(Status.REVOKED, status());
        assertThrows(IllegalStateException.class, () -> keys.sign(ID, digest()));
        assertTrue(users.certificateChain(ID).isEmpty());
        assertThrows(InvalidRequestException.class, () -> credentials.csr(ID, "CN=x"));
        assertThrows(InvalidRequestException.class, () -> credentials.install(ID, "x"));
    }

    @Test
    void anIdOfTheConfigurationIsNotReused() {
        assertThrows(InvalidRequestException.class, () -> credentials.create("taken-001", "altia-dev", "secret"));
    }

    @Test
    void aCredentialAndItsKeyAreCreatedTogether() {
        jdbc.sql("alter table dss_credential_key rename to gone").update();
        assertThrows(RuntimeException.class, () -> credentials.create("altia-dev-009", "altia-dev", "secret"));
        assertTrue(users.credential("altia-dev-009").isEmpty());
    }
}
