package com.fikua.dss.users;

import com.fikua.dss.keys.CredentialCertificates;
import com.fikua.dss.keys.EncryptedDbKeyStore;
import com.fikua.dss.keys.MasterKeys;
import com.fikua.dss.users.ListSigners.Subject;
import com.fikua.dss.users.ManagedCredential.Status;
import com.fikua.dss.users.ManagedUser.Environment;
import com.fikua.dss.web.InvalidRequestException;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ListSignersTest {

    private static final String SCHEMA = "list_signers_test";
    private static final String ID = "altia-lists-dev-001";
    private static final Subject SUBJECT = new Subject("ES", "Scheme Operator (TEST)", "List signer DEV (TEST)");

    private ManagedUsers users;
    private EncryptedDbKeyStore keys;
    private ListSigners signers;

    @BeforeEach
    void setUp() {
        var dataSource = new DriverManagerDataSource(
                Postgres.url(SCHEMA), Postgres.SERVER.getUsername(), Postgres.SERVER.getPassword());
        var flyway = Flyway.configure().dataSource(dataSource).schemas(SCHEMA).cleanDisabled(false).load();
        flyway.clean();
        flyway.migrate();
        var jdbc = JdbcClient.create(dataSource);
        users = new ManagedUsers(jdbc, Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(), Clock.systemUTC());
        keys = new EncryptedDbKeyStore(jdbc,
                new MasterKeys(Base64.getEncoder().encodeToString(new byte[32]), null));
        signers = new ListSigners(users, keys, new TransactionTemplate(new DataSourceTransactionManager(dataSource)),
                "taken-001"::equals, Clock.systemUTC());
        users.create(new ManagedUser("altia-lists-dev", "Altia", Environment.DEV, "Lists", true));
    }

    @Test
    void theCertificateHasTheProfileOfAListSigner() throws Exception {
        var certificate = signers.create(ID, "altia-lists-dev", "secret", SUBJECT);
        certificate.verify(certificate.getPublicKey());
        assertEquals(certificate.getIssuerX500Principal(), certificate.getSubjectX500Principal());
        assertTrue(certificate.getSubjectX500Principal().getName().contains("O=Scheme Operator (TEST)"));
        assertEquals(-1, certificate.getBasicConstraints());
        assertTrue(certificate.getCriticalExtensionOIDs().containsAll(List.of("2.5.29.19", "2.5.29.15")));
        assertEquals(List.of(ListSigners.TSL_SIGNING), certificate.getExtendedKeyUsage());
        assertNotNull(certificate.getExtensionValue("2.5.29.14"));
        assertFalse(certificate.getKeyUsage()[5], "keyCertSign");
        var validity = Duration.between(certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant());
        assertTrue(validity.toDays() >= 1825, validity.toString());
        assertArrayEquals(keys.publicKey(ID).getEncoded(), certificate.getPublicKey().getEncoded());
    }

    @Test
    void itIsThenAnActiveCredentialThatSigns() throws Exception {
        var certificate = signers.create(ID, "altia-lists-dev", "secret", SUBJECT);
        assertEquals(Status.ACTIVE, users.credential(ID).orElseThrow().status());
        assertTrue(users.passwordMatches(ID, "secret"));
        assertEquals(certificate, CredentialCertificates.parse(users.certificateChain(ID).orElseThrow()).getFirst());

        var verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(certificate);
        verifier.update("list".getBytes());
        assertTrue(verifier.verify(keys.sign(ID, MessageDigest.getInstance("SHA-256").digest("list".getBytes()))));
    }

    @Test
    void itNeedsAUserAndAFreeId() {
        assertThrows(InvalidRequestException.class, () -> signers.create(ID, "nobody", "secret", SUBJECT));
        assertThrows(InvalidRequestException.class,
                () -> signers.create("taken-001", "altia-lists-dev", "secret", SUBJECT));
        assertTrue(users.credential(ID).isEmpty());
    }

    @Test
    void theCommandPrintsTheCertificateAndThePassword() {
        var out = new ByteArrayOutputStream();
        var environment = new MockEnvironment()
                .withProperty("dss.list-signer.user", "altia-lists-dev")
                .withProperty("dss.list-signer.credential", ID)
                .withProperty("dss.list-signer.country", "ES")
                .withProperty("dss.list-signer.organisation", "Scheme Operator (TEST)")
                .withProperty("dss.list-signer.common-name", "List signer DEV (TEST)");
        new ListSignerCommand(signers, environment, new PrintStream(out)).run(new DefaultApplicationArguments());
        var printed = out.toString();
        var password = printed.lines().filter(l -> l.startsWith("password")).findFirst().orElseThrow()
                .split(": ", 2)[1];
        assertTrue(users.passwordMatches(ID, password));
        assertTrue(printed.contains("-----BEGIN CERTIFICATE-----"));
        assertFalse(printed.contains("PRIVATE KEY"));
    }

    @Test
    void theCommandSaysWhatIsMissing() {
        var command = new ListSignerCommand(signers, new MockEnvironment(), System.out);
        var arguments = new DefaultApplicationArguments();
        var error = assertThrows(IllegalArgumentException.class, () -> command.run(arguments));
        assertTrue(error.getMessage().contains("dss.list-signer.credential"));
    }

    @Test
    void theServiceItselfHasNoWayToCreateOne() {
        // Only the configuration, behind dss.command, builds them.
        for (var type : List.of(ManagedCredentials.class, ManagedUsers.class)) {
            assertFalse(Arrays.stream(type.getDeclaredFields()).anyMatch(f -> f.getType() == ListSigners.class));
        }
        assertEquals(0, ListSigners.class.getAnnotations().length);
    }
}
