package com.fikua.dss.users;

import com.fikua.dss.users.ManagedCredential.Status;
import com.fikua.dss.users.ManagedUser.Environment;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManagedUsersTest {

    private static final String SCHEMA = "managed_users_test";

    private final MovingClock clock = new MovingClock();
    private JdbcClient jdbc;
    private ManagedUsers users;

    @BeforeEach
    void setUp() {
        var dataSource = new DriverManagerDataSource(
                Postgres.url(SCHEMA), Postgres.SERVER.getUsername(), Postgres.SERVER.getPassword());
        var flyway = Flyway.configure().dataSource(dataSource).schemas(SCHEMA).cleanDisabled(false).load();
        flyway.clean();
        flyway.migrate();
        jdbc = JdbcClient.create(dataSource);
        users = new ManagedUsers(jdbc, Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(), clock);
        users.create(new ManagedUser("altia-dev", "Altia", Environment.DEV, "Issuer", true));
    }

    private void activate(String id) {
        jdbc.sql("update dss_credential set status = 'active' where id = :id").param("id", id).update();
    }

    @Test
    void aUserIsReadAsItWasCreated() {
        assertEquals(new ManagedUser("altia-dev", "Altia", Environment.DEV, "Issuer", true),
                users.user("altia-dev").orElseThrow());
        assertTrue(users.user("nobody").isEmpty());
        assertEquals(1, users.users().size());
    }

    @Test
    void aClientIdIsUniqueAndWellFormed() {
        var again = new ManagedUser("altia-dev", "Other", Environment.STG, "", true);
        var malformed = new ManagedUser("Altia Dev", "Altia", Environment.DEV, "", true);
        assertThrows(DataIntegrityViolationException.class, () -> users.create(again));
        assertThrows(DataIntegrityViolationException.class, () -> users.create(malformed));
    }

    @Test
    void aUserIsDeactivatedAndActivated() {
        assertTrue(users.setActive("altia-dev", false));
        assertFalse(users.user("altia-dev").orElseThrow().active());
        assertTrue(users.setActive("altia-dev", true));
        assertTrue(users.user("altia-dev").orElseThrow().active());
        assertFalse(users.setActive("nobody", false));
    }

    @Test
    void aNewCredentialIsPendingAndItsPasswordDoesNotWorkYet() {
        users.createCredential("altia-dev-002", "altia-dev", "secret");
        assertEquals(Status.PENDING, users.credentials("altia-dev").getFirst().status());
        assertFalse(users.passwordMatches("altia-dev-002", "secret"));
    }

    @Test
    void aCredentialNeedsAUserAndAnIdOfItsOwn() {
        users.createCredential("altia-dev-002", "altia-dev", "secret");
        assertThrows(DataIntegrityViolationException.class,
                () -> users.createCredential("altia-dev-002", "altia-dev", "secret"));
        assertThrows(DataIntegrityViolationException.class,
                () -> users.createCredential("altia-dev-003", "nobody", "secret"));
    }

    @Test
    void onlyTheHashOfThePasswordIsKept() {
        users.createCredential("altia-dev-002", "altia-dev", "a-very-secret-password");
        users.rotatePassword("altia-dev-002", "another-secret-password", Duration.ofHours(1));
        var row = jdbc.sql("select row_to_json(c)::text from dss_credential c").query(String.class).single();
        assertFalse(row.contains("secret-password"), row);
        assertTrue(row.contains("$argon2id$"), row);
    }

    @Test
    void thePasswordIsCompared() {
        users.createCredential("altia-dev-002", "altia-dev", "secret");
        activate("altia-dev-002");
        assertTrue(users.passwordMatches("altia-dev-002", "secret"));
        assertFalse(users.passwordMatches("altia-dev-002", "other"));
        assertFalse(users.passwordMatches("altia-dev-002", null));
        assertFalse(users.passwordMatches("nope", "secret"));
    }

    @Test
    void theOldPasswordWorksUntilTheOverlapEnds() {
        users.createCredential("altia-dev-002", "altia-dev", "old");
        activate("altia-dev-002");
        assertTrue(users.rotatePassword("altia-dev-002", "new", Duration.ofHours(24)));
        assertTrue(users.passwordMatches("altia-dev-002", "old"));
        assertTrue(users.passwordMatches("altia-dev-002", "new"));

        clock.now = clock.now.plus(Duration.ofHours(25));
        assertFalse(users.passwordMatches("altia-dev-002", "old"));
        assertTrue(users.passwordMatches("altia-dev-002", "new"));
    }

    @Test
    void withoutOverlapTheOldPasswordStopsAtOnce() {
        users.createCredential("altia-dev-002", "altia-dev", "old");
        activate("altia-dev-002");
        users.rotatePassword("altia-dev-002", "newer", Duration.ofHours(24));
        users.rotatePassword("altia-dev-002", "newest", Duration.ZERO);
        assertFalse(users.passwordMatches("altia-dev-002", "old"));
        assertFalse(users.passwordMatches("altia-dev-002", "newer"));
        assertTrue(users.passwordMatches("altia-dev-002", "newest"));
        assertThrows(IllegalArgumentException.class,
                () -> users.rotatePassword("altia-dev-002", "x", Duration.ofSeconds(-1)));
    }

    @Test
    void aRevokedCredentialIsFinal() {
        users.createCredential("altia-dev-002", "altia-dev", "secret");
        activate("altia-dev-002");
        assertTrue(users.revoke("altia-dev-002"));
        assertFalse(users.passwordMatches("altia-dev-002", "secret"));
        assertFalse(users.rotatePassword("altia-dev-002", "again", Duration.ZERO));
        assertFalse(users.revoke("altia-dev-002"));
        assertEquals(Status.REVOKED, users.credentials("altia-dev").getFirst().status());
    }

    private static final class MovingClock extends Clock {
        private Instant now = Instant.parse("2026-11-25T10:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
