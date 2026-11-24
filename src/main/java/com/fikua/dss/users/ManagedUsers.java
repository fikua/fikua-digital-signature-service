package com.fikua.dss.users;

import com.fikua.dss.users.ManagedCredential.Status;
import com.fikua.dss.users.ManagedUser.Environment;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * The users and credentials in the database. A password goes in to be hashed or
 * compared and never comes out.
 */
public class ManagedUsers {

    private static final String USER_COLUMNS = "client_id, customer, environment, description, active";
    private static final String CREDENTIAL_COLUMNS = "id, client_id, status, password_rotated_at";

    private final JdbcClient jdbc;
    private final PasswordEncoder passwords;
    private final Clock clock;

    public ManagedUsers(JdbcClient jdbc, PasswordEncoder passwords, Clock clock) {
        this.jdbc = jdbc;
        this.passwords = passwords;
        this.clock = clock;
    }

    public Optional<ManagedUser> user(String clientId) {
        return jdbc.sql("select " + USER_COLUMNS + " from dss_user where client_id = :id")
                .param("id", clientId).query(ManagedUsers::toUser).optional();
    }

    public List<ManagedUser> users() {
        return jdbc.sql("select " + USER_COLUMNS + " from dss_user order by client_id")
                .query(ManagedUsers::toUser).list();
    }

    public void create(ManagedUser user) {
        jdbc.sql("""
                        insert into dss_user (client_id, customer, environment, description, active)
                        values (:id, :customer, :environment, :description, :active)""")
                .param("id", user.clientId()).param("customer", user.customer())
                .param("environment", lower(user.environment())).param("description", user.description())
                .param("active", user.active()).update();
    }

    /** False when there is no such user. */
    public boolean setActive(String clientId, boolean active) {
        return jdbc.sql("update dss_user set active = :active, updated_at = :now where client_id = :id")
                .param("active", active).param("now", now()).param("id", clientId).update() == 1;
    }

    public List<ManagedCredential> credentials(String clientId) {
        return jdbc.sql("select " + CREDENTIAL_COLUMNS + " from dss_credential where client_id = :id order by id")
                .param("id", clientId).query(ManagedUsers::toCredential).list();
    }

    public Optional<ManagedCredential> credential(String id) {
        return jdbc.sql("select " + CREDENTIAL_COLUMNS + " from dss_credential where id = :id")
                .param("id", id).query(ManagedUsers::toCredential).optional();
    }

    /** The certificate chain in use of an active credential, PEM, leaf first. */
    public Optional<String> certificateChain(String id) {
        return jdbc.sql("""
                        select k.chain_pem from dss_credential_certificate k
                        join dss_credential c on c.id = k.credential_id
                        where c.id = :id and c.status = 'active' order by k.id desc limit 1""")
                .param("id", id).query(String.class).optional();
    }

    /** Puts a certificate in use and activates the credential. False when it does not exist or is revoked. */
    boolean installCertificate(String id, List<X509Certificate> chain) {
        var active = jdbc.sql("update dss_credential set status = 'active', updated_at = :now "
                        + "where id = :id and status <> 'revoked'")
                .param("now", now()).param("id", id).update() == 1;
        if (active) {
            jdbc.sql("insert into dss_credential_certificate (credential_id, chain_pem, not_after, installed_at) "
                            + "values (:id, :pem, :notAfter, :now)")
                    .param("id", id).param("pem", pem(chain))
                    .param("notAfter", Timestamp.from(chain.getFirst().getNotAfter().toInstant()))
                    .param("now", now()).update();
        }
        return active;
    }

    static String pem(List<X509Certificate> chain) {
        var pem = new StringBuilder();
        for (var certificate : chain) {
            try {
                pem.append("-----BEGIN CERTIFICATE-----\n")
                        .append(Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                                .encodeToString(certificate.getEncoded()))
                        .append("\n-----END CERTIFICATE-----\n");
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Failed to encode a certificate", e);
            }
        }
        return pem.toString();
    }

    /** A new credential, pending until it has a certificate. */
    public void createCredential(String id, String clientId, String password) {
        jdbc.sql("insert into dss_credential (id, client_id, password_hash, password_rotated_at) "
                        + "values (:id, :client, :hash, :now)")
                .param("id", id).param("client", clientId).param("hash", passwords.encode(password))
                .param("now", now()).update();
    }

    /**
     * Changes the password; the one it replaces is accepted for {@code overlap}
     * more (zero, not at all). False when the credential does not exist or is revoked.
     */
    public boolean rotatePassword(String id, String password, Duration overlap) {
        if (overlap.isNegative()) {
            throw new IllegalArgumentException("Negative overlap");
        }
        var keep = overlap.isPositive();
        return jdbc.sql("""
                        update dss_credential set
                            previous_password_hash = case when :keep then password_hash end,
                            previous_password_until = case when :keep then cast(:until as timestamptz) end,
                            password_hash = :hash, password_rotated_at = :now, updated_at = :now
                        where id = :id and status <> 'revoked'""")
                .param("keep", keep).param("until", Timestamp.from(clock.instant().plus(overlap)))
                .param("hash", passwords.encode(password)).param("now", now()).param("id", id).update() == 1;
    }

    /** Whether this is the credential's password, or the one it replaced while it is still accepted. */
    public boolean passwordMatches(String id, String password) {
        if (password == null) {
            return false;
        }
        record Hashes(String current, String previous) {}
        var hashes = jdbc.sql("""
                        select password_hash,
                               case when previous_password_until > :now then previous_password_hash end as previous
                        from dss_credential where id = :id and status = 'active'""")
                .param("now", now()).param("id", id)
                .query((rs, _) -> new Hashes(rs.getString("password_hash"), rs.getString("previous"))).optional();
        return hashes.map(h -> passwords.matches(password, h.current())
                || (h.previous() != null && passwords.matches(password, h.previous()))).orElse(false);
    }

    /** Final: a revoked credential never comes back. False when there was nothing to revoke. */
    public boolean revoke(String id) {
        return jdbc.sql("""
                        update dss_credential set status = 'revoked', previous_password_hash = null,
                            previous_password_until = null, updated_at = :now
                        where id = :id and status <> 'revoked'""")
                .param("now", now()).param("id", id).update() == 1;
    }

    private Timestamp now() {
        return Timestamp.from(clock.instant());
    }

    private static String lower(Enum<?> value) {
        return value.name().toLowerCase(Locale.ROOT);
    }

    private static ManagedUser toUser(ResultSet rs, int row) throws SQLException {
        return new ManagedUser(rs.getString("client_id"), rs.getString("customer"),
                Environment.valueOf(rs.getString("environment").toUpperCase(Locale.ROOT)),
                rs.getString("description"), rs.getBoolean("active"));
    }

    private static ManagedCredential toCredential(ResultSet rs, int row) throws SQLException {
        return new ManagedCredential(rs.getString("id"), rs.getString("client_id"),
                Status.valueOf(rs.getString("status").toUpperCase(Locale.ROOT)),
                rs.getTimestamp("password_rotated_at").toInstant());
    }
}
