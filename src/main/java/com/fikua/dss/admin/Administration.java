package com.fikua.dss.admin;

import com.fikua.dss.audit.AuditEvents;
import com.fikua.dss.keys.CredentialCertificates;
import com.fikua.dss.service.CredentialService;
import com.fikua.dss.users.ManagedCredential;
import com.fikua.dss.users.ManagedCredentials;
import com.fikua.dss.users.ManagedUser;
import com.fikua.dss.users.ManagedUser.Environment;
import com.fikua.dss.users.ManagedUsers;
import com.fikua.dss.web.InvalidRequestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Users, credentials and their secrets, as one: a user is its client in the
 * authorization server and its row here.
 */
public class Administration {

    private static final Logger log = LoggerFactory.getLogger(Administration.class);
    private static final Pattern CLIENT_ID = Pattern.compile("[a-z0-9][a-z0-9-]{2,40}");
    private static final int PASSWORD_BYTES = 32;
    private static final int MAX_OVERLAP_HOURS = 168;
    private static final int MAX_TEXT = 200;

    private final ManagedUsers users;
    private final ManagedCredentials credentials;
    private final CredentialService all;
    private final MachineClients clients;
    private final AuditEvents audit;
    private final SecureRandom random = new SecureRandom();

    public Administration(ManagedUsers users, ManagedCredentials credentials, CredentialService all,
                          MachineClients clients, AuditEvents audit) {
        this.users = users;
        this.credentials = credentials;
        this.all = all;
        this.clients = clients;
        this.audit = audit;
    }

    // -- users -----------------------------------------------------------------

    public List<Views.User> users() {
        var found = new TreeMap<String, Views.User>();
        all.configuredUserIds().forEach(id -> found.put(id, view(id, Optional.empty())));
        users.users().forEach(user -> found.put(user.clientId(), view(user.clientId(), Optional.of(user))));
        return List.copyOf(found.values());
    }

    public Views.User user(String clientId) {
        var managed = users.user(clientId);
        if (managed.isEmpty() && !all.configuredUserIds().contains(clientId)) {
            throw new NotFoundException("Unknown user");
        }
        return view(clientId, managed);
    }

    /** The client in the authorization server, the user and its first credential; all or nothing. */
    public Views.CreatedUser create(Views.NewUser request, Administrator by) {
        var user = validated(request);
        var id = user.clientId();
        if (users.user(id).isPresent() || all.configuredUserIds().contains(id)) {
            throw new InvalidRequestException("There is a user with that id");
        }
        var secret = clients.create(id, user.description());
        var credentialId = id + "-001";
        var password = newPassword();
        try {
            credentials.createWithUser(user, credentialId, password);
        } catch (RuntimeException e) {
            undo(id);
            throw e;
        }
        audit.administered("admin.user.created", by.id(), id, null);
        audit.administered("admin.credential.created", by.id(), id, credentialId);
        return new Views.CreatedUser(id, secret, credentialId, password);
    }

    /** Takes a user of the configuration under administration: its credentials there do not change. */
    public Views.User adopt(Views.NewUser request, Administrator by) {
        var user = validated(request);
        if (!all.configuredUserIds().contains(user.clientId())) {
            throw new NotFoundException("Unknown user");
        }
        if (users.user(user.clientId()).isPresent()) {
            throw new InvalidRequestException("The user is already managed");
        }
        users.create(user);
        audit.administered("admin.user.adopted", by.id(), user.clientId(), null);
        return user(user.clientId());
    }

    /** Deactivating stops it here first, so it stops even if the authorization server does not answer. */
    public Views.User setActive(String clientId, boolean active, Administrator by) {
        managed(clientId);
        if (active) {
            clients.setEnabled(clientId, true);
            users.setActive(clientId, true);
        } else {
            users.setActive(clientId, false);
            audit.administered("admin.user.deactivated", by.id(), clientId, null);
            clients.setEnabled(clientId, false);
            return user(clientId);
        }
        audit.administered("admin.user.activated", by.id(), clientId, null);
        return user(clientId);
    }

    public Views.ClientSecret rotateSecret(String clientId, Administrator by) {
        managed(clientId);
        var secret = clients.rotateSecret(clientId);
        audit.administered("admin.user.secret_rotated", by.id(), clientId, null);
        return new Views.ClientSecret(clientId, secret);
    }

    // -- credentials -----------------------------------------------------------

    public List<Views.Credential> credentials() {
        return users().stream().flatMap(user -> user.credentials().stream()).toList();
    }

    public Views.CredentialPassword createCredential(String clientId, Administrator by) {
        managed(clientId);
        var id = nextCredentialId(clientId);
        var password = newPassword();
        credentials.create(id, clientId, password);
        audit.administered("admin.credential.created", by.id(), clientId, id);
        return new Views.CredentialPassword(id, password);
    }

    public String csr(String credentialId, String subject, Administrator by) {
        var credential = credential(credentialId);
        var csr = credentials.csr(credentialId, subject == null || subject.isBlank() ? "CN=" + credentialId : subject);
        audit.administered("admin.credential.csr_downloaded", by.id(), credential.clientId(), credentialId);
        return csr;
    }

    public Views.Credential installCertificate(String credentialId, String pem, Administrator by) {
        var credential = credential(credentialId);
        credentials.install(credentialId, pem);
        audit.administered("admin.credential.certificate_installed", by.id(), credential.clientId(), credentialId);
        return view(credential(credentialId));
    }

    public Views.CredentialPassword rotatePassword(String credentialId, Integer overlapHours, Administrator by) {
        var credential = credential(credentialId);
        var hours = overlapHours == null ? 0 : overlapHours;
        if (hours < 0 || hours > MAX_OVERLAP_HOURS) {
            throw new InvalidRequestException("overlapHours must be between 0 and " + MAX_OVERLAP_HOURS);
        }
        var password = newPassword();
        if (!users.rotatePassword(credentialId, password, Duration.ofHours(hours))) {
            throw new InvalidRequestException("The credential is revoked");
        }
        audit.administered("admin.credential.password_rotated", by.id(), credential.clientId(), credentialId);
        return new Views.CredentialPassword(credentialId, password);
    }

    public Views.Credential revoke(String credentialId, Administrator by) {
        var credential = credential(credentialId);
        credentials.revoke(credentialId);
        audit.administered("admin.credential.revoked", by.id(), credential.clientId(), credentialId);
        return view(credential(credentialId));
    }

    // --------------------------------------------------------------------------

    private void undo(String clientId) {
        try {
            clients.delete(clientId);
        } catch (RuntimeException e) {
            log.atError().setMessage("client left without user").addKeyValue("user.id", clientId).setCause(e).log();
        }
    }

    private void managed(String clientId) {
        if (users.user(clientId).isPresent()) return;
        if (all.configuredUserIds().contains(clientId)) {
            throw new InvalidRequestException("A user of the configuration: adopt it first");
        }
        throw new NotFoundException("Unknown user");
    }

    private ManagedCredential credential(String id) {
        return users.credential(id).orElseThrow(() -> new NotFoundException("Unknown credential"));
    }

    private String nextCredentialId(String clientId) {
        var taken = new ArrayList<>(users.credentials(clientId).stream().map(ManagedCredential::id).toList());
        all.configuredCredentials(clientId).forEach(c -> taken.add(c.id()));
        for (var number = 1; ; number++) {
            var id = clientId + "-%03d".formatted(number);
            if (!taken.contains(id)) return id;
        }
    }

    private String newPassword() {
        var bytes = new byte[PASSWORD_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static ManagedUser validated(Views.NewUser request) {
        if (request.clientId() == null || !CLIENT_ID.matcher(request.clientId()).matches()) {
            throw new InvalidRequestException("clientId: lower case letters, digits and hyphens, 3 to 41");
        }
        if (request.customer() == null || request.customer().isBlank() || request.customer().length() > MAX_TEXT) {
            throw new InvalidRequestException("customer is missing or too long");
        }
        var description = request.description() == null ? "" : request.description().strip();
        if (description.length() > MAX_TEXT) {
            throw new InvalidRequestException("description is too long");
        }
        try {
            var environment = Environment.valueOf(String.valueOf(request.environment()).toUpperCase(Locale.ROOT));
            return new ManagedUser(request.clientId(), request.customer().strip(), environment, description, true);
        } catch (IllegalArgumentException _) {
            throw new InvalidRequestException("environment must be local, dev, stg or pro");
        }
    }

    private Views.User view(String clientId, Optional<ManagedUser> managed) {
        var listed = new ArrayList<Views.Credential>();
        all.configuredCredentials(clientId).forEach(c -> listed.add(new Views.Credential(c.id(), clientId, "active",
                "file", null, certificate(c.leaf()))));
        if (managed.isPresent()) {
            users.credentials(clientId).forEach(c -> listed.add(view(c)));
        }
        return managed.map(u -> new Views.User(clientId, u.customer(), lower(u.environment()), u.description(),
                        u.active(), true, List.copyOf(listed)))
                .orElseGet(() -> new Views.User(clientId, null, null, null, true, false, List.copyOf(listed)));
    }

    private Views.Credential view(ManagedCredential credential) {
        var certificate = users.certificateChain(credential.id()).map(CredentialCertificates::parse)
                .map(chain -> certificate(chain.getFirst())).orElse(null);
        return new Views.Credential(credential.id(), credential.clientId(), lower(credential.status()), "service",
                credential.passwordRotatedAt(), certificate);
    }

    private static Views.Certificate certificate(X509Certificate certificate) {
        try {
            return new Views.Certificate(certificate.getSubjectX500Principal().getName(),
                    certificate.getIssuerX500Principal().getName(), certificate.getSerialNumber().toString(16),
                    certificate.getNotBefore().toInstant(), certificate.getNotAfter().toInstant(),
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to read a certificate", e);
        }
    }

    private static String lower(Enum<?> value) {
        return value.name().toLowerCase(Locale.ROOT);
    }
}
