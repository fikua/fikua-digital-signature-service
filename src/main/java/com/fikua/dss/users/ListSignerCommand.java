package com.fikua.dss.users;

import com.fikua.dss.users.ListSigners.Subject;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;

import java.io.PrintStream;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * The operator's command {@code create-list-signer}. It prints the public
 * certificate and, once, the credential's password.
 */
public class ListSignerCommand implements ApplicationRunner {

    public static final String NAME = "create-list-signer";
    private static final String PREFIX = "dss.list-signer.";
    private static final int PASSWORD_BYTES = 32;

    private final ListSigners signers;
    private final Environment environment;
    private final PrintStream out;

    public ListSignerCommand(ListSigners signers, Environment environment, PrintStream out) {
        this.signers = signers;
        this.environment = environment;
        this.out = out;
    }

    @Override
    public void run(ApplicationArguments arguments) {
        var random = new byte[PASSWORD_BYTES];
        new SecureRandom().nextBytes(random);
        var password = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        var id = required("credential");
        X509Certificate certificate = signers.create(id, required("user"), password,
                new Subject(required("country"), required("organisation"), required("common-name")));
        out.println("credentialID: " + id);
        out.println("password (shown only now): " + password);
        out.print(ManagedUsers.pem(List.of(certificate)));
    }

    private String required(String name) {
        var value = environment.getProperty(PREFIX + name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing --" + PREFIX + name);
        }
        return value;
    }
}
