package com.fikua.dss.health;

import com.fikua.dss.service.CredentialService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;

/**
 * Exposes each credential's certificate as an Actuator health component under
 * /health → components.certificate. Returns DOWN as soon as any credential's
 * certificate is not yet valid or has expired.
 */
@Component("certificate")
public class CertificateHealthIndicator implements HealthIndicator {

    private static final String REASON_KEY = "reason";

    private final CredentialService credentialService;
    private final Clock clock;

    @Autowired
    public CertificateHealthIndicator(CredentialService credentialService) {
        this(credentialService, Clock.systemUTC());
    }

    CertificateHealthIndicator(CredentialService credentialService, Clock clock) {
        this.credentialService = credentialService;
        this.clock = clock;
    }

    @Override
    public Health health() {
        try {
            var all = credentialService.allCredentials();
            if (all.isEmpty()) {
                return Health.down().withDetail(REASON_KEY, "no credentials configured").build();
            }

            var now = Instant.now(clock);
            var builder = Health.up();
            for (var credential : all) {
                var id = credential.id();
                var cert = credential.certificateChain().getFirst();
                var notBefore = cert.getNotBefore().toInstant();
                var notAfter = cert.getNotAfter().toInstant();

                if (now.isBefore(notBefore)) {
                    return Health.down()
                            .withDetail(REASON_KEY, "certificate not yet valid for credential " + id)
                            .withDetail("validFrom", notBefore.toString())
                            .build();
                }
                if (now.isAfter(notAfter)) {
                    return Health.down()
                            .withDetail(REASON_KEY, "certificate expired for credential " + id)
                            .withDetail("validTo", notAfter.toString())
                            .build();
                }
                builder.withDetail(id, cert.getSubjectX500Principal().getName()
                        + " (valid to " + notAfter + ", user " + credential.userId() + ")");
            }
            return builder.build();
        } catch (Exception e) {
            return Health.down(e).build();
        }
    }
}
