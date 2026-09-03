package com.fikua.dss.health;

import com.fikua.dss.service.CertificateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;

/**
 * Exposes each tenant's signing cert + private key as an Actuator health
 * component under /health → components.certificate. Returns DOWN as soon as
 * any tenant's cert is not yet valid, has expired, or failed to load its key.
 */
@Component("certificate")
public class CertificateHealthIndicator implements HealthIndicator {

    private static final String REASON_KEY = "reason";

    private final CertificateService certificateService;
    private final Clock clock;

    @Autowired
    public CertificateHealthIndicator(CertificateService certificateService) {
        this(certificateService, Clock.systemUTC());
    }

    CertificateHealthIndicator(CertificateService certificateService, Clock clock) {
        this.certificateService = certificateService;
        this.clock = clock;
    }

    @Override
    public Health health() {
        try {
            var tenants = certificateService.allTenants();
            if (tenants.isEmpty()) {
                return Health.down().withDetail(REASON_KEY, "no tenants configured").build();
            }

            var now = Instant.now(clock);
            var builder = Health.up();
            for (var entry : tenants.entrySet()) {
                var clientId = entry.getKey();
                var material = entry.getValue();
                var cert = material.certificateChain().getFirst();
                var notBefore = cert.getNotBefore().toInstant();
                var notAfter = cert.getNotAfter().toInstant();

                if (now.isBefore(notBefore)) {
                    return Health.down()
                            .withDetail(REASON_KEY, "certificate not yet valid for tenant " + clientId)
                            .withDetail("validFrom", notBefore.toString())
                            .build();
                }
                if (now.isAfter(notAfter)) {
                    return Health.down()
                            .withDetail(REASON_KEY, "certificate expired for tenant " + clientId)
                            .withDetail("validTo", notAfter.toString())
                            .build();
                }
                builder.withDetail(clientId, cert.getSubjectX500Principal().getName()
                        + " (valid to " + notAfter + ")");
                builder.withDetail(clientId + ".keyAlgorithm", material.privateKey().getAlgorithm());
            }
            return builder.build();
        } catch (Exception e) {
            return Health.down(e).build();
        }
    }
}
