package com.fikua.dss.health;

import com.fikua.dss.service.CertificateService;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Exposes the signing cert + private key as an Actuator health component
 * under /health → components.certificate. Returns DOWN when the cert is not
 * yet valid, has expired, or the private key failed to load.
 */
@Component("certificate")
public class CertificateHealthIndicator implements HealthIndicator {

    private final CertificateService certificateService;

    public CertificateHealthIndicator(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Override
    public Health health() {
        try {
            var chain = certificateService.getCertificateChain();
            if (chain == null || chain.isEmpty()) {
                return Health.down().withDetail("reason", "no certificate loaded").build();
            }
            var cert = chain.getFirst();
            var now = Instant.now();
            var notBefore = cert.getNotBefore().toInstant();
            var notAfter = cert.getNotAfter().toInstant();
            var keyAlgo = certificateService.getPrivateKey() == null
                    ? null
                    : certificateService.getPrivateKey().getAlgorithm();

            if (now.isBefore(notBefore)) {
                return Health.down()
                        .withDetail("reason", "certificate not yet valid")
                        .withDetail("validFrom", notBefore.toString())
                        .build();
            }
            if (now.isAfter(notAfter)) {
                return Health.down()
                        .withDetail("reason", "certificate expired")
                        .withDetail("validTo", notAfter.toString())
                        .build();
            }
            if (keyAlgo == null) {
                return Health.down().withDetail("reason", "private key not loaded").build();
            }
            return Health.up()
                    .withDetail("subject", cert.getSubjectX500Principal().getName())
                    .withDetail("validTo", notAfter.toString())
                    .withDetail("keyAlgorithm", keyAlgo)
                    .build();
        } catch (Exception e) {
            return Health.down(e).build();
        }
    }
}
