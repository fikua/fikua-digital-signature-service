package com.fikua.dss.controller;

import com.fikua.dss.service.CertificateService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class HealthController {

    private final CertificateService certificateService;

    public HealthController(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        var details = new LinkedHashMap<String, Object>();
        var checks = new LinkedHashMap<String, Object>();

        try {
            var cert = certificateService.getCertificateChain().getFirst();
            var now = new java.util.Date();
            boolean certValid = now.after(cert.getNotBefore()) && now.before(cert.getNotAfter());
            boolean keyLoaded = certificateService.getPrivateKey() != null;

            checks.put("certificate", Map.of(
                    "status", certValid ? "UP" : "DOWN",
                    "subject", cert.getSubjectX500Principal().getName(),
                    "validTo", cert.getNotAfter().toInstant().toString()
            ));
            checks.put("signingKey", Map.of(
                    "status", keyLoaded ? "UP" : "DOWN",
                    "algorithm", keyLoaded ? certificateService.getPrivateKey().getAlgorithm() : "N/A"
            ));

            boolean healthy = certValid && keyLoaded;
            details.put("status", healthy ? "UP" : "DOWN");
            details.put("checks", checks);

            return healthy
                    ? ResponseEntity.ok(details)
                    : ResponseEntity.status(503).body(details);

        } catch (Exception e) {
            details.put("status", "DOWN");
            details.put("error", e.getMessage());
            return ResponseEntity.status(503).body(details);
        }
    }
}
