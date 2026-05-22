package com.fikua.dss;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

/**
 * Boots the full Spring context against a self-signed e-seal generated at
 * build time by the {@code prepareTestCerts} Gradle task (see build.gradle).
 * Subclasses get a wired-up MockMvc, services, filters and Actuator endpoints
 * against the real bean graph.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dss.certificate.cert-path=file:build/test-certs/mock-eseal.crt",
        "dss.certificate.key-path=file:build/test-certs/mock-eseal.key",
        "dss.token-ttl-seconds=3600",
        "dss.sad-ttl-seconds=300"
})
public abstract class IntegrationTestBase {
}
