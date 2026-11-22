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
        "dss.users[0].client-id=mock-client",
        "dss.users[0].client-secret=mock-secret",
        "dss.users[0].credentials[0].id=mock-credential-001",
        "dss.users[0].credentials[0].password=mock-password",
        "dss.users[0].credentials[0].certificate.cert-path=file:build/test-certs/mock-eseal.crt",
        "dss.users[0].credentials[0].certificate.key-path=file:build/test-certs/mock-eseal.key",
        "dss.token-ttl-seconds=3600",
        "dss.sad-ttl-seconds=300",
        // No downloads in tests: TrustedListsTest covers the trusted lists.
        "dss.trusted-lists.enabled=false"
})
public abstract class IntegrationTestBase {
}
