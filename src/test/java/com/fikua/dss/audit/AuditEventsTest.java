package com.fikua.dss.audit;

import com.fikua.dss.audit.AuditEvents.Reason;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.logs.Severity;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import io.opentelemetry.sdk.logs.data.LogRecordData;
import io.opentelemetry.sdk.logs.export.SimpleLogRecordProcessor;
import io.opentelemetry.sdk.testing.exporter.InMemoryLogRecordExporter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class AuditEventsTest {

    private InMemoryLogRecordExporter exporter;
    private AuditEvents audit;

    @BeforeEach
    void setUp() {
        exporter = InMemoryLogRecordExporter.create();
        var sdk = OpenTelemetrySdk.builder()
                .setLoggerProvider(SdkLoggerProvider.builder()
                        .addLogRecordProcessor(SimpleLogRecordProcessor.create(exporter))
                        .build())
                .build();
        audit = new AuditEvents(sdk);
    }

    @Test
    void credentialSignedCarriesOnlyTheCatalogueAttributes() {
        audit.credentialSigned("tenant-a", "cred-1", 3, "v2");

        var record = single();
        assertThat(record.getBodyValue().asString()).isEqualTo("credential.signed");
        assertThat(record.getSeverity()).isEqualTo(Severity.INFO);
        assertThat(record.getAttributes().get(AuditEvents.EVENT_DOMAIN)).isEqualTo("audit");
        assertThat(record.getAttributes().get(AuditEvents.EVENT_NAME)).isEqualTo("credential.signed");
        assertThat(record.getAttributes().get(AuditEvents.TENANT)).isEqualTo("tenant-a");
        assertThat(record.getAttributes().get(AuditEvents.CREDENTIAL)).isEqualTo("cred-1");
        assertThat(record.getAttributes().get(AuditEvents.SIGNATURE_COUNT)).isEqualTo(3L);
        assertThat(record.getAttributes().get(AuditEvents.CSC_VERSION)).isEqualTo("v2");
        assertThat(keys(record)).containsExactlyInAnyOrder(
                "event.domain", "event.name", "tenant.client_id", "credential.id", "signature.count", "csc.version");
    }

    @Test
    void tokenIssuedAndCredentialAuthorized() {
        audit.tokenIssued("tenant-a");
        audit.credentialAuthorized("tenant-a", "cred-1");

        var records = exporter.getFinishedLogRecordItems();
        assertThat(records).extracting(r -> r.getAttributes().get(AuditEvents.EVENT_NAME))
                .containsExactly("token.issued", "credential.authorized");
        assertThat(keys(records.get(0))).containsExactlyInAnyOrder("event.domain", "event.name", "tenant.client_id");
        assertThat(keys(records.get(1))).containsExactlyInAnyOrder(
                "event.domain", "event.name", "tenant.client_id", "credential.id");
    }

    @Test
    void rejectionOfAnUnknownCallerHasNoTenant() {
        audit.authRejected(null, Reason.INVALID_CLIENT);

        var record = single();
        assertThat(record.getAttributes().get(AuditEvents.EVENT_NAME)).isEqualTo("auth.rejected");
        assertThat(record.getAttributes().get(AuditEvents.REASON)).isEqualTo("invalid_client");
        assertThat(keys(record)).containsExactlyInAnyOrder("event.domain", "event.name", "reason");
    }

    @Test
    void rejectionOfAKnownTenantNamesIt() {
        audit.authRejected("tenant-a", Reason.INVALID_SAD);

        var record = single();
        assertThat(record.getAttributes().get(AuditEvents.TENANT)).isEqualTo("tenant-a");
        assertThat(record.getAttributes().get(AuditEvents.REASON)).isEqualTo("invalid_sad");
    }

    private LogRecordData single() {
        assertThat(exporter.getFinishedLogRecordItems()).hasSize(1);
        return exporter.getFinishedLogRecordItems().get(0);
    }

    private static Set<String> keys(LogRecordData record) {
        return record.getAttributes().asMap().keySet().stream()
                .map(AttributeKey::getKey)
                .collect(Collectors.toSet());
    }
}
