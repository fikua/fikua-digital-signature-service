package com.fikua.dss.audit;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.logs.Logger;
import io.opentelemetry.api.logs.Severity;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Audit events of the signature service (fikua-docs ADR 0014, section 1).
 *
 * <p>Each event is an OpenTelemetry log record with {@code event.domain = audit},
 * a stable {@code event.name} and only the attributes of the catalogue below. The
 * platform Collector sends them to the audit stream and to the locked archive, where
 * they cannot be corrected for five years: an event or attribute is added here only
 * after the catalogue has been reviewed. Events are emitted after the action is done.
 *
 * <table>
 *   <caption>Catalogue</caption>
 *   <tr><th>event.name</th><th>When</th><th>Attributes</th></tr>
 *   <tr><td>token.issued</td><td>an access token was issued to a client</td>
 *       <td>tenant.client_id</td></tr>
 *   <tr><td>credential.authorized</td><td>a SAD was issued for a credential</td>
 *       <td>tenant.client_id, credential.id</td></tr>
 *   <tr><td>credential.signed</td><td>hashes or documents were signed</td>
 *       <td>tenant.client_id, credential.id, signature.count, csc.version</td></tr>
 *   <tr><td>auth.rejected</td><td>a client, token, SAD or authorization data was refused</td>
 *       <td>tenant.client_id (only when it is a known tenant), reason</td></tr>
 * </table>
 *
 * <p>No hash, document, IP address or personal name is ever an attribute.
 */
@Component
public class AuditEvents {

    static final String INSTRUMENTATION_SCOPE = "com.fikua.dss.audit";

    static final AttributeKey<String> EVENT_DOMAIN = AttributeKey.stringKey("event.domain");
    static final AttributeKey<String> EVENT_NAME = AttributeKey.stringKey("event.name");
    static final AttributeKey<String> TENANT = AttributeKey.stringKey("tenant.client_id");
    static final AttributeKey<String> CREDENTIAL = AttributeKey.stringKey("credential.id");
    static final AttributeKey<Long> SIGNATURE_COUNT = AttributeKey.longKey("signature.count");
    static final AttributeKey<String> CSC_VERSION = AttributeKey.stringKey("csc.version");
    static final AttributeKey<String> REASON = AttributeKey.stringKey("reason");

    /** Reasons for {@code auth.rejected}. */
    public enum Reason {
        INVALID_CLIENT("invalid_client"),
        INVALID_TOKEN("invalid_token"),
        INVALID_AUTHORIZATION_DATA("invalid_authorization_data"),
        INVALID_SAD("invalid_sad");

        private final String value;

        Reason(String value) {
            this.value = value;
        }
    }

    private final Logger logger;

    /** Uses the application's OpenTelemetry instance; a no-op one when there is none. */
    @Autowired
    public AuditEvents(ObjectProvider<OpenTelemetry> openTelemetry) {
        this(openTelemetry.getIfAvailable(OpenTelemetry::noop));
    }

    AuditEvents(OpenTelemetry openTelemetry) {
        this.logger = openTelemetry.getLogsBridge().loggerBuilder(INSTRUMENTATION_SCOPE).build();
    }

    public void tokenIssued(String tenantClientId) {
        emit("token.issued", Attributes.builder().put(TENANT, tenantClientId));
    }

    public void credentialAuthorized(String tenantClientId, String credentialId) {
        emit("credential.authorized", Attributes.builder()
                .put(TENANT, tenantClientId)
                .put(CREDENTIAL, credentialId));
    }

    public void credentialSigned(String tenantClientId, String credentialId, int signatureCount, String cscVersion) {
        emit("credential.signed", Attributes.builder()
                .put(TENANT, tenantClientId)
                .put(CREDENTIAL, credentialId)
                .put(SIGNATURE_COUNT, signatureCount)
                .put(CSC_VERSION, cscVersion));
    }

    /**
     * @param knownTenantClientId the tenant, only when the caller is a known tenant;
     *                            null otherwise (never a value the caller made up)
     */
    public void authRejected(String knownTenantClientId, Reason reason) {
        var attributes = Attributes.builder().put(REASON, reason.value);
        if (knownTenantClientId != null) {
            attributes.put(TENANT, knownTenantClientId);
        }
        emit("auth.rejected", attributes);
    }

    private void emit(String name, AttributesBuilder attributes) {
        logger.logRecordBuilder()
                .setSeverity(Severity.INFO)
                .setSeverityText("INFO")
                .setBody(name)
                .setAllAttributes(attributes
                        .put(EVENT_DOMAIN, "audit")
                        .put(EVENT_NAME, name)
                        .build())
                .emit();
    }
}
