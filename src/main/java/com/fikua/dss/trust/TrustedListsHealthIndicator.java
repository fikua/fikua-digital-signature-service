package com.fikua.dss.trust;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * "trustedLists" in /health: UP while the copy is fresh, UNKNOWN (warn in the
 * OBS-17 format) before the first refresh or when it is older than
 * dss.trusted-lists.max-age. Never DOWN: signing does not depend on it.
 */
@Component
@ConditionalOnBean(TrustedLists.class)
public class TrustedListsHealthIndicator implements HealthIndicator {

    private final TrustedLists trustedLists;

    public TrustedListsHealthIndicator(TrustedLists trustedLists) {
        this.trustedLists = trustedLists;
    }

    @Override
    public Health health() {
        var state = trustedLists.state();
        var builder = state.fresh() && state.trustedKeys() > 0 ? Health.up() : Health.unknown();
        return builder
                .withDetail("lastRefresh", String.valueOf(state.lastRefresh()))
                .withDetail("trustedLists", state.trustedLists())
                .withDetail("trustedKeys", state.trustedKeys())
                .withDetail("lastError", String.valueOf(state.lastError()))
                .build();
    }
}
