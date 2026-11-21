package com.fikua.dss.trust;

import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Status;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TrustedListsHealthIndicatorTest {

    private final TrustedLists lists = mock(TrustedLists.class);
    private final TrustedListsHealthIndicator indicator = new TrustedListsHealthIndicator(lists);

    @Test
    void upWhileFreshWithAnchors() {
        when(lists.state()).thenReturn(new TrustedLists.State(Instant.now(), null, 4702, 31, true));
        var health = indicator.health();
        assertEquals(Status.UP, health.getStatus());
        assertEquals(31, health.getDetails().get("trustedLists"));
    }

    @Test
    void unknownWhenStale() {
        when(lists.state()).thenReturn(new TrustedLists.State(Instant.now(), "DSSException", 4702, 31, false));
        assertEquals(Status.UNKNOWN, indicator.health().getStatus());
    }

    @Test
    void unknownWhenFreshButEmpty() {
        when(lists.state()).thenReturn(new TrustedLists.State(Instant.now(), null, 0, 0, true));
        assertEquals(Status.UNKNOWN, indicator.health().getStatus());
    }
}
