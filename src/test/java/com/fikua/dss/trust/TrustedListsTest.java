package com.fikua.dss.trust;

import com.fikua.dss.config.TrustedListProperties;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.model.DSSException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.health.contributor.Status;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The trusted lists without the network: the Official Journal signers load,
 * a refresh that cannot download leaves the service running and /health warns.
 * (The real EU LoTL was checked by hand: 31 lists, ~4,700 trust anchors.)
 */
class TrustedListsTest {

    private static final Instant NOW = Instant.parse("2026-11-22T00:00:00Z");

    @Test
    void officialJournalSignersAreBundled() {
        var signers = TrustedLists.officialJournalSigners();
        assertEquals(6, signers.getCertificates().size());
    }

    @Test
    void aRefreshWithoutNetworkLeavesNoAnchorsAndWarns(@TempDir Path cache) {
        var lists = new TrustedLists(properties(cache), Clock.fixed(NOW, ZoneOffset.UTC), new Offline());

        lists.refresh(true);

        var state = lists.state();
        assertEquals(0, state.trustedKeys());
        assertNull(state.lastError(), "a missing list is not an exception");
        var health = new TrustedListsHealthIndicator(lists).health();
        assertEquals(Status.UNKNOWN, health.getStatus(), "warn in /health, never down");
    }

    @Test
    void beforeTheFirstRefreshTheCopyIsNotFresh(@TempDir Path cache) {
        var lists = new TrustedLists(properties(cache), Clock.fixed(NOW, ZoneOffset.UTC), new Offline());

        var state = lists.state();
        assertNull(state.lastRefresh());
        assertFalse(state.fresh());
        assertNotNull(lists.certificates());
    }

    @Test
    void aCopyOlderThanMaxAgeIsStale(@TempDir Path cache) {
        var clock = new MutableClock(NOW);
        var lists = new TrustedLists(properties(cache), clock, new Offline());
        lists.refresh(false);
        assertTrue(lists.state().fresh());

        clock.now = NOW.plus(Duration.ofHours(27));
        assertFalse(lists.state().fresh());
    }

    @Test
    void startRefreshesInTheBackgroundAndStopEndsIt(@TempDir Path cache) throws Exception {
        var lists = new TrustedLists(properties(cache), Clock.fixed(NOW, ZoneOffset.UTC), new Offline());

        lists.start();
        for (int i = 0; i < 100 && lists.state().lastRefresh() == null; i++) {
            Thread.sleep(50);
        }
        lists.stop();

        assertEquals(NOW, lists.state().lastRefresh(), "the first refresh ran on the background thread");
    }

    private static TrustedListProperties properties(Path cache) {
        return new TrustedListProperties(true, "https://example.invalid/lotl.xml",
                "https://example.invalid/oj", cache.toString(), Duration.ofHours(1), Duration.ofHours(26));
    }

    /** A downloader without network: every URL is unreachable. */
    private static final class Offline extends CommonsDataLoader {
        @Override
        public byte[] get(String url) {
            throw new DSSException("offline");
        }
    }

    private static final class MutableClock extends Clock {
        Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
