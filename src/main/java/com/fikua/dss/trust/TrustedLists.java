package com.fikua.dss.trust;

import com.fikua.dss.config.TrustedListProperties;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader;
import eu.europa.esig.dss.spi.client.http.DSSFileLoader;
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader;
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource;
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource;
import eu.europa.esig.dss.tsl.function.OfficialJournalSchemeInformationURI;
import eu.europa.esig.dss.tsl.job.TLValidationJob;
import eu.europa.esig.dss.tsl.source.LOTLSource;
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A local copy of the EU List of Trusted Lists and the national trusted lists
 * it points to (ETSI TS 119 612), with the EU DSS libraries.
 *
 * <p>Never in the request path: after the start, a background thread loads the
 * copy on disk (offline refresh) and then downloads what changed (online
 * refresh), every {@code dss.trusted-lists.refresh}. The LoTL signature is
 * checked against the signers the Official Journal announced
 * ({@code trust/eu-lotl-signers.p12}, from the EU DSS demonstrations, OJ
 * C/2026/1944) and the pivot LoTLs after it; a list with an invalid signature or
 * past its next update is not trusted ({@link ExpirationAndSignatureCheckStrategy}).
 */
@Component
@ConditionalOnProperty(prefix = "dss.trusted-lists", name = "enabled", havingValue = "true", matchIfMissing = true)
public class TrustedLists {

    private static final Logger log = LoggerFactory.getLogger(TrustedLists.class);
    private static final String SIGNERS_KEYSTORE = "/trust/eu-lotl-signers.p12";
    // The password of a keystore of public certificates, as published with it.
    private static final String SIGNERS_KEYSTORE_PASSWORD = "dss-password";

    private final TrustedListProperties properties;
    private final Clock clock;
    private final TrustedListsCertificateSource certificates = new TrustedListsCertificateSource();
    private final TLValidationJob job = new TLValidationJob();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().name("trusted-lists").daemon().factory());

    private volatile Instant lastRefresh;
    private volatile String lastError;

    @Autowired
    public TrustedLists(TrustedListProperties properties) {
        this(properties, Clock.systemUTC(), new CommonsDataLoader());
    }

    TrustedLists(TrustedListProperties properties, Clock clock, CommonsDataLoader downloader) {
        this.properties = properties;
        this.clock = clock;
        var cache = new File(properties.cacheDirectory());
        job.setListOfTrustedListSources(europeanLotl(properties));
        job.setOfflineDataLoader(loader(cache, -1, new IgnoreDataLoader()));
        job.setOnlineDataLoader(loader(cache, 0, downloader));
        job.setTrustedListCertificateSource(certificates);
        job.setSynchronizationStrategy(new ExpirationAndSignatureCheckStrategy());
    }

    /** The trust anchors of the lists currently trusted. */
    public TrustedListsCertificateSource certificates() {
        return certificates;
    }

    /** What /health reports: when the copy was last refreshed and how much it holds. */
    public State state() {
        var summary = certificates.getSummary();
        return new State(lastRefresh, lastError, certificates.getNumberOfTrustedEntityKeys(),
                summary == null ? 0 : summary.getNumberOfProcessedTLs(),
                lastRefresh != null && lastRefresh.isAfter(clock.instant().minus(properties.maxAge())));
    }

    public record State(Instant lastRefresh, String lastError, int trustedKeys, int trustedLists, boolean fresh) {}

    @EventListener(ApplicationReadyEvent.class)
    public void start() {
        scheduler.execute(() -> refresh(true));
        var every = properties.refresh().toSeconds();
        scheduler.scheduleWithFixedDelay(() -> refresh(false), every, every, TimeUnit.SECONDS);
    }

    @PreDestroy
    public void stop() {
        scheduler.shutdownNow();
    }

    /** Offline first (the copy on disk, no network), then online; never throws. */
    void refresh(boolean offlineFirst) {
        try {
            if (offlineFirst) {
                job.offlineRefresh();
                log.atInfo().setMessage("trusted lists loaded from the local copy")
                        .addKeyValue("trusted.keys", certificates.getNumberOfTrustedEntityKeys())
                        .log();
            }
            job.onlineRefresh();
            lastRefresh = clock.instant();
            lastError = null;
            log.atInfo().setMessage("trusted lists refreshed")
                    .addKeyValue("trusted.keys", certificates.getNumberOfTrustedEntityKeys())
                    .addKeyValue("trusted.lists", state().trustedLists())
                    .log();
        } catch (RuntimeException e) {
            lastError = e.getClass().getSimpleName();
            log.atWarn().setMessage("trusted lists refresh failed")
                    .addKeyValue("error.type", "trusted_lists_refresh")
                    .addKeyValue("exception.type", e.getClass().getSimpleName())
                    .setCause(e)
                    .log();
        }
    }

    private static LOTLSource europeanLotl(TrustedListProperties properties) {
        var lotl = new LOTLSource();
        lotl.setUrl(properties.lotlUrl());
        lotl.setCertificateSource(officialJournalSigners());
        lotl.setSigningCertificatesAnnouncementPredicate(
                new OfficialJournalSchemeInformationURI(properties.officialJournalUrl()));
        lotl.setPivotSupport(true);
        return lotl;
    }

    static KeyStoreCertificateSource officialJournalSigners() {
        try (var in = TrustedLists.class.getResourceAsStream(SIGNERS_KEYSTORE)) {
            if (in == null) {
                throw new IllegalStateException("Missing " + SIGNERS_KEYSTORE);
            }
            return new KeyStoreCertificateSource(in, "PKCS12", SIGNERS_KEYSTORE_PASSWORD.toCharArray());
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read " + SIGNERS_KEYSTORE, e);
        }
    }

    private static DSSFileLoader loader(File cache, long expiration,
                                        eu.europa.esig.dss.spi.client.http.DataLoader dataLoader) {
        var loader = new FileCacheDataLoader();
        loader.setFileCacheDirectory(cache);
        loader.setCacheExpirationTime(expiration);
        loader.setDataLoader(dataLoader);
        return loader;
    }
}
