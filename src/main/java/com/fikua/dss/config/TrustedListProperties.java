package com.fikua.dss.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * The EU trusted lists (ETSI TS 119 612): where the List of Trusted Lists is,
 * which Official Journal publication announces its signers, where the local
 * copy lives and how often it is refreshed.
 */
@ConfigurationProperties(prefix = "dss.trusted-lists")
public record TrustedListProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("https://ec.europa.eu/tools/lotl/eu-lotl.xml") String lotlUrl,
        @DefaultValue("https://eur-lex.europa.eu/eli/C/2026/1944/oj") String officialJournalUrl,
        @DefaultValue("/var/lib/dss/trusted-lists") String cacheDirectory,
        @DefaultValue("PT1H") Duration refresh,
        // Older than this, the copy is stale and /health says warn.
        @DefaultValue("PT26H") Duration maxAge
) {}
