package com.fikua.dss.users;

import org.testcontainers.postgresql.PostgreSQLContainer;

/** One PostgreSQL for all the tests that need it, the platform's major version. */
public final class Postgres {

    public static final PostgreSQLContainer SERVER = new PostgreSQLContainer("postgres:17-alpine");

    static {
        SERVER.start();
    }

    private Postgres() {}

    /** The URL of an empty schema of its own. */
    public static String url(String schema) {
        return SERVER.getJdbcUrl() + (SERVER.getJdbcUrl().contains("?") ? "&" : "?") + "currentSchema=" + schema;
    }
}
