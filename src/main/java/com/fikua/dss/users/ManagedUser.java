package com.fikua.dss.users;

/** A user kept in the database. Its client id is the one of its Keycloak client. */
public record ManagedUser(String clientId, String customer, Environment environment, String description,
                          boolean active) {

    public enum Environment { LOCAL, DEV, STG, PRO }
}
