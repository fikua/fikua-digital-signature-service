package com.fikua.dss.admin;

import com.fikua.dss.web.InvalidRequestException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Against the Keycloak of the platform, with the realm as fikua-platform-iac makes it. */
class KeycloakClientsTest {

    private static final GenericContainer<?> KEYCLOAK = new GenericContainer<>("quay.io/keycloak/keycloak:26.8.1")
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin").withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCommand("start-dev").withExposedPorts(8080)
            .waitingFor(Wait.forHttp("/realms/master").withStartupTimeout(Duration.ofMinutes(3)));

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static RestClient http;
    private static String url;

    private final KeycloakClients clients = new KeycloakClients(
            new AdminProperties.Keycloak(url, "dss", "fikua-sign-admin", "admin-secret"));

    @BeforeAll
    static void realm() {
        KEYCLOAK.start();
        url = "http://" + KEYCLOAK.getHost() + ":" + KEYCLOAK.getMappedPort(8080);
        http = RestClient.create(url);
        var form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "password");
        form.add("client_id", "admin-cli");
        form.add("username", "admin");
        form.add("password", "admin");
        var admin = http.post().uri("/realms/master/protocol/openid-connect/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form).retrieve().body(JsonNode.class)
                .get("access_token").asString();
        post(admin, "/admin/realms", Map.of("realm", "dss", "enabled", true));
        for (var scope : List.of("service", "credential")) {
            post(admin, "/admin/realms/dss/client-scopes", Map.of("name", scope, "protocol", "openid-connect"));
        }
        post(admin, "/admin/realms/dss/client-scopes", Map.of("name", "dss-audience", "protocol", "openid-connect",
                "attributes", Map.of("include.in.token.scope", "false"),
                "protocolMappers", List.of(Map.of("name", "aud", "protocol", "openid-connect",
                        "protocolMapper", "oidc-audience-mapper",
                        "config", Map.of("included.custom.audience", "https://dss.example.test",
                                "access.token.claim", "true")))));
        post(admin, "/admin/realms/dss/clients", Map.of("clientId", "fikua-sign-admin", "secret", "admin-secret",
                "publicClient", false, "serviceAccountsEnabled", true));
        var own = get(admin, "/admin/realms/dss/clients?clientId=fikua-sign-admin").get(0).get("id").asString();
        var user = get(admin, "/admin/realms/dss/clients/" + own + "/service-account-user").get("id").asString();
        var management = get(admin, "/admin/realms/dss/clients?clientId=realm-management").get(0).get("id").asString();
        var role = get(admin, "/admin/realms/dss/clients/" + management + "/roles/manage-clients");
        post(admin, "/admin/realms/dss/users/" + user + "/role-mappings/clients/" + management, List.of(role));
    }

    @AfterAll
    static void stop() {
        KEYCLOAK.stop();
    }

    private static void post(String admin, String path, Object body) {
        http.post().uri(path).headers(h -> h.setBearerAuth(admin)).contentType(MediaType.APPLICATION_JSON)
                .body(body).retrieve().toBodilessEntity();
    }

    private static JsonNode get(String admin, String path) {
        return http.get().uri(path).headers(h -> h.setBearerAuth(admin)).retrieve().body(JsonNode.class);
    }

    /** The claims of a token of this client, as it would ask for it. */
    private static JsonNode claims(String clientId, String secret, String scope) {
        var form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "client_credentials");
        if (scope != null) form.add("scope", scope);
        var token = http.post().uri("/realms/dss/protocol/openid-connect/token")
                .headers(h -> h.setBasicAuth(clientId, secret)).contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form).retrieve().body(JsonNode.class).get("access_token").asString();
        return MAPPER.readTree(Base64.getUrlDecoder().decode(token.split("\\.")[1]));
    }

    private static void refused(String clientId, String secret) {
        assertThrows(HttpClientErrorException.class, () -> claims(clientId, secret, null));
    }

    @Test
    void aNewClientGetsATokenForThisServiceAndNothingElse() {
        var secret = clients.create("new-dev", "A new client");
        var claims = claims("new-dev", secret, null);
        assertEquals("https://dss.example.test", claims.get("aud").asString());
        assertEquals("new-dev", claims.get("azp").asString());
        for (var claim : List.of("clientAddress", "clientHost", "realm_access", "resource_access", "email_verified",
                "preferred_username")) {
            assertFalse(claims.has(claim), claim);
        }
        assertEquals("service", claims("new-dev", secret, "service").get("scope").asString());
        assertEquals("credential", claims("new-dev", secret, "credential").get("scope").asString());
    }

    @Test
    void aClientIdIsNotReused() {
        clients.create("once-dev", "");
        assertThrows(InvalidRequestException.class, () -> clients.create("once-dev", ""));
    }

    @Test
    void aRotatedSecretReplacesTheOldOne() {
        var old = clients.create("rotated-dev", "");
        var secret = clients.rotateSecret("rotated-dev");
        assertNotEquals(old, secret);
        refused("rotated-dev", old);
        assertEquals("rotated-dev", claims("rotated-dev", secret, null).get("azp").asString());
    }

    @Test
    void aDisabledClientGetsNoTokenAndKeepsItsSecretAndScopes() {
        var secret = clients.create("disabled-dev", "");
        clients.setEnabled("disabled-dev", false);
        refused("disabled-dev", secret);
        clients.setEnabled("disabled-dev", true);
        var claims = claims("disabled-dev", secret, "service");
        assertEquals("https://dss.example.test", claims.get("aud").asString());
        assertFalse(claims.has("clientAddress"));
    }

    @Test
    void aDeletedClientIsGone() {
        var secret = clients.create("deleted-dev", "");
        clients.delete("deleted-dev");
        refused("deleted-dev", secret);
        assertThrows(InvalidRequestException.class, () -> clients.rotateSecret("deleted-dev"));
    }

    @Test
    void theOtherClientsOfTheRealmAreNotTouched() {
        for (var id : List.of("fikua-sign-admin", "realm-management", "account")) {
            assertThrows(InvalidRequestException.class, () -> clients.delete(id));
            assertThrows(InvalidRequestException.class, () -> clients.rotateSecret(id));
            assertThrows(InvalidRequestException.class, () -> clients.setEnabled(id, false));
        }
    }

    @Test
    void withoutAnswerOrPermissionItSaysSo() {
        var wrong = new KeycloakClients(new AdminProperties.Keycloak(url, "dss", "fikua-sign-admin", "nope"));
        var error = assertThrows(MachineClients.Unavailable.class, () -> wrong.create("x-dev", ""));
        assertTrue(error.getMessage().contains("401"), error.getMessage());
        var nowhere = new KeycloakClients(
                new AdminProperties.Keycloak("http://localhost:1", "dss", "fikua-sign-admin", "x"));
        assertThrows(MachineClients.Unavailable.class, () -> nowhere.create("x-dev", ""));
    }
}
