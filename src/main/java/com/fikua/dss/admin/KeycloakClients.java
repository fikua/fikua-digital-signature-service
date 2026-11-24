package com.fikua.dss.admin;

import com.fikua.dss.web.InvalidRequestException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The machine clients of a Keycloak realm. Only clients with the audience scope
 * of this service are touched, so never Keycloak's own nor this one's.
 */
public class KeycloakClients implements MachineClients {

    static final String AUDIENCE_SCOPE = "dss-audience";
    private static final Set<String> DEFAULT_SCOPES = Set.of("basic", AUDIENCE_SCOPE);
    private static final Set<String> OPTIONAL_SCOPES = Set.of("service", "credential");
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final RestClient http;
    private final AdminProperties.Keycloak properties;
    private String token;
    private Instant tokenExpiry = Instant.MIN;

    public KeycloakClients(AdminProperties.Keycloak properties) {
        this.properties = properties;
        var factory = new JdkClientHttpRequestFactory(HttpClient.newBuilder().connectTimeout(TIMEOUT).build());
        factory.setReadTimeout(TIMEOUT);
        this.http = RestClient.builder().requestFactory(factory).baseUrl(properties.url()).build();
    }

    private record Token(String access_token, long expires_in) {}

    private record Client(String id, String clientId, List<String> defaultClientScopes) {}

    private record Scope(String id, String name) {}

    private record Secret(String value) {}

    @Override
    public String create(String clientId, String description) {
        return answering(() -> {
            if (!find(clientId).isEmpty()) {
                throw new InvalidRequestException("There is a client with that id");
            }
            http.post().uri(clients()).headers(h -> h.setBearerAuth(token()))
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.ofEntries(
                            Map.entry("clientId", clientId), Map.entry("description", description),
                            Map.entry("protocol", "openid-connect"), Map.entry("publicClient", false),
                            Map.entry("serviceAccountsEnabled", true), Map.entry("standardFlowEnabled", false),
                            Map.entry("directAccessGrantsEnabled", false), Map.entry("fullScopeAllowed", false),
                            Map.entry("defaultClientScopes", DEFAULT_SCOPES),
                            Map.entry("optionalClientScopes", OPTIONAL_SCOPES)))
                    .retrieve().toBodilessEntity();
            var id = find(clientId).getFirst().id();
            try {
                // Keycloak adds its own, and with them the client's IP address in the token.
                keepOnly(id, "default-client-scopes", DEFAULT_SCOPES);
                keepOnly(id, "optional-client-scopes", OPTIONAL_SCOPES);
                return secret(id);
            } catch (RuntimeException e) {
                http.delete().uri(clients() + "/{id}", id).headers(h -> h.setBearerAuth(token()))
                        .retrieve().toBodilessEntity();
                throw e;
            }
        });
    }

    @Override
    public String rotateSecret(String clientId) {
        return answering(() -> {
            var id = managed(clientId);
            return http.post().uri(clients() + "/{id}/client-secret", id).headers(h -> h.setBearerAuth(token()))
                    .retrieve().body(Secret.class).value();
        });
    }

    @Override
    public void setEnabled(String clientId, boolean enabled) {
        answering(() -> http.put().uri(clients() + "/{id}", managed(clientId))
                .headers(h -> h.setBearerAuth(token())).contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("clientId", clientId, "enabled", enabled)).retrieve().toBodilessEntity());
    }

    @Override
    public void delete(String clientId) {
        answering(() -> http.delete().uri(clients() + "/{id}", managed(clientId))
                .headers(h -> h.setBearerAuth(token())).retrieve().toBodilessEntity());
    }

    private String managed(String clientId) {
        var found = find(clientId);
        if (found.isEmpty()) {
            throw new InvalidRequestException("Unknown client");
        }
        var client = found.getFirst();
        if (client.defaultClientScopes() == null || !client.defaultClientScopes().contains(AUDIENCE_SCOPE)) {
            throw new InvalidRequestException("Not a machine client of this service");
        }
        return client.id();
    }

    private List<Client> find(String clientId) {
        var found = http.get().uri(clients() + "?clientId={clientId}", clientId)
                .headers(h -> h.setBearerAuth(token())).retrieve().body(Client[].class);
        return found == null ? List.of() : List.of(found);
    }

    private void keepOnly(String id, String kind, Set<String> wanted) {
        var scopes = http.get().uri(clients() + "/{id}/" + kind, id).headers(h -> h.setBearerAuth(token()))
                .retrieve().body(Scope[].class);
        for (var scope : scopes) {
            if (!wanted.contains(scope.name())) {
                http.delete().uri(clients() + "/{id}/" + kind + "/{scope}", id, scope.id())
                        .headers(h -> h.setBearerAuth(token())).retrieve().toBodilessEntity();
            }
        }
    }

    private String secret(String id) {
        return http.get().uri(clients() + "/{id}/client-secret", id).headers(h -> h.setBearerAuth(token()))
                .retrieve().body(Secret.class).value();
    }

    private String clients() {
        return "/admin/realms/" + properties.realm() + "/clients";
    }

    private synchronized String token() {
        if (Instant.now().isBefore(tokenExpiry)) {
            return token;
        }
        var form = new LinkedMultiValueMap<String, String>();
        form.add("grant_type", "client_credentials");
        var issued = http.post().uri("/realms/" + properties.realm() + "/protocol/openid-connect/token")
                .headers(h -> h.setBasicAuth(properties.clientId(), properties.clientSecret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form).retrieve().body(Token.class);
        token = issued.access_token();
        tokenExpiry = Instant.now().plusSeconds(Math.max(0, issued.expires_in() - 30));
        return token;
    }

    private <T> T answering(Supplier<T> call) {
        try {
            return call.get();
        } catch (RestClientResponseException e) {
            if (is(e.getStatusCode(), HttpStatus.CONFLICT)) {
                throw new InvalidRequestException("There is a client with that id");
            }
            // Its body could say too much; the status is enough.
            throw new Unavailable("Keycloak answered " + e.getStatusCode().value(), null);
        } catch (RestClientException e) {
            throw new Unavailable("Keycloak does not answer", e);
        }
    }

    private static boolean is(HttpStatusCode code, HttpStatus status) {
        return code.value() == status.value();
    }
}
