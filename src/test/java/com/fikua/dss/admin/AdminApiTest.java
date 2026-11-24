package com.fikua.dss.admin;

import com.fikua.dss.IntegrationTestBase;
import com.fikua.dss.service.TokenService;
import com.fikua.dss.support.FakeAuthorizationServer;
import com.fikua.dss.support.TestCa;
import com.fikua.dss.users.ManagedUsers;
import com.fikua.dss.users.Postgres;
import com.fikua.dss.web.InvalidRequestException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.StringReader;
import java.nio.file.Files;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@Import(AdminApiTest.Clients.class)
class AdminApiTest extends IntegrationTestBase {

    private static final int PORT = 9443;
    private static final String SCHEMA = "admin_api_test";
    private static final FakeAuthorizationServer SERVER = new FakeAuthorizationServer();
    private static final TestCa CA = new TestCa("CN=Accepted CA");

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper mapper;
    @Autowired FakeClients clients;
    @Autowired ManagedUsers users;
    @Autowired TokenService tokenService;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) throws Exception {
        JdbcClient.create(new DriverManagerDataSource(Postgres.SERVER.getJdbcUrl(), Postgres.SERVER.getUsername(),
                Postgres.SERVER.getPassword())).sql("create schema " + SCHEMA).update();
        var ca = Files.createTempFile("accepted-ca", ".pem");
        Files.writeString(ca, TestCa.pem(CA.certificate));
        registry.add("dss.database.url", () -> Postgres.url(SCHEMA));
        registry.add("dss.database.username", Postgres.SERVER::getUsername);
        registry.add("dss.database.password", Postgres.SERVER::getPassword);
        registry.add("dss.keys.master-key", () -> Base64.getEncoder().encodeToString(new byte[32]));
        registry.add("dss.keys.accepted-cas[0]", () -> "file:" + ca);
        registry.add("dss.admin.port", () -> PORT);
        registry.add("dss.admin.issuer", () -> FakeAuthorizationServer.ISSUER);
        registry.add("dss.admin.jwks-uri", SERVER::jwksUri);
        registry.add("dss.admin.audience", () -> FakeAuthorizationServer.AUDIENCE);
        registry.add("dss.admin.keycloak.url", () -> "http://localhost:1");
    }

    /** The authorization server, in memory. */
    static class FakeClients implements MachineClients {
        final Map<String, String> secrets = new HashMap<>();
        final Map<String, Boolean> enabled = new HashMap<>();
        boolean down;

        private void answer() {
            if (down) throw new Unavailable("down", null);
        }

        @Override
        public String create(String clientId, String description) {
            answer();
            if (secrets.containsKey(clientId)) throw new InvalidRequestException("There is a client with that id");
            secrets.put(clientId, UUID.randomUUID().toString());
            enabled.put(clientId, true);
            return secrets.get(clientId);
        }

        @Override
        public String rotateSecret(String clientId) {
            answer();
            secrets.put(clientId, UUID.randomUUID().toString());
            return secrets.get(clientId);
        }

        @Override
        public void setEnabled(String clientId, boolean value) {
            answer();
            enabled.put(clientId, value);
        }

        @Override
        public void delete(String clientId) {
            secrets.remove(clientId);
        }
    }

    @TestConfiguration
    static class Clients {
        @Bean
        @Primary
        FakeClients fakeClients() {
            return new FakeClients();
        }
    }

    @BeforeEach
    void up() {
        clients.down = false;
    }

    private static String admin(String... groups) {
        return SERVER.sign(FakeAuthorizationServer.claims("portal").subject("admin-sub").claim("name", "Admin")
                .claim("groups", List.of(groups)).build());
    }

    private ResultActions call(HttpMethod method, String path, String json) throws Exception {
        var request = on(PORT, method, path).header("Authorization", "Bearer " + admin("dss-admins"));
        return mockMvc.perform(json == null ? request : request.contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private static MockHttpServletRequestBuilder on(int port, HttpMethod method, String path) {
        return request(method, path).servletPath(path.split("\\?")[0]).with(r -> {
            r.setLocalPort(port);
            return r;
        });
    }

    private JsonNode json(ResultActions result) throws Exception {
        return mapper.readTree(result.andReturn().getResponse().getContentAsString());
    }

    private JsonNode create(String id) throws Exception {
        return json(call(HttpMethod.POST, "/admin/v1/users", """
                {"clientId":"%s","customer":"Altia","environment":"dev","description":"Issuer"}""".formatted(id))
                .andExpect(status().isCreated()));
    }

    private String install(String credentialId) throws Exception {
        var pem = call(HttpMethod.GET, "/admin/v1/credentials/" + credentialId + "/csr", null)
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        try (var parser = new PEMParser(new StringReader(pem))) {
            var csr = new JcaPKCS10CertificationRequest((PKCS10CertificationRequest) parser.readObject());
            var certificate = TestCa.pem(CA.issue(csr.getPublicKey()));
            mockMvc.perform(on(PORT, HttpMethod.PUT, "/admin/v1/credentials/" + credentialId + "/certificate")
                            .header("Authorization", "Bearer " + admin("dss-admins"))
                            .contentType("application/x-pem-file").content(certificate))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.status").value("active"));
            return certificate;
        }
    }

    // -- who gets in -----------------------------------------------------------

    @Test
    void onlyOnItsPort() throws Exception {
        var token = "Bearer " + admin("dss-admins");
        mockMvc.perform(on(80, HttpMethod.GET, "/admin/v1/users").header("Authorization", token))
                .andExpect(status().isNotFound());
        mockMvc.perform(on(PORT, HttpMethod.POST, "/csc/v2/info").header("Authorization", token)
                .contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isNotFound());
        mockMvc.perform(on(80, HttpMethod.POST, "/csc/v2/info")
                .contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isOk());
    }

    @Test
    void onlyAnAdministrator() throws Exception {
        for (var path : List.of("/admin/v1/me", "/admin/v1/users", "/admin/v1/credentials")) {
            mockMvc.perform(on(PORT, HttpMethod.GET, path)).andExpect(status().isUnauthorized());
            mockMvc.perform(on(PORT, HttpMethod.GET, path).header("Authorization", "Bearer x.y.z"))
                    .andExpect(status().isUnauthorized());
            mockMvc.perform(on(PORT, HttpMethod.GET, path).header("Authorization", "Bearer " + admin("other")))
                    .andExpect(status().isForbidden());
        }
        var noGroups = SERVER.sign(FakeAuthorizationServer.claims("portal").build());
        mockMvc.perform(on(PORT, HttpMethod.GET, "/admin/v1/me").header("Authorization", "Bearer " + noGroups))
                .andExpect(status().isForbidden());
        call(HttpMethod.GET, "/admin/v1/me", null).andExpect(jsonPath("$.id").value("admin-sub"));
    }

    @Test
    void aMachinesTokenIsNotAnAdministrators() throws Exception {
        // Its own token of the service and one of a machine, with the right audience.
        for (var token : List.of(tokenService.issueAccessToken("mock-client", "mock-secret"),
                SERVER.token("altia-dev"))) {
            mockMvc.perform(on(PORT, HttpMethod.GET, "/admin/v1/users").header("Authorization", "Bearer " + token))
                    .andExpect(status().is4xxClientError());
        }
    }

    // -- users -----------------------------------------------------------------

    @Test
    void aUserIsCreatedWithEverythingItNeedsAndTheSecretsAreShownOnce() throws Exception {
        var created = create("acme-dev");
        assertEquals(clients.secrets.get("acme-dev"), created.get("clientSecret").asString());
        assertEquals("acme-dev-001", created.get("credentialId").asString());
        var password = created.get("credentialPassword").asString();
        assertTrue(password.length() >= 43);

        for (var path : List.of("/admin/v1/users", "/admin/v1/users/acme-dev", "/admin/v1/credentials")) {
            call(HttpMethod.GET, path, null).andExpect(status().isOk())
                    .andExpect(content().string(not(containsString(password))))
                    .andExpect(content().string(not(containsString(clients.secrets.get("acme-dev")))));
        }
        call(HttpMethod.GET, "/admin/v1/users/acme-dev", null)
                .andExpect(jsonPath("$.customer").value("Altia")).andExpect(jsonPath("$.environment").value("dev"))
                .andExpect(jsonPath("$.credentials[0].status").value("pending"))
                .andExpect(jsonPath("$.credentials[0].key").value("service"))
                .andExpect(jsonPath("$.credentials[0].certificate").doesNotExist());
    }

    @Test
    void ifTheUserCannotBeCreatedItsClientIsUndone() throws Exception {
        // Its first credential's id is taken by another user's.
        create("taken-dev");
        JdbcClient.create(new DriverManagerDataSource(Postgres.url(SCHEMA), Postgres.SERVER.getUsername(),
                        Postgres.SERVER.getPassword()))
                .sql("insert into dss_credential (id, client_id, password_hash) values ('undone-dev-001', 'taken-dev', 'x')")
                .update();
        call(HttpMethod.POST, "/admin/v1/users", """
                {"clientId":"undone-dev","customer":"Altia","environment":"dev"}""").andExpect(status().isConflict());
        assertFalse(clients.secrets.containsKey("undone-dev"));
        assertTrue(users.user("undone-dev").isEmpty());
    }

    @Test
    void withoutTheAuthorizationServerNothingIsCreated() throws Exception {
        clients.down = true;
        call(HttpMethod.POST, "/admin/v1/users", """
                {"clientId":"down-dev","customer":"Altia","environment":"dev"}""").andExpect(status().isBadGateway());
        assertTrue(users.user("down-dev").isEmpty());
    }

    @Test
    void wrongUsersAreRefused() throws Exception {
        create("dup-dev");
        for (var body : List.of("{\"clientId\":\"dup-dev\",\"customer\":\"A\",\"environment\":\"dev\"}",
                "{\"clientId\":\"mock-client\",\"customer\":\"A\",\"environment\":\"dev\"}",
                "{\"clientId\":\"Bad Id\",\"customer\":\"A\",\"environment\":\"dev\"}",
                "{\"clientId\":\"ok-dev\",\"customer\":\" \",\"environment\":\"dev\"}",
                "{\"clientId\":\"ok-dev\",\"customer\":\"A\",\"environment\":\"moon\"}",
                "{\"clientId\":\"ok-dev\",\"customer\":\"A\"}", "{}")) {
            call(HttpMethod.POST, "/admin/v1/users", body).andExpect(status().isBadRequest());
        }
        assertFalse(clients.secrets.containsKey("ok-dev"));
    }

    @Test
    void deactivatingStopsItHereEvenIfTheAuthorizationServerIsDown() throws Exception {
        create("stop-dev");
        clients.down = true;
        call(HttpMethod.PATCH, "/admin/v1/users/stop-dev", "{\"active\":false}").andExpect(status().isBadGateway());
        assertFalse(users.user("stop-dev").orElseThrow().active());

        clients.down = false;
        call(HttpMethod.PATCH, "/admin/v1/users/stop-dev", "{\"active\":false}").andExpect(status().isOk());
        assertEquals(false, clients.enabled.get("stop-dev"));
        call(HttpMethod.PATCH, "/admin/v1/users/stop-dev", "{\"active\":true}")
                .andExpect(jsonPath("$.active").value(true));
        assertEquals(true, clients.enabled.get("stop-dev"));
        call(HttpMethod.PATCH, "/admin/v1/users/stop-dev", "{}").andExpect(status().isBadRequest());
    }

    @Test
    void theSecretIsRotated() throws Exception {
        var old = create("rot-dev").get("clientSecret").asString();
        var secret = json(call(HttpMethod.POST, "/admin/v1/users/rot-dev/secret", null).andExpect(status().isOk()))
                .get("clientSecret").asString();
        assertFalse(old.equals(secret));
        call(HttpMethod.POST, "/admin/v1/users/nobody/secret", null).andExpect(status().isNotFound());
    }

    @Test
    void aUserOfTheConfigurationIsSeenAndAdopted() throws Exception {
        call(HttpMethod.GET, "/admin/v1/users/mock-client", null)
                .andExpect(jsonPath("$.managed").value(false))
                .andExpect(jsonPath("$.credentials[0].id").value("mock-credential-001"))
                .andExpect(jsonPath("$.credentials[0].key").value("file"))
                .andExpect(jsonPath("$.credentials[0].certificate.sha256").exists());
        call(HttpMethod.POST, "/admin/v1/users/mock-client/credentials", null).andExpect(status().isBadRequest());

        call(HttpMethod.PUT, "/admin/v1/users/mock-client", "{\"customer\":\"Local\",\"environment\":\"local\"}")
                .andExpect(status().isOk()).andExpect(jsonPath("$.managed").value(true))
                .andExpect(jsonPath("$.credentials[0].id").value("mock-credential-001"));
        call(HttpMethod.POST, "/admin/v1/users/mock-client/credentials", null).andExpect(status().isCreated())
                .andExpect(jsonPath("$.credentialId").value("mock-client-001"));
        call(HttpMethod.PUT, "/admin/v1/users/nobody", "{\"customer\":\"A\",\"environment\":\"dev\"}")
                .andExpect(status().isNotFound());
    }

    // -- credentials -----------------------------------------------------------

    @Test
    void fromAPendingCredentialToAnActiveOneAndRenewed() throws Exception {
        var password = create("cert-dev").get("credentialPassword").asString();
        assertFalse(users.passwordMatches("cert-dev-001", password));
        install("cert-dev-001");
        assertTrue(users.passwordMatches("cert-dev-001", password));
        install("cert-dev-001");
        call(HttpMethod.GET, "/admin/v1/users/cert-dev", null)
                .andExpect(jsonPath("$.credentials[0].certificate.issuer").value("CN=Accepted CA"));
    }

    @Test
    void aCertificateOfAnotherKeyIsRefused() throws Exception {
        create("other-dev");
        mockMvc.perform(on(PORT, HttpMethod.PUT, "/admin/v1/credentials/other-dev-001/certificate")
                        .header("Authorization", "Bearer " + admin("dss-admins")).contentType("text/plain")
                        .content(TestCa.pem(CA.issue(TestCa.newPair("secp256r1").getPublic()))))
                .andExpect(status().isBadRequest());
        call(HttpMethod.GET, "/admin/v1/credentials/nope/csr", null).andExpect(status().isNotFound());
    }

    @Test
    void theCsrHasTheSubjectAsked() throws Exception {
        create("csr-dev");
        var pem = call(HttpMethod.GET, "/admin/v1/credentials/csr-dev-001/csr?subject=C=ES,O=Altia,CN=csr", null)
                .andReturn().getResponse().getContentAsString();
        try (var parser = new PEMParser(new StringReader(pem))) {
            assertTrue(((PKCS10CertificationRequest) parser.readObject()).getSubject().toString().contains("O=Altia"));
        }
    }

    @Test
    void thePasswordIsRotatedWithOverlap() throws Exception {
        var old = create("pw-dev").get("credentialPassword").asString();
        install("pw-dev-001");
        var path = "/admin/v1/credentials/pw-dev-001/password";
        var renewed = json(call(HttpMethod.POST, path, "{\"overlapHours\":24}").andExpect(status().isOk()))
                .get("credentialPassword").asString();
        assertTrue(users.passwordMatches("pw-dev-001", old));
        assertTrue(users.passwordMatches("pw-dev-001", renewed));
        call(HttpMethod.POST, path, null).andExpect(status().isOk());
        assertFalse(users.passwordMatches("pw-dev-001", old));
        assertFalse(users.passwordMatches("pw-dev-001", renewed));
        call(HttpMethod.POST, path, "{\"overlapHours\":-1}").andExpect(status().isBadRequest());
        call(HttpMethod.POST, path, "{\"overlapHours\":1000}").andExpect(status().isBadRequest());
    }

    @Test
    void aRevokedCredentialIsFinal() throws Exception {
        create("rev-dev");
        install("rev-dev-001");
        call(HttpMethod.DELETE, "/admin/v1/credentials/rev-dev-001", null)
                .andExpect(jsonPath("$.status").value("revoked"));
        call(HttpMethod.GET, "/admin/v1/credentials/rev-dev-001/csr", null).andExpect(status().isBadRequest());
        call(HttpMethod.POST, "/admin/v1/credentials/rev-dev-001/password", null).andExpect(status().isBadRequest());
        call(HttpMethod.POST, "/admin/v1/users/rev-dev/credentials", null)
                .andExpect(jsonPath("$.credentialId").value("rev-dev-002"));
        // One of the configuration is not changed here.
        call(HttpMethod.DELETE, "/admin/v1/credentials/mock-credential-001", null).andExpect(status().isNotFound());
    }
}
