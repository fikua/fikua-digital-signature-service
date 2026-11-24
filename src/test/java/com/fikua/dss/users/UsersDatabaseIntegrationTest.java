package com.fikua.dss.users;

import com.fikua.dss.IntegrationTestBase;
import com.fikua.dss.service.CredentialService;
import com.fikua.dss.service.TokenService;
import com.fikua.dss.users.ManagedUser.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** With a database, the users of the configuration still work and can be deactivated. */
@AutoConfigureMockMvc
class UsersDatabaseIntegrationTest extends IntegrationTestBase {

    @Autowired MockMvc mockMvc;
    @Autowired TokenService tokenService;
    @Autowired CredentialService credentials;
    @Autowired ManagedUsers managed;

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        // The public schema: as in production, the role's own schema.
        registry.add("dss.database.url", Postgres.SERVER::getJdbcUrl);
        registry.add("dss.database.username", Postgres.SERVER::getUsername);
        registry.add("dss.database.password", Postgres.SERVER::getPassword);
    }

    @AfterEach
    void activateAgain() {
        managed.setActive("mock-client", true);
    }

    private ResultActions list(String token) throws Exception {
        return mockMvc.perform(post("/csc/v2/credentials/list")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"));
    }

    @Test
    void aConfiguredUserWorksWithoutARow() throws Exception {
        list(tokenService.issueAccessToken("mock-client", "mock-secret"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialIDs[0]").value("mock-credential-001"));
    }

    @Test
    void deactivatingAConfiguredUserRefusesTheTokenItAlreadyHas() throws Exception {
        if (managed.user("mock-client").isEmpty()) {
            managed.create(new ManagedUser("mock-client", "Local", Environment.LOCAL, "", true));
        }
        var token = tokenService.issueAccessToken("mock-client", "mock-secret");
        list(token).andExpect(status().isOk());

        managed.setActive("mock-client", false);
        list(token).andExpect(status().isUnauthorized());

        managed.setActive("mock-client", true);
        list(token).andExpect(status().isOk());
    }

    @Test
    void aUserOfTheDatabaseOnlyHasNoCredentialsYet() {
        managed.create(new ManagedUser("only-in-database", "Altia", Environment.DEV, "", true));
        assertNotNull(credentials.user("only-in-database"));
        assertTrue(credentials.user("only-in-database").credentialIds().isEmpty());
        managed.setActive("only-in-database", false);
        assertNull(credentials.user("only-in-database"));
        assertNull(credentials.user("nobody"));
    }
}
