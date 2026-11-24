package com.fikua.dss.controller;

import com.fikua.dss.support.FakeAuthorizationServer;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.ResultActions;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The isolation of users holds with the authorization server's tokens too. */
class AuthorizationServerTokenTest extends UserIsolationTest {

    static final FakeAuthorizationServer SERVER = new FakeAuthorizationServer();

    @DynamicPropertySource
    static void oauth(DynamicPropertyRegistry registry) {
        registry.add("dss.oauth.issuer", () -> FakeAuthorizationServer.ISSUER);
        registry.add("dss.oauth.jwks-uri", SERVER::jwksUri);
        registry.add("dss.oauth.audience", () -> FakeAuthorizationServer.AUDIENCE);
    }

    @Override
    String bearerFor(String clientId, String secret) {
        return "Bearer " + SERVER.token(clientId);
    }

    private ResultActions list(String bearer) throws Exception {
        return mockMvc.perform(post("/csc/v2/credentials/list")
                .header("Authorization", bearer)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}"));
    }

    @Test
    void aClientThatIsNotAUserIsRefused() throws Exception {
        list("Bearer " + SERVER.token("nobody")).andExpect(status().isUnauthorized());
    }

    @Test
    void theServicesOwnTokensStillWork() throws Exception {
        list("Bearer " + tokenService.issueAccessToken("user-a", "secret-a"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialIDs.length()").value(2));
    }
}
