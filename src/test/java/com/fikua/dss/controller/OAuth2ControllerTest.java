package com.fikua.dss.controller;

import com.fikua.dss.IntegrationTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class OAuth2ControllerTest extends IntegrationTestBase {

    @Autowired MockMvc mockMvc;

    private static String basic(String id, String secret) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((id + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void tokenIssuedForClientCredentials() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("mock-client", "mock-secret"))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(header().exists("X-Request-Id"));
    }

    @Test
    void rejectsUnsupportedGrantType() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("mock-client", "mock-secret"))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    @Test
    void rejectsMissingBasicHeader() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void rejectsWrongCredentials() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("bad", "credentials"))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void respectsIncomingRequestIdHeader() throws Exception {
        var caller = "my-correlation-id-123";
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("mock-client", "mock-secret"))
                        .header("X-Request-Id", caller)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Request-Id", caller));
    }
}
