package com.fikua.dss.web;

import com.fikua.dss.IntegrationTestBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class GlobalExceptionHandlerTest extends IntegrationTestBase {

    @Autowired MockMvc mockMvc;

    @Test
    void malformedJsonReturns400() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/info")
                        .header("Authorization", "Bearer whatever")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ this is not json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void missingFormParameterReturns400() throws Exception {
        // /oauth2/token requires grant_type form param; omit it.
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isBadRequest());
    }

    @Test
    void missingAuthHeaderReturns400() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/list")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }
}
