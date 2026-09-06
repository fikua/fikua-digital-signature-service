package com.fikua.dss.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.dss.IntegrationTestBase;
import com.fikua.dss.dto.v1.CredentialsAuthorizeRequest;
import com.fikua.dss.dto.v1.CredentialsInfoRequest;
import com.fikua.dss.dto.v1.CredentialsListRequest;
import com.fikua.dss.dto.v1.SignHashRequest;
import com.fikua.dss.service.TokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * CSC v1 (1.0.3.0) conformance: GET info, PIN/OTP authorize, `hash`+`hashAlgo`
 * signHash, no signDoc. See {@link CscV2ControllerTest} for the v2 surface.
 */
@AutoConfigureMockMvc
class CscV1ControllerTest extends IntegrationTestBase {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper mapper;
    @Autowired TokenService tokenService;

    private String bearer() {
        return "Bearer " + tokenService.issueAccessToken("mock-client", "mock-secret");
    }

    private String issueSad() {
        return tokenService.issueSad("mock-client", "mock-credential-001", "mock-password");
    }

    private static String sha256Base64Url(byte[] data) throws Exception {
        var md = MessageDigest.getInstance("SHA-256");
        var hash = md.digest(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    // -- /csc/v1/info --------------------------------------------------------

    @Test
    void infoIsGetAndExposesV1Specs() throws Exception {
        mockMvc.perform(get("/csc/v1/info").param("lang", "en-US"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.specs").value("1.0.3.0"))
                .andExpect(jsonPath("$.methods").isArray());
    }

    // -- /csc/v1/credentials/list ---------------------------------------------

    @Test
    void credentialsListReturnsConfiguredCredentialId() throws Exception {
        mockMvc.perform(post("/csc/v1/credentials/list")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("user", null, null, null))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialIDs[0]").value("mock-credential-001"));
    }

    @Test
    void credentialsListRejectsBogusBearer() throws Exception {
        mockMvc.perform(post("/csc/v1/credentials/list")
                        .header("Authorization", "Bearer nope")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("user", null, null, null))))
                .andExpect(status().isUnauthorized());
    }

    // -- /csc/v1/credentials/info ---------------------------------------------

    @Test
    void credentialsInfoReturnsV1FieldsAuthModePinOtpMultisignLang() throws Exception {
        var req = new CredentialsInfoRequest("mock-credential-001", "chain", true, true, null, null);
        mockMvc.perform(post("/csc/v1/credentials/info")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authMode").value("explicit"))
                .andExpect(jsonPath("$.PIN").exists())
                .andExpect(jsonPath("$.OTP").exists())
                .andExpect(jsonPath("$.multisign").value(1))
                .andExpect(jsonPath("$.lang").value("en-US"));
    }

    @Test
    void credentialsInfoRejectsUnknownCredential() throws Exception {
        var req = new CredentialsInfoRequest("wrong-cred", "chain", true, true, null, null);
        mockMvc.perform(post("/csc/v1/credentials/info")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    // -- /csc/v1/credentials/authorize -----------------------------------------

    @Test
    void authorizeUsesPinNotAuthData() throws Exception {
        var hash = sha256Base64Url("hello".getBytes());
        var req = new CredentialsAuthorizeRequest(
                "mock-credential-001", 1, List.of(hash), "mock-password", null, null, null);
        mockMvc.perform(post("/csc/v1/credentials/authorize")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.SAD").exists());
    }

    @Test
    void authorizeRejectsMissingPin() throws Exception {
        var req = new CredentialsAuthorizeRequest(
                "mock-credential-001", 1, List.of("aGVsbG8"), null, null, null, null);
        mockMvc.perform(post("/csc/v1/credentials/authorize")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void authorizeRejectsWrongPin() throws Exception {
        var req = new CredentialsAuthorizeRequest(
                "mock-credential-001", 1, List.of("aGVsbG8"), "WRONG", null, null, null);
        mockMvc.perform(post("/csc/v1/credentials/authorize")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    // -- /csc/v1/signatures/signHash -------------------------------------------

    @Test
    void signHashAcceptsV1Body() throws Exception {
        var hash = sha256Base64Url("hello".getBytes());
        var sad = issueSad();
        var req = new SignHashRequest("mock-credential-001", sad, List.of(hash),
                "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", null, null);
        mockMvc.perform(post("/csc/v1/signatures/signHash")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signatures").isArray())
                .andExpect(jsonPath("$.signatures[0]").exists());
    }

    @Test
    void signHashRejectsExpiredOrInvalidSad() throws Exception {
        var req = new SignHashRequest("mock-credential-001", "not-a-sad",
                List.of("aGVsbG8"), "2.16.840.1.101.3.4.2.1", null, null, null);
        mockMvc.perform(post("/csc/v1/signatures/signHash")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }
}
