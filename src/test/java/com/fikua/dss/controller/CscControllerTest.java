package com.fikua.dss.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.dss.IntegrationTestBase;
import com.fikua.dss.dto.CredentialsAuthorizeRequest;
import com.fikua.dss.dto.CredentialsAuthorizeRequest.AuthData;
import com.fikua.dss.dto.CredentialsInfoRequest;
import com.fikua.dss.dto.CredentialsListRequest;
import com.fikua.dss.dto.SignDocRequest;
import com.fikua.dss.dto.SignDocRequest.Document;
import com.fikua.dss.dto.SignHashRequest;
import com.fikua.dss.service.TokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
class CscControllerTest extends IntegrationTestBase {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper mapper;
    @Autowired TokenService tokenService;

    private String bearer() {
        return "Bearer " + tokenService.issueAccessToken("mock-client", "mock-secret");
    }

    private String issueSad() {
        return tokenService.issueSad("mock-credential-001", "mock-password");
    }

    private static String sha256Base64Url(byte[] data) throws Exception {
        var md = MessageDigest.getInstance("SHA-256");
        var hash = md.digest(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    // -- /csc/v2/info -------------------------------------------------------

    @Test
    void infoReturnsServiceMetadata() throws Exception {
        mockMvc.perform(post("/csc/v2/info")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.specs").value("2.0.0.0"));
    }

    // -- /csc/v2/credentials/list ------------------------------------------

    @Test
    void credentialsListRequiresBearer() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/list")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("user", true, null, true, true, true))))
                .andExpect(status().isBadRequest()); // missing required Authorization header
    }

    @Test
    void credentialsListReturnsConfiguredCredentialId() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/list")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("user", true, null, true, true, true))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialIDs[0]").value("mock-credential-001"));
    }

    @Test
    void credentialsListRejectsBogusBearer() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/list")
                        .header("Authorization", "Bearer nope")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("u", true, null, true, true, true))))
                .andExpect(status().isUnauthorized());
    }

    // -- /csc/v2/credentials/info ------------------------------------------

    @Test
    void credentialsInfoReturnsCertChain() throws Exception {
        var req = new CredentialsInfoRequest("mock-credential-001", "chain", "true", "true");
        mockMvc.perform(post("/csc/v2/credentials/info")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cert.status").value("valid"))
                .andExpect(jsonPath("$.cert.certificates").isArray());
    }

    @Test
    void credentialsInfoRejectsUnknownCredential() throws Exception {
        var req = new CredentialsInfoRequest("wrong-cred", "chain", "true", "true");
        mockMvc.perform(post("/csc/v2/credentials/info")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    // -- /csc/v2/credentials/authorize -------------------------------------

    @Test
    void credentialsAuthorizeIssuesSad() throws Exception {
        var hash = sha256Base64Url("hello".getBytes());
        var req = new CredentialsAuthorizeRequest(
                "mock-credential-001", 1, List.of(hash), "2.16.840.1.101.3.4.2.1",
                List.of(new AuthData("password", "mock-password")));
        mockMvc.perform(post("/csc/v2/credentials/authorize")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.SAD").exists());
    }

    @Test
    void credentialsAuthorizeFailsWithoutPasswordAuthData() throws Exception {
        var req = new CredentialsAuthorizeRequest(
                "mock-credential-001", 1, List.of("aGVsbG8"), "2.16.840.1.101.3.4.2.1",
                List.of());
        mockMvc.perform(post("/csc/v2/credentials/authorize")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void credentialsAuthorizeFailsWithWrongPassword() throws Exception {
        var req = new CredentialsAuthorizeRequest(
                "mock-credential-001", 1, List.of("aGVsbG8"), "2.16.840.1.101.3.4.2.1",
                List.of(new AuthData("password", "WRONG")));
        mockMvc.perform(post("/csc/v2/credentials/authorize")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    // -- /csc/v2/signatures/signHash ---------------------------------------

    @Test
    void signHashReturnsSignatures() throws Exception {
        var hash = sha256Base64Url("hello".getBytes());
        var sad = issueSad();
        var req = new SignHashRequest("mock-credential-001", sad, List.of(hash),
                "2.16.840.1.101.3.4.2.1", null);
        mockMvc.perform(post("/csc/v2/signatures/signHash")
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
                List.of("aGVsbG8"), "2.16.840.1.101.3.4.2.1", null);
        mockMvc.perform(post("/csc/v2/signatures/signHash")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    // -- /csc/v2/signatures/signDoc ----------------------------------------

    @Test
    void signDocReturnsSignatures() throws Exception {
        var docB64 = Base64.getEncoder().encodeToString("a tiny document".getBytes());
        var sad = issueSad();
        var req = new SignDocRequest("mock-credential-001", sad, "eu_eidas_qes",
                List.of(new Document(docB64, "P", "B-B", null)));
        mockMvc.perform(post("/csc/v2/signatures/signDoc")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.DocumentWithSignature").isArray());
    }

    @Test
    void signDocRejectsInvalidSad() throws Exception {
        var docB64 = Base64.getEncoder().encodeToString("data".getBytes());
        var req = new SignDocRequest("mock-credential-001", "bad-sad", "eu_eidas_qes",
                List.of(new Document(docB64, "P", "B-B", null)));
        mockMvc.perform(post("/csc/v2/signatures/signDoc")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }
}
