package com.fikua.dss.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.dss.IntegrationTestBase;
import com.fikua.dss.dto.v2.CredentialsAuthorizeRequest;
import com.fikua.dss.dto.v2.CredentialsAuthorizeRequest.AuthData;
import com.fikua.dss.dto.v2.CredentialsInfoRequest;
import com.fikua.dss.dto.v2.CredentialsListRequest;
import com.fikua.dss.dto.v2.SignDocRequest;
import com.fikua.dss.dto.v2.SignDocRequest.Document;
import com.fikua.dss.dto.v2.SignHashRequest;
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

/**
 * CSC v2 (2.1.0.1) conformance: POST info, `authData` array authorize,
 * `hashes`+`hashAlgorithmOID` signHash, and signDoc (v2-only). See
 * {@link CscV1ControllerTest} for the v1 surface.
 */
@AutoConfigureMockMvc
class CscV2ControllerTest extends IntegrationTestBase {

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

    // -- /csc/v2/info ---------------------------------------------------------

    @Test
    void infoIsPostAndIncludesV2RequiredFields() throws Exception {
        mockMvc.perform(post("/csc/v2/info")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.specs").value("2.0.0.0"))
                .andExpect(jsonPath("$.signature_formats").exists())
                .andExpect(jsonPath("$.conformance_levels").isArray())
                .andExpect(jsonPath("$.methods", org.hamcrest.Matchers.hasItem("signatures/signDoc")));
    }

    // -- /csc/v2/credentials/list ----------------------------------------------

    @Test
    void credentialsListRequiresBearer() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/list")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("user", true, null, true, true, true, null, null))))
                .andExpect(status().isBadRequest()); // missing required Authorization header
    }

    @Test
    void credentialsListReturnsConfiguredCredentialId() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/list")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("user", true, null, true, true, true, null, null))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialIDs[0]").value("mock-credential-001"));
    }

    @Test
    void credentialsListRejectsBogusBearer() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/list")
                        .header("Authorization", "Bearer nope")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("u", true, null, true, true, true, null, null))))
                .andExpect(status().isUnauthorized());
    }

    // -- /csc/v2/credentials/info ----------------------------------------------

    @Test
    void credentialsInfoUsesAuthObjectNotAuthMode() throws Exception {
        var req = new CredentialsInfoRequest("mock-credential-001", "chain", true, true, null, null);
        mockMvc.perform(post("/csc/v2/credentials/info")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cert.status").value("valid"))
                .andExpect(jsonPath("$.cert.certificates").isArray())
                .andExpect(jsonPath("$.auth.mode").value("explicit"))
                .andExpect(jsonPath("$.auth.objects").isArray());
    }

    @Test
    void credentialsInfoRejectsUnknownCredential() throws Exception {
        var req = new CredentialsInfoRequest("wrong-cred", "chain", true, true, null, null);
        mockMvc.perform(post("/csc/v2/credentials/info")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    // -- /csc/v2/credentials/authorize ------------------------------------------

    @Test
    void authorizeUsesAuthDataArrayNotPin() throws Exception {
        var hash = sha256Base64Url("hello".getBytes());
        var req = new CredentialsAuthorizeRequest(
                "mock-credential-001", 1, List.of(hash), "2.16.840.1.101.3.4.2.1",
                List.of(new AuthData("password", "mock-password")), null, null);
        mockMvc.perform(post("/csc/v2/credentials/authorize")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.SAD").exists());
    }

    @Test
    void authorizeFailsWithoutPasswordAuthData() throws Exception {
        var req = new CredentialsAuthorizeRequest(
                "mock-credential-001", 1, List.of("aGVsbG8"), "2.16.840.1.101.3.4.2.1",
                List.of(), null, null);
        mockMvc.perform(post("/csc/v2/credentials/authorize")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void authorizeFailsWithWrongPassword() throws Exception {
        var req = new CredentialsAuthorizeRequest(
                "mock-credential-001", 1, List.of("aGVsbG8"), "2.16.840.1.101.3.4.2.1",
                List.of(new AuthData("password", "WRONG")), null, null);
        mockMvc.perform(post("/csc/v2/credentials/authorize")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    // -- /csc/v2/signatures/signHash --------------------------------------------

    @Test
    void signHashUsesHashesField() throws Exception {
        var hash = sha256Base64Url("hello".getBytes());
        var sad = issueSad();
        var req = new SignHashRequest("mock-credential-001", sad, List.of(hash),
                "2.16.840.1.101.3.4.2.1", null, null, null, null, null, null);
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
                List.of("aGVsbG8"), "2.16.840.1.101.3.4.2.1", null, null, null, null, null, null);
        mockMvc.perform(post("/csc/v2/signatures/signHash")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    // -- /csc/v2/signatures/signDoc ----------------------------------------------

    @Test
    void signDocAcceptsDocumentsModeAndReturnsSignatureObjectField() throws Exception {
        var docB64 = Base64.getEncoder().encodeToString("a tiny document".getBytes());
        var sad = issueSad();
        var req = new SignDocRequest("mock-credential-001", "eu_eidas_qes", sad,
                null,
                List.of(new Document(docB64, "P", "Ades-B-B", null, null)),
                "2.16.840.1.101.3.4.2.1", null, null, null, null, null);
        mockMvc.perform(post("/csc/v2/signatures/signDoc")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.DocumentWithSignature").isArray())
                .andExpect(jsonPath("$.SignatureObject").isArray());
    }

    @Test
    void signDocRejectsInvalidSad() throws Exception {
        var docB64 = Base64.getEncoder().encodeToString("data".getBytes());
        var req = new SignDocRequest("mock-credential-001", "eu_eidas_qes", "bad-sad",
                null,
                List.of(new Document(docB64, "P", "Ades-B-B", null, null)),
                "2.16.840.1.101.3.4.2.1", null, null, null, null, null);
        mockMvc.perform(post("/csc/v2/signatures/signDoc")
                        .header("Authorization", bearer())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }
}
