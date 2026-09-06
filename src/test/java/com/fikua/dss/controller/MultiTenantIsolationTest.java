package com.fikua.dss.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fikua.dss.dto.v2.CredentialsAuthorizeRequest;
import com.fikua.dss.dto.v2.CredentialsAuthorizeRequest.AuthData;
import com.fikua.dss.dto.v2.CredentialsListRequest;
import com.fikua.dss.dto.v2.SignHashRequest;
import com.fikua.dss.service.TokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifies that one tenant's access token can never be used to read or sign
 * with another tenant's certificate, even when it references the other
 * tenant's credentialID directly.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dss.tenants[0].client-id=tenant-a",
        "dss.tenants[0].client-secret=secret-a",
        "dss.tenants[0].credential-id=cred-a",
        "dss.tenants[0].credential-password=pw-a",
        "dss.tenants[0].certificate.cert-path=file:build/test-certs/mock-eseal.crt",
        "dss.tenants[0].certificate.key-path=file:build/test-certs/mock-eseal.key",
        "dss.tenants[1].client-id=tenant-b",
        "dss.tenants[1].client-secret=secret-b",
        "dss.tenants[1].credential-id=cred-b",
        "dss.tenants[1].credential-password=pw-b",
        "dss.tenants[1].certificate.cert-path=file:build/test-certs/tenant-b-eseal.crt",
        "dss.tenants[1].certificate.key-path=file:build/test-certs/tenant-b-eseal.key",
        "dss.token-ttl-seconds=3600",
        "dss.sad-ttl-seconds=300"
})
class MultiTenantIsolationTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper mapper;
    @Autowired TokenService tokenService;

    private String bearerFor(String clientId, String secret) {
        return "Bearer " + tokenService.issueAccessToken(clientId, secret);
    }

    private static String sha256Base64Url(byte[] data) throws Exception {
        var md = MessageDigest.getInstance("SHA-256");
        var hash = md.digest(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    @Test
    void credentialsListOnlyReturnsOwnTenantCredential() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/list")
                        .header("Authorization", bearerFor("tenant-a", "secret-a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("u", true, null, true, true, true, null, null))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialIDs[0]").value("cred-a"));

        mockMvc.perform(post("/csc/v2/credentials/list")
                        .header("Authorization", bearerFor("tenant-b", "secret-b"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("u", true, null, true, true, true, null, null))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialIDs[0]").value("cred-b"));
    }

    @Test
    void authorizeRejectsOtherTenantsCredentialId() throws Exception {
        var req = new CredentialsAuthorizeRequest(
                "cred-b", 1, List.of(sha256Base64Url("hello".getBytes())), "2.16.840.1.101.3.4.2.1",
                List.of(new AuthData("password", "pw-b")), null, null);
        // tenant-a's token authorizing against tenant-b's credential must fail.
        mockMvc.perform(post("/csc/v2/credentials/authorize")
                        .header("Authorization", bearerFor("tenant-a", "secret-a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signHashRejectsSadIssuedToADifferentTenant() throws Exception {
        var sad = tokenService.issueSad("tenant-b", "cred-b", "pw-b");
        var req = new SignHashRequest("cred-b", sad, List.of(sha256Base64Url("hello".getBytes())),
                "2.16.840.1.101.3.4.2.1", null, null, null, null, null, null);

        // A SAD minted for tenant-b must not be usable with a tenant-a bearer token.
        mockMvc.perform(post("/csc/v2/signatures/signHash")
                        .header("Authorization", bearerFor("tenant-a", "secret-a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signHashSucceedsWhenTokenAndSadBelongToSameTenant() throws Exception {
        var sad = tokenService.issueSad("tenant-b", "cred-b", "pw-b");
        var req = new SignHashRequest("cred-b", sad, List.of(sha256Base64Url("hello".getBytes())),
                "2.16.840.1.101.3.4.2.1", null, null, null, null, null, null);

        mockMvc.perform(post("/csc/v2/signatures/signHash")
                        .header("Authorization", bearerFor("tenant-b", "secret-b"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signatures[0]").exists());
    }
}
