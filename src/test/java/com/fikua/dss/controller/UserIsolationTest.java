package com.fikua.dss.controller;

import tools.jackson.databind.ObjectMapper;
import com.fikua.dss.dto.v2.CredentialsAuthorizeRequest;
import com.fikua.dss.dto.v2.CredentialsAuthorizeRequest.AuthData;
import com.fikua.dss.dto.v2.CredentialsListRequest;
import com.fikua.dss.dto.v2.SignHashRequest;
import com.fikua.dss.service.TokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * One user's access token can never read or sign with another user's
 * credential, even when it names the other credential directly; a user with
 * two credentials sees both and each signs with its own key.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dss.users[0].client-id=user-a",
        "dss.users[0].client-secret=secret-a",
        "dss.users[0].credentials[0].id=cred-a",
        "dss.users[0].credentials[0].password=pw-a",
        "dss.users[0].credentials[0].certificate.cert-path=file:build/test-certs/mock-eseal.crt",
        "dss.users[0].credentials[0].certificate.key-path=file:build/test-certs/mock-eseal.key",
        "dss.users[0].credentials[1].id=cred-a2",
        "dss.users[0].credentials[1].password=pw-a2",
        "dss.users[0].credentials[1].certificate.cert-path=file:build/test-certs/other-eseal.crt",
        "dss.users[0].credentials[1].certificate.key-path=file:build/test-certs/other-eseal.key",
        "dss.users[1].client-id=user-b",
        "dss.users[1].client-secret=secret-b",
        "dss.users[1].credentials[0].id=cred-b",
        "dss.users[1].credentials[0].password=pw-b",
        "dss.users[1].credentials[0].certificate.cert-path=file:build/test-certs/other-eseal.crt",
        "dss.users[1].credentials[0].certificate.key-path=file:build/test-certs/other-eseal.key",
        "dss.token-ttl-seconds=3600",
        "dss.sad-ttl-seconds=300",
        "dss.trusted-lists.enabled=false"
})
class UserIsolationTest {

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper mapper;
    @Autowired TokenService tokenService;

    String bearerFor(String clientId, String secret) {
        return "Bearer " + tokenService.issueAccessToken(clientId, secret);
    }

    private static String sha256Base64Url(byte[] data) throws Exception {
        var md = MessageDigest.getInstance("SHA-256");
        var hash = md.digest(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    @Test
    void credentialsListReturnsAllAndOnlyTheUsersCredentials() throws Exception {
        mockMvc.perform(post("/csc/v2/credentials/list")
                        .header("Authorization", bearerFor("user-a", "secret-a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("u", true, null, true, true, true, null, null))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialIDs.length()").value(2))
                .andExpect(jsonPath("$.credentialIDs[0]").value("cred-a"))
                .andExpect(jsonPath("$.credentialIDs[1]").value("cred-a2"));

        mockMvc.perform(post("/csc/v2/credentials/list")
                        .header("Authorization", bearerFor("user-b", "secret-b"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(
                                new CredentialsListRequest("u", true, null, true, true, true, null, null))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credentialIDs.length()").value(1))
                .andExpect(jsonPath("$.credentialIDs[0]").value("cred-b"));
    }

    @Test
    void authorizeRejectsAnotherUsersCredential() throws Exception {
        var req = new CredentialsAuthorizeRequest(
                "cred-b", 1, List.of(sha256Base64Url("hello".getBytes())), "2.16.840.1.101.3.4.2.1",
                List.of(new AuthData("password", "pw-b")), null, null);
        // user-a's token authorizing against user-b's credential must fail.
        mockMvc.perform(post("/csc/v2/credentials/authorize")
                        .header("Authorization", bearerFor("user-a", "secret-a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signHashRejectsASadIssuedToAnotherUser() throws Exception {
        var sad = tokenService.issueSad("user-b", "cred-b", "pw-b", 1, List.of());
        var req = new SignHashRequest("cred-b", sad, List.of(sha256Base64Url("hello".getBytes())),
                "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2", null, null, null, null, null);

        // A SAD issued to user-b must not be usable with a user-a bearer token.
        mockMvc.perform(post("/csc/v2/signatures/signHash")
                        .header("Authorization", bearerFor("user-a", "secret-a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void signHashSucceedsWhenTokenAndSadBelongToTheSameUser() throws Exception {
        var sad = tokenService.issueSad("user-b", "cred-b", "pw-b", 1, List.of());
        var req = new SignHashRequest("cred-b", sad, List.of(sha256Base64Url("hello".getBytes())),
                "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2", null, null, null, null, null);

        mockMvc.perform(post("/csc/v2/signatures/signHash")
                        .header("Authorization", bearerFor("user-b", "secret-b"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signatures[0]").exists());
    }

    @Test
    void eachCredentialSignsWithItsOwnKey() throws Exception {
        var data = "hello".getBytes();
        var sad = tokenService.issueSad("user-a", "cred-a2", "pw-a2", 1, List.of());
        var req = new SignHashRequest("cred-a2", sad, List.of(sha256Base64Url(data)),
                "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2", null, null, null, null, null);

        var body = mockMvc.perform(post("/csc/v2/signatures/signHash")
                        .header("Authorization", bearerFor("user-a", "secret-a"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        var signature = Base64.getDecoder().decode(mapper.readTree(body).get("signatures").get(0).asString());

        assertTrue(verifies("build/test-certs/other-eseal.crt", data, signature), "signed with cred-a2's key");
        assertFalse(verifies("build/test-certs/mock-eseal.crt", data, signature), "not with cred-a's key");
    }

    private static boolean verifies(String certPath, byte[] data, byte[] signature) throws Exception {
        try (var in = java.nio.file.Files.newInputStream(java.nio.file.Path.of(certPath))) {
            var cert = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(in);
            var sig = java.security.Signature.getInstance("SHA256withECDSA");
            sig.initVerify(cert);
            sig.update(data);
            return sig.verify(signature);
        }
    }
}
