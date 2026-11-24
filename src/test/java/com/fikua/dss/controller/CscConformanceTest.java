package com.fikua.dss.controller;

import com.fikua.dss.IntegrationTestBase;
import com.fikua.dss.service.TokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.ObjectMapper;

import java.security.MessageDigest;
import java.util.Base64;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** What CSC 1.0.3.0 and 2.1.0.1 ask for, and the request bodies EUDIStack's issuer sends. */
@AutoConfigureMockMvc
class CscConformanceTest extends IntegrationTestBase {

    private static final String ID = "mock-credential-001";
    private static final String ES256 = "1.2.840.10045.4.3.2";
    private static final String SHA256 = "2.16.840.1.101.3.4.2.1";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper mapper;
    @Autowired TokenService tokenService;

    private ResultActions call(String path, String json) throws Exception {
        return mockMvc.perform(post(path)
                .header("Authorization", "Bearer " + tokenService.issueAccessToken("mock-client", "mock-secret"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(json));
    }

    private static byte[] hash(String data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data.getBytes());
    }

    private static String b64(String data) throws Exception {
        return Base64.getEncoder().encodeToString(hash(data));
    }

    private static String b64url(String data) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash(data));
    }

    private String sad(String extra) throws Exception {
        var body = call("/csc/v2/credentials/authorize", """
                {"credentialID":"%s","numSignatures":1,%s"authData":[{"id":"password","value":"mock-password"}]}"""
                .formatted(ID, extra)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return mapper.readTree(body).get("SAD").asString();
    }

    private ResultActions signHash(String sad, String hashes, String signAlgo) throws Exception {
        return call("/csc/v2/signatures/signHash", """
                {"credentialID":"%s","SAD":"%s","hashes":[%s],"hashAlgorithmOID":"%s"%s}"""
                .formatted(ID, sad, hashes, SHA256, signAlgo == null ? "" : ",\"signAlgo\":\"" + signAlgo + "\""));
    }

    @Test
    void noAnswerHasNullFields() throws Exception {
        for (var path : new String[]{"/csc/v1/info", "/csc/v2/info", "/csc/v1/credentials/list", "/csc/v2/credentials/list"}) {
            call(path, "{}").andExpect(status().isOk()).andExpect(content().string(not(containsString(":null"))));
        }
        for (var path : new String[]{"/csc/v1/credentials/info", "/csc/v2/credentials/info"}) {
            call(path, "{\"credentialID\":\"" + ID + "\"}").andExpect(status().isOk())
                    .andExpect(content().string(not(containsString(":null"))));
        }
    }

    @Test
    void infoAnnouncesWhatTheServiceDoes() throws Exception {
        call("/csc/v2/info", "{}")
                .andExpect(jsonPath("$.authType", hasSize(1)))
                .andExpect(jsonPath("$.authType[0]").value("oauth2client"))
                .andExpect(jsonPath("$.signAlgorithms.algos[0]").value(ES256));
        call("/csc/v1/info", "{\"lang\":\"es-ES\"}")
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.lang").value("es-ES"))
                .andExpect(content().string(not(containsString("auth/login"))));
    }

    @Test
    void credentialsInfoReturnsWhatIsAsked() throws Exception {
        call("/csc/v2/credentials/info", "{\"credentialID\":\"" + ID + "\",\"certificates\":\"none\"}")
                .andExpect(jsonPath("$.cert.certificates").doesNotExist())
                .andExpect(jsonPath("$.cert.subjectDN").doesNotExist())
                .andExpect(jsonPath("$.auth").doesNotExist());
        call("/csc/v2/credentials/info", """
                {"credentialID":"%s","certificates":"chain","certInfo":true,"authInfo":true}""".formatted(ID))
                .andExpect(jsonPath("$.cert.certificates").isArray())
                .andExpect(jsonPath("$.cert.subjectDN").exists())
                .andExpect(jsonPath("$.auth.expression").value("AND"))
                .andExpect(jsonPath("$.auth.objects[0].id").value("password"));
        call("/csc/v2/credentials/info", "{\"credentialID\":\"" + ID + "\",\"certificates\":\"all\"}")
                .andExpect(status().isBadRequest());
    }

    @Test
    void credentialsListReturnsTheirInfoWhenAsked() throws Exception {
        call("/csc/v2/credentials/list", "{}").andExpect(jsonPath("$.credentialInfos").doesNotExist());
        call("/csc/v2/credentials/list", "{\"credentialInfo\":true,\"onlyValid\":true,\"certificates\":\"chain\"}")
                .andExpect(jsonPath("$.credentialInfos[0].credentialID").value(ID))
                .andExpect(jsonPath("$.onlyValid").value(true));
    }

    @Test
    void theSignatureIsBase64() throws Exception {
        var body = signHash(sad(""), "\"" + b64("x") + "\"", ES256).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        var signature = mapper.readTree(body).get("signatures").get(0).asString();
        assertDoesNotThrow(() -> Base64.getDecoder().decode(signature));
        assertFalse(signature.contains("-") || signature.contains("_"));
    }

    @Test
    void signAlgoIsRequiredAndOnlyEs256() throws Exception {
        signHash(sad(""), "\"" + b64("x") + "\"", null).andExpect(status().isBadRequest());
        signHash(sad(""), "\"" + b64("x") + "\"", "1.2.840.113549.1.1.11").andExpect(status().isBadRequest());
    }

    @Test
    void anAuthorizationOnlySignsItsHash() throws Exception {
        var sad = sad("\"hashes\":[\"" + b64("x") + "\"],");
        signHash(sad, "\"" + b64("other") + "\"", ES256).andExpect(status().isBadRequest());
        // The same hash in the other alphabet is the same hash.
        signHash(sad, "\"" + b64url("x") + "\"", ES256).andExpect(status().isOk());
        signHash(sad, "\"" + b64("x") + "\"", ES256).andExpect(status().isUnauthorized());
    }

    @Test
    void theV1NamesOfEudistacksIssuerAlsoBindTheHash() throws Exception {
        var sad = sad("\"hash\":[\"" + b64url("x") + "\"],\"hashAlgo\":\"" + SHA256 + "\",");
        signHash(sad, "\"" + b64url("other") + "\"", ES256).andExpect(status().isBadRequest());
        signHash(sad, "\"" + b64url("x") + "\"", ES256).andExpect(status().isOk());
    }

    @Test
    void oneAuthorizationIsOneSignature() throws Exception {
        signHash(sad(""), "\"" + b64("x") + "\",\"" + b64("y") + "\"", ES256).andExpect(status().isBadRequest());
        call("/csc/v2/credentials/authorize", """
                {"credentialID":"%s","numSignatures":2,"authData":[{"id":"password","value":"mock-password"}]}"""
                .formatted(ID)).andExpect(status().isBadRequest());
        call("/csc/v2/credentials/authorize", """
                {"credentialID":"%s","authData":[{"id":"password","value":"mock-password"}]}""".formatted(ID))
                .andExpect(status().isBadRequest());
    }
}
