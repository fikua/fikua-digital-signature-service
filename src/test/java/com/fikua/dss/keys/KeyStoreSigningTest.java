package com.fikua.dss.keys;

import com.fikua.dss.IntegrationTestBase;
import com.fikua.dss.service.TokenService;
import com.fikua.dss.support.TestCa;
import com.fikua.dss.users.ManagedCredentials;
import com.fikua.dss.users.ManagedUser;
import com.fikua.dss.users.ManagedUser.Environment;
import com.fikua.dss.users.ManagedUsers;
import com.fikua.dss.users.Postgres;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** From nothing to a signature over CSC, beside a credential of the configuration. */
@AutoConfigureMockMvc
class KeyStoreSigningTest extends IntegrationTestBase {

    private static final String SCHEMA = "key_store_signing_test";
    private static final TestCa CA = new TestCa("CN=Accepted CA");
    private static final String NEW = "mock-client-002";

    @Autowired MockMvc mockMvc;
    @Autowired ObjectMapper mapper;
    @Autowired TokenService tokenService;
    @Autowired ManagedUsers users;
    @Autowired ManagedCredentials credentials;
    @Autowired CredentialKeyStore keys;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) throws Exception {
        JdbcClient.create(new DriverManagerDataSource(Postgres.SERVER.getJdbcUrl(), Postgres.SERVER.getUsername(),
                Postgres.SERVER.getPassword())).sql("create schema " + SCHEMA).update();
        var file = Files.createTempFile("accepted-ca", ".pem");
        Files.writeString(file, TestCa.pem(CA.certificate));
        registry.add("dss.database.url", () -> Postgres.url(SCHEMA));
        registry.add("dss.database.username", Postgres.SERVER::getUsername);
        registry.add("dss.database.password", Postgres.SERVER::getPassword);
        registry.add("dss.keys.master-key", () -> MasterKeysTest.key(7));
        registry.add("dss.keys.accepted-cas[0]", () -> "file:" + file);
    }

    private ResultActions call(String path, String json) throws Exception {
        return mockMvc.perform(post(path)
                .header("Authorization", "Bearer " + tokenService.issueAccessToken("mock-client", "mock-secret"))
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private ResultActions authorize(String id, String password) throws Exception {
        return call("/csc/v2/credentials/authorize", """
                {"credentialID":"%s","numSignatures":1,"authData":[{"id":"password","value":"%s"}]}"""
                .formatted(id, password));
    }

    @Test
    void aNewCredentialSignsWhenItHasItsCertificate() throws Exception {
        users.create(new ManagedUser("mock-client", "Local", Environment.LOCAL, "", true));
        credentials.create(NEW, "mock-client", "new-password");

        // Pending: not listed, not authorized.
        call("/csc/v2/credentials/list", "{}").andExpect(jsonPath("$.credentialIDs.length()").value(1));
        authorize(NEW, "new-password").andExpect(status().isUnauthorized());

        credentials.install(NEW, TestCa.pem(CA.issue(keys.publicKey(NEW))));

        call("/csc/v2/credentials/list", "{}")
                .andExpect(jsonPath("$.credentialIDs[0]").value("mock-credential-001"))
                .andExpect(jsonPath("$.credentialIDs[1]").value(NEW));
        authorize(NEW, "mock-password").andExpect(status().isUnauthorized());
        var sad = mapper.readTree(authorize(NEW, "new-password").andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).get("SAD").asString();

        var data = "to sign".getBytes();
        var hash = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(data));
        var body = call("/csc/v2/signatures/signHash", """
                {"credentialID":"%s","SAD":"%s","hashes":["%s"],"signAlgo":"1.2.840.10045.4.3.2"}"""
                .formatted(NEW, sad, hash)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(keys.publicKey(NEW));
        verifier.update(data);
        assertTrue(verifier.verify(Base64.getDecoder().decode(mapper.readTree(body).get("signatures").get(0).asString())));

        // signDoc: a whole JAdES with that key.
        var second = mapper.readTree(authorize(NEW, "new-password").andReturn().getResponse().getContentAsString())
                .get("SAD").asString();
        call("/csc/v2/signatures/signDoc", """
                {"credentialID":"%s","SAD":"%s","documents":[{"document":"%s","signature_format":"J",
                 "conformance_level":"Ades-B","signAlgo":"1.2.840.10045.4.3.2"}]}"""
                .formatted(NEW, second, Base64.getEncoder().encodeToString("{}".getBytes())))
                .andExpect(status().isOk()).andExpect(jsonPath("$.DocumentWithSignature[0]").exists());

        // The one of the configuration still works; the new one stops when revoked.
        authorize("mock-credential-001", "mock-password").andExpect(status().isOk());
        credentials.revoke(NEW);
        authorize(NEW, "new-password").andExpect(status().isUnauthorized());
        call("/csc/v2/credentials/list", "{}").andExpect(jsonPath("$.credentialIDs.length()").value(1));
    }
}
