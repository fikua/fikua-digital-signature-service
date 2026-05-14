package es.in2.mockqtsp.controller;

import es.in2.mockqtsp.config.MockQtspProperties;
import es.in2.mockqtsp.dto.v2.CredentialsAuthorizeRequest;
import es.in2.mockqtsp.dto.v2.CredentialsAuthorizeResponse;
import es.in2.mockqtsp.dto.v2.CredentialsInfoRequest;
import es.in2.mockqtsp.dto.v2.CredentialsInfoResponse;
import es.in2.mockqtsp.dto.v2.CredentialsListResponse;
import es.in2.mockqtsp.dto.v2.InfoResponse;
import es.in2.mockqtsp.dto.v2.SignDocRequest;
import es.in2.mockqtsp.dto.v2.SignDocResponse;
import es.in2.mockqtsp.dto.v2.SignHashRequest;
import es.in2.mockqtsp.dto.v2.SignHashResponse;
import es.in2.mockqtsp.test.support.StubFactory;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CscV2ControllerTest {

    private final MockQtspProperties properties = StubFactory.props();
    private final CscV2Controller controller = new CscV2Controller(
            properties, StubFactory.tokens(), StubFactory.certs(), StubFactory.signing());

    @Test
    void infoIsPostAndIncludesV2RequiredFields() {
        ResponseEntity<?> resp = controller.info(null);
        InfoResponse body = (InfoResponse) resp.getBody();
        assertNotNull(body);
        assertEquals("2.0.0.0", body.specs());
        assertNotNull(body.signAlgorithms());
        assertNotNull(body.signature_formats());
        assertNotNull(body.conformance_levels());
        assertTrue(body.methods().contains("signatures/signDoc"));
    }

    @Test
    void credentialsListReturnsConfiguredId() {
        ResponseEntity<?> resp = controller.credentialsList("Bearer t", null);
        CredentialsListResponse body = (CredentialsListResponse) resp.getBody();
        assertNotNull(body);
        assertEquals(List.of("cred-1"), body.credentialIDs());
    }

    @Test
    void credentialsInfoUsesAuthObjectNotAuthMode() {
        ResponseEntity<?> resp = controller.credentialsInfo(
                "Bearer t",
                new CredentialsInfoRequest("cred-1", "chain", true, true, null, null));
        CredentialsInfoResponse body = (CredentialsInfoResponse) resp.getBody();
        assertNotNull(body);
        assertNotNull(body.auth());
        assertEquals("explicit", body.auth().mode());
        assertNotNull(body.auth().objects());
    }

    @Test
    void authorizeUsesAuthDataArrayNotPin() {
        ResponseEntity<?> resp = controller.credentialsAuthorize(
                "Bearer t",
                new CredentialsAuthorizeRequest("cred-1", 1, List.of("h"), "oid",
                        List.of(new CredentialsAuthorizeRequest.AuthData("PIN", "mock-password")),
                        null, null));
        assertEquals(200, resp.getStatusCode().value());
        CredentialsAuthorizeResponse body = (CredentialsAuthorizeResponse) resp.getBody();
        assertNotNull(body);
        assertEquals("SAD-STUB", body.SAD());
    }

    @Test
    void signHashUsesHashesField() {
        ResponseEntity<?> resp = controller.signHash(
                "Bearer t",
                new SignHashRequest("cred-1", "SAD-STUB", List.of("h"),
                        "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11",
                        null, null, null, null, null));
        SignHashResponse body = (SignHashResponse) resp.getBody();
        assertNotNull(body);
        assertEquals(List.of("sig-stub"), body.signatures());
    }

    @Test
    void signHashRequestDeserialisedFromV1ShapeHasNullHashes() {
        // Documents the gap: a v1-shape body (`hash` field) deserialises into the v2 DTO
        // with `hashes=null`. The controller forwards null to the signing service, which
        // would fail at runtime against the real SigningService. The smoke test confirms
        // the runtime NPE. Here we just assert the structural mismatch on the record.
        SignHashRequest v1ShapeAfterDeserialisation = new SignHashRequest(
                "cred-1", "SAD-STUB", null, null, "1.2.840.113549.1.1.11",
                null, null, null, null, null);
        assertEquals(null, v1ShapeAfterDeserialisation.hashes(),
                "v2 SignHashRequest has no `hash` field; v1-shape body cannot populate hashes");
    }

    @Test
    void signDocAcceptsDocumentsModeAndReturnsSignaturesField() {
        ResponseEntity<?> resp = controller.signDoc(
                "Bearer t",
                new SignDocRequest("cred-1", "eu_eidas_qes", "SAD-STUB",
                        null,
                        List.of(new SignDocRequest.Document("aGVsbG8=", "P", "Ades-B-B",
                                "1.2.840.113549.1.1.11", null)),
                        "2.16.840.1.101.3.4.2.1", null, null, null, null, null));
        SignDocResponse body = (SignDocResponse) resp.getBody();
        assertNotNull(body);
        assertNotNull(body.documentWithSignature());
        assertNotNull(body.signatureObject(), "v2 spec marks `signatures` as REQUIRED");
        assertEquals("docsig-stub", body.signatureObject().get(0));
    }
}
