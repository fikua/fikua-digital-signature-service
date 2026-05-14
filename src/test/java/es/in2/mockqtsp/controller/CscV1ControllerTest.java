package es.in2.mockqtsp.controller;

import es.in2.mockqtsp.config.MockQtspProperties;
import es.in2.mockqtsp.dto.common.ErrorResponse;
import es.in2.mockqtsp.dto.v1.CredentialsAuthorizeRequest;
import es.in2.mockqtsp.dto.v1.CredentialsAuthorizeResponse;
import es.in2.mockqtsp.dto.v1.CredentialsInfoRequest;
import es.in2.mockqtsp.dto.v1.CredentialsInfoResponse;
import es.in2.mockqtsp.dto.v1.CredentialsListResponse;
import es.in2.mockqtsp.dto.v1.InfoResponse;
import es.in2.mockqtsp.dto.v1.SignHashRequest;
import es.in2.mockqtsp.dto.v1.SignHashResponse;
import es.in2.mockqtsp.test.support.StubFactory;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CscV1ControllerTest {

    private final MockQtspProperties properties = StubFactory.props();
    private final CscV1Controller controller = new CscV1Controller(
            properties, StubFactory.tokens(), StubFactory.certs(), StubFactory.signing());

    @Test
    void infoIsGetAndExposesV1Specs() {
        ResponseEntity<?> resp = controller.info("en-US");
        assertEquals(200, resp.getStatusCode().value());
        InfoResponse body = (InfoResponse) resp.getBody();
        assertNotNull(body);
        assertEquals("1.0.3.0", body.specs());
        assertTrue(body.methods().contains("signatures/signHash"));
        assertTrue(!body.methods().contains("signatures/signDoc"), "signDoc must not be advertised in v1");
    }

    @Test
    void credentialsListReturnsConfiguredId() {
        ResponseEntity<?> resp = controller.credentialsList("Bearer t", null);
        assertEquals(200, resp.getStatusCode().value());
        CredentialsListResponse body = (CredentialsListResponse) resp.getBody();
        assertNotNull(body);
        assertEquals(List.of("cred-1"), body.credentialIDs());
    }

    @Test
    void credentialsInfoReturnsV1FieldsAuthModePinOtpMultisignLang() {
        ResponseEntity<?> resp = controller.credentialsInfo(
                "Bearer t",
                new CredentialsInfoRequest("cred-1", "chain", true, true, null, null));
        CredentialsInfoResponse body = (CredentialsInfoResponse) resp.getBody();
        assertNotNull(body);
        assertEquals("explicit", body.authMode());
        assertNotNull(body.PIN());
        assertNotNull(body.OTP());
        assertEquals(1, body.multisign());
        assertEquals("en-US", body.lang());
    }

    @Test
    void authorizeUsesPinNotAuthData() {
        ResponseEntity<?> resp = controller.credentialsAuthorize(
                "Bearer t",
                new CredentialsAuthorizeRequest("cred-1", 1, List.of("h"), "mock-password", null, null, null));
        assertEquals(200, resp.getStatusCode().value());
        CredentialsAuthorizeResponse body = (CredentialsAuthorizeResponse) resp.getBody();
        assertNotNull(body);
        assertEquals("SAD-STUB", body.SAD());
    }

    @Test
    void authorizeRejectsMissingPin() {
        ResponseEntity<?> resp = controller.credentialsAuthorize(
                "Bearer t",
                new CredentialsAuthorizeRequest("cred-1", 1, List.of("h"), null, null, null, null));
        assertEquals(400, resp.getStatusCode().value());
        ErrorResponse body = (ErrorResponse) resp.getBody();
        assertNotNull(body);
        assertEquals("invalid_request", body.error());
    }

    @Test
    void signHashAcceptsV1Body() {
        ResponseEntity<?> resp = controller.signHash(
                "Bearer t",
                new SignHashRequest("cred-1", "SAD-STUB", List.of("h"),
                        "2.16.840.1.101.3.4.2.1", "1.2.840.113549.1.1.11", null, null));
        assertEquals(200, resp.getStatusCode().value());
        SignHashResponse body = (SignHashResponse) resp.getBody();
        assertNotNull(body);
        assertEquals(List.of("sig-stub"), body.signatures());
    }
}
