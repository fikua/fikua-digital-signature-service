package com.fikua.dss.support;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

/** A JWK set over HTTP and tokens signed with its key, as Keycloak issues them. */
public class FakeAuthorizationServer implements AutoCloseable {

    public static final String ISSUER = "https://auth.example.test/realms/dss";
    public static final String AUDIENCE = "https://dss.example.test";

    private final HttpServer server;
    private final ECKey key = newKey("key-1");

    public FakeAuthorizationServer() {
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        server.createContext("/certs", exchange -> {
            var body = new JWKSet(key.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    public String jwksUri() {
        return "http://localhost:" + server.getAddress().getPort() + "/certs";
    }

    /** The claims of a valid token of this client. */
    public static JWTClaimsSet.Builder claims(String clientId) {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .subject("service-account")
                .claim("azp", clientId)
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)));
    }

    public String token(String clientId) {
        return sign(claims(clientId).build());
    }

    public String sign(JWTClaimsSet claims) {
        return sign(claims, key);
    }

    public static String sign(JWTClaimsSet claims, ECKey key) {
        try {
            var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public static ECKey newKey(String id) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(id).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
