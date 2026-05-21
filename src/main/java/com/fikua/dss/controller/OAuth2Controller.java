package com.fikua.dss.controller;

import com.fikua.dss.config.DssProperties;
import com.fikua.dss.dto.ErrorResponse;
import com.fikua.dss.dto.TokenResponse;
import com.fikua.dss.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@RestController
public class OAuth2Controller {

    private static final Logger log = LoggerFactory.getLogger(OAuth2Controller.class);

    private final TokenService tokenService;
    private final DssProperties properties;

    public OAuth2Controller(TokenService tokenService, DssProperties properties) {
        this.tokenService = tokenService;
        this.properties = properties;
    }

    @PostMapping(value = "/oauth2/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<?> token(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "scope", required = false) String scope,
            @RequestParam(value = "authorization_details", required = false) String authorizationDetails
    ) {
        log.info("POST /oauth2/token grant_type={} scope={}", grantType, scope);

        if (!"client_credentials".equals(grantType)) {
            return ResponseEntity.badRequest().body(
                    new ErrorResponse("unsupported_grant_type", "Only client_credentials is supported"));
        }

        String clientId;
        String clientSecret;

        if (authHeader != null && authHeader.startsWith("Basic ")) {
            var decoded = new String(Base64.getDecoder().decode(authHeader.substring(6)), StandardCharsets.UTF_8);
            var parts = decoded.split(":", 2);
            clientId = parts[0];
            clientSecret = parts.length > 1 ? parts[1] : "";
        } else {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_client", "Missing Basic authentication header"));
        }

        try {
            var token = tokenService.issueAccessToken(clientId, clientSecret);
            return ResponseEntity.ok(new TokenResponse(token, "Bearer", properties.tokenTtlSeconds()));
        } catch (SecurityException e) {
            return ResponseEntity.status(401).body(
                    new ErrorResponse("invalid_client", e.getMessage()));
        }
    }
}
