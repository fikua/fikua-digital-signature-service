package com.fikua.dss.web;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Customises the generated OpenAPI document with project metadata and an
 * OAuth2 client_credentials security scheme so Swagger UI can authenticate
 * against /oauth2/token interactively.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI dssOpenAPI() {
        var oauth = new SecurityScheme()
                .type(SecurityScheme.Type.OAUTH2)
                .flows(new OAuthFlows().clientCredentials(
                        new OAuthFlow()
                                .tokenUrl("/oauth2/token")
                                .scopes(new io.swagger.v3.oas.models.security.Scopes())));

        var bearer = new SecurityScheme()
                .type(SecurityScheme.Type.HTTP)
                .scheme("bearer")
                .bearerFormat("JWT");

        return new OpenAPI()
                .info(new Info()
                        .title("Fikua Digital Signature Service")
                        .description("Cloud Signature Consortium (CSC) v2 API. Mock QTSP for "
                                + "development and testing of remote signing flows.")
                        .version("0.3.1")
                        .license(new License()
                                .name("Apache-2.0")
                                .url("https://www.apache.org/licenses/LICENSE-2.0")))
                .components(new Components()
                        .addSecuritySchemes("oauth2", oauth)
                        .addSecuritySchemes("bearerAuth", bearer))
                .addSecurityItem(new SecurityRequirement().addList("oauth2"))
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
    }
}
