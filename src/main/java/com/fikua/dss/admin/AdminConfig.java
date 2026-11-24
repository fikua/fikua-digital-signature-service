package com.fikua.dss.admin;

import com.fikua.dss.audit.AuditEvents;
import com.fikua.dss.service.CredentialService;
import com.fikua.dss.service.JwtVerifier;
import com.fikua.dss.users.ManagedCredentials;
import com.fikua.dss.users.ManagedUsers;
import com.nimbusds.jose.JWSAlgorithm;
import org.apache.catalina.connector.Connector;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

import java.time.Duration;
import java.util.Set;

/** The administration API, only with {@code dss.admin.port}; it needs the database and the key store. */
@Configuration
@ConditionalOnProperty("dss.admin.port")
@EnableConfigurationProperties(AdminProperties.class)
public class AdminConfig {

    /** Short: an administrator removed from the keys' issuer does not last. */
    private static final JwtVerifier.Caching CACHING =
            new JwtVerifier.Caching(Duration.ofMinutes(5), Duration.ofMinutes(15));

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> adminPort(AdminProperties properties) {
        return factory -> {
            var connector = new Connector();
            connector.setPort(properties.port());
            factory.addAdditionalConnectors(connector);
        };
    }

    /** After the request id, before everything else. */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 10)
    AdminFilter adminFilter(AdminProperties properties) {
        return new AdminFilter(properties.port(), properties.group(),
                new JwtVerifier(properties.issuer(), properties.jwksUri(), properties.audience(),
                        Set.of(JWSAlgorithm.ES256, JWSAlgorithm.RS256), Set.of("exp", "sub"), CACHING));
    }

    @Bean
    MachineClients machineClients(AdminProperties properties) {
        return new KeycloakClients(properties.keycloak());
    }

    @Bean
    Administration administration(ManagedUsers users, ManagedCredentials credentials, CredentialService all,
                                  MachineClients clients, AuditEvents audit) {
        return new Administration(users, credentials, all, clients, audit);
    }
}
