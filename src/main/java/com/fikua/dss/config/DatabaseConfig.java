package com.fikua.dss.config;

import com.fikua.dss.users.ManagedUsers;
import com.zaxxer.hikari.HikariDataSource;
import org.flywaydb.core.Flyway;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;
import java.time.Clock;

/**
 * The database of users and credentials, only when {@code dss.database.url} is
 * set. Without it the service has the users of its configuration and nothing else.
 */
@Configuration
@ConditionalOnProperty("dss.database.url")
@EnableConfigurationProperties(DatabaseConfig.DatabaseProperties.class)
public class DatabaseConfig {

    @ConfigurationProperties(prefix = "dss.database")
    public record DatabaseProperties(String url, String username, String password, @DefaultValue("5") int poolSize) {}

    @Bean(destroyMethod = "close")
    HikariDataSource dataSource(DatabaseProperties properties) {
        var dataSource = new HikariDataSource();
        dataSource.setJdbcUrl(properties.url());
        dataSource.setUsername(properties.username());
        dataSource.setPassword(properties.password());
        dataSource.setMaximumPoolSize(properties.poolSize());
        // A request waits this long at most for the database, then answers 503.
        dataSource.setConnectionTimeout(3_000);
        return dataSource;
    }

    /** Migrated before anything reads it. */
    @Bean
    ManagedUsers managedUsers(DataSource dataSource, PasswordEncoder passwordEncoder) {
        Flyway.configure().dataSource(dataSource).load().migrate();
        return new ManagedUsers(JdbcClient.create(dataSource), passwordEncoder, Clock.systemUTC());
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }
}
