package com.fikua.dss.config;

import com.fikua.dss.keys.CredentialCertificates;
import com.fikua.dss.keys.CredentialKeyStore;
import com.fikua.dss.keys.EncryptedDbKeyStore;
import com.fikua.dss.keys.MasterKeys;
import com.fikua.dss.users.ListSignerCommand;
import com.fikua.dss.users.ListSigners;
import com.fikua.dss.users.ManagedCredentials;
import com.fikua.dss.users.ManagedUsers;
import com.zaxxer.hikari.HikariDataSource;
import org.flywaydb.core.Flyway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.core.env.Environment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;

/**
 * The database of users and credentials, only when {@code dss.database.url} is
 * set. Without it the service has the users of its configuration and nothing else.
 */
@Configuration
@ConditionalOnProperty("dss.database.url")
@EnableConfigurationProperties({DatabaseConfig.DatabaseProperties.class, DatabaseConfig.KeysProperties.class})
public class DatabaseConfig {

    private static final Logger log = LoggerFactory.getLogger(DatabaseConfig.class);

    @ConfigurationProperties(prefix = "dss.database")
    public record DatabaseProperties(String url, String username, String password, @DefaultValue("5") int poolSize) {}

    /** The master key of the key store and the CAs whose certificates are installed (PEM files). */
    @ConfigurationProperties(prefix = "dss.keys")
    public record KeysProperties(String masterKey, String previousMasterKey, List<String> acceptedCas) {}

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

    /** After managedUsers, which migrates the database. */
    @Bean
    @DependsOn("managedUsers")
    @ConditionalOnProperty("dss.keys.master-key")
    CredentialKeyStore credentialKeyStore(DataSource dataSource, KeysProperties properties) {
        var store = new EncryptedDbKeyStore(JdbcClient.create(dataSource),
                new MasterKeys(properties.masterKey(), properties.previousMasterKey()));
        var rewrapped = store.rewrap();
        if (rewrapped > 0) {
            log.atInfo().setMessage("keys encrypted again with the current master key")
                    .addKeyValue("keys", rewrapped).log();
        }
        return store;
    }

    @Bean
    @ConditionalOnProperty("dss.keys.master-key")
    ManagedCredentials managedCredentials(ManagedUsers users, CredentialKeyStore keys, KeysProperties properties,
                                          DataSource dataSource, DssProperties configuration) {
        var transaction = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        return new ManagedCredentials(users, keys,
                new CredentialCertificates(keys, acceptedCas(properties), Clock.systemUTC()), transaction,
                id -> isConfigured(configuration, id));
    }

    /** Only while the operator's command runs: the service never has it. */
    @Bean
    @ConditionalOnProperty(name = "dss.command", havingValue = ListSignerCommand.NAME)
    ListSignerCommand listSignerCommand(ManagedUsers users, CredentialKeyStore keys, DataSource dataSource,
                                        DssProperties configuration, Environment environment) {
        var transaction = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        return new ListSignerCommand(new ListSigners(users, keys, transaction,
                id -> isConfigured(configuration, id), Clock.systemUTC()), environment, System.out);
    }

    private static boolean isConfigured(DssProperties configuration, String credentialId) {
        return configuration.users() != null && configuration.users().stream()
                .flatMap(u -> u.credentials().stream()).anyMatch(c -> c.id().equals(credentialId));
    }

    private static List<X509Certificate> acceptedCas(KeysProperties properties) {
        var loader = new DefaultResourceLoader();
        var files = properties.acceptedCas() == null ? List.<String>of() : properties.acceptedCas();
        return files.stream().flatMap(file -> {
            try (var in = loader.getResource(file).getInputStream()) {
                return CredentialCertificates.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8)).stream();
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to read an accepted CA", e);
            }
        }).toList();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }
}
