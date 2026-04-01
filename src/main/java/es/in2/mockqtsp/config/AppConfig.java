package es.in2.mockqtsp.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(MockQtspProperties.class)
public class AppConfig {
}