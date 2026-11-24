package com.fikua.dss.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties({DssProperties.class, OAuthProperties.class, TrustedListProperties.class})
public class AppConfig {
}