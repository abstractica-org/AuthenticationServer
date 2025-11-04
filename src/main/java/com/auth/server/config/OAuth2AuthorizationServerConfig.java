package com.auth.server.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

/**
 * OAuth2 Configuration for JWT signing.
 * Note: Full OAuth2 Authorization Server will be implemented in a separate phase.
 * This configuration provides the foundation for JWT token generation and validation.
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
public class OAuth2AuthorizationServerConfig {

    @Value("${jwt.expiration:900000}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh.expiration:2592000000}")
    private long refreshTokenExpiration;

    /**
     * Generate RSA key pair for JWT signing
     */
    @Bean
    public KeyPair keyPair() throws Exception {
        log.info("Initializing RSA key pair for JWT signing");
        return generateRsaKey();
    }

    /**
     * Generate RSA key (2048-bit)
     */
    private static KeyPair generateRsaKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
