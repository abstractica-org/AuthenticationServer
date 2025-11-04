package com.auth.server.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

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

    /**
     * JWT Decoder for validating JWT tokens
     */
    @Bean
    public JwtDecoder jwtDecoder(KeyPair keyPair) {
        log.info("Configuring JWT Decoder with RSA public key");
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    /**
     * JWT Encoder for creating JWT tokens
     */
    @Bean
    public JwtEncoder jwtEncoder(KeyPair keyPair) {
        log.info("Configuring JWT Encoder with RSA key pair");
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .build();

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
        return new NimbusJwtEncoder(jwkSource);
    }
}
