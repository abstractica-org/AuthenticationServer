package com.auth.server.config;

import com.auth.server.service.EmailService;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import static org.mockito.Mockito.mock;

/**
 * Test configuration that provides mock beans for integration tests.
 */
@TestConfiguration
public class TestConfig {

    /**
     * Mock EmailService bean for testing
     * Prevents actual email sending during tests
     */
    @Bean
    @Primary
    public EmailService emailService() {
        return mock(EmailService.class);
    }
}
