package com.auth.server;

import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Abstract base class for all Spring Boot integration tests.
 * Provides common setup and utilities for testing.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
public abstract class AbstractTest {

    @Autowired
    protected ObjectMapper objectMapper;

    /**
     * Create a test user
     */
    protected User createTestUser(String username, String email, Role... roles) {
        User user = User.builder()
                .id(UUID.randomUUID())
                .username(username)
                .email(email)
                .passwordHash("$2a$13$hashedPasswordHash123456789")  // BCrypt hashed "Test@1234"
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(roles)))
                .build();
        return user;
    }

    /**
     * Create a test role
     */
    protected Role createTestRole(String name, String description) {
        return Role.builder()
                .name(name)
                .description(description)
                .build();
    }

    /**
     * Convert object to JSON string
     */
    protected String toJsonString(Object object) throws Exception {
        return objectMapper.writeValueAsString(object);
    }

    /**
     * Parse JSON string to object
     */
    protected <T> T fromJsonString(String json, Class<T> clazz) throws Exception {
        return objectMapper.readValue(json, clazz);
    }
}
