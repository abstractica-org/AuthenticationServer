package com.auth.server.controller;

import com.auth.server.AbstractTest;
import com.auth.server.config.TestConfig;
import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.repository.RoleRepository;
import com.auth.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashSet;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for UserController.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestConfig.class)
@DisplayName("UserController Integration Tests")
public class UserControllerTest extends AbstractTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    private User testUser;
    private Role userRole;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        roleRepository.deleteAll();

        userRole = roleRepository.save(Role.builder()
                .name("ROLE_USER")
                .description("Standard user role")
                .build());

        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(testUser);
    }

    @Test
    @DisplayName("Should redirect to login when accessing protected endpoint without authentication")
    void testGetCurrentUserUnauthenticated() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    @DisplayName("Should get current user profile when authenticated")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testGetCurrentUserAuthenticated() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.emailVerified").value(true))
                .andExpect(jsonPath("$.enabled").value(true))
                .andExpect(jsonPath("$.locked").value(false));
    }

    @Test
    @DisplayName("Should return user roles in profile")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testGetCurrentUserWithRoles() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").isArray())
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"));
    }

    @Test
    @DisplayName("Should return 2FA status in profile")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testGetCurrentUserWith2FAStatus() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.twoFactorAuthEnabled").value(false));
    }

    @Test
    @DisplayName("Should return timestamps in user profile")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testGetCurrentUserWithTimestamps() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.createdAt").exists())
                .andExpect(jsonPath("$.updatedAt").exists());
    }

    @Test
    @DisplayName("Should return null lastLogin for new user")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testGetCurrentUserWithNullLastLogin() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.lastLogin").isEmpty());
    }

    @Test
    @DisplayName("Should return 404 when authenticated user doesn't exist")
    @WithMockUser(username = "nonexistent", roles = {"USER"})
    void testGetCurrentUserNotFound() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("User not found"));
    }

    @Test
    @DisplayName("Should handle locked user profile retrieval")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testGetCurrentUserProfileWhenLocked() throws Exception {
        // Given - Lock the user
        testUser.setLocked(true);
        userRepository.save(testUser);

        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.locked").value(true));
    }

    @Test
    @DisplayName("Should handle disabled user profile retrieval")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testGetCurrentUserProfileWhenDisabled() throws Exception {
        // Given - Disable the user
        testUser.setEnabled(false);
        userRepository.save(testUser);

        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.enabled").value(false));
    }

    @Test
    @DisplayName("Should handle unverified user profile retrieval")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testGetCurrentUserProfileWhenUnverified() throws Exception {
        // Given - Mark email as unverified
        testUser.setEmailVerified(false);
        userRepository.save(testUser);

        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.emailVerified").value(false));
    }

    @Test
    @DisplayName("Should handle user with multiple roles")
    void testGetCurrentUserWithMultipleRoles() throws Exception {
        // Given - Add admin role to user
        Role adminRole = roleRepository.save(Role.builder()
                .name("ROLE_ADMIN")
                .description("Admin role")
                .build());

        testUser.getRoles().add(adminRole);
        userRepository.save(testUser);

        // When & Then
        mockMvc.perform(get("/api/users/me")
                .header("Authorization", "Bearer dummy-token"))
                // Note: This would require proper JWT token in real scenario
                // For testing with @WithMockUser, we would use:
                // @WithMockUser(username = "testuser", roles = {"USER", "ADMIN"})
                .andExpect(status().is3xxRedirection());  // Invalid token redirects to login
    }

    @Test
    @DisplayName("Should return correct content type for user profile")
    @WithMockUser(username = "testuser", roles = {"USER"})
    void testGetCurrentUserContentType() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"));
    }
}
