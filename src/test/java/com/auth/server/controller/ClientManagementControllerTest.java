package com.auth.server.controller;

import com.auth.server.AbstractTest;
import com.auth.server.config.TestConfig;
import com.auth.server.dto.ClientCreateRequest;
import com.auth.server.dto.ClientCreatedResponse;
import com.auth.server.dto.ClientResponse;
import com.auth.server.entity.RegisteredClient;
import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.exception.ResourceNotFoundException;
import com.auth.server.repository.RegisteredClientRepository;
import com.auth.server.repository.RoleRepository;
import com.auth.server.repository.UserRepository;
import com.auth.server.service.RegisteredClientService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.hamcrest.Matchers.hasSize;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for ClientManagementController.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestConfig.class)
@DisplayName("ClientManagementController Integration Tests")
public class ClientManagementControllerTest extends AbstractTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository clientRepository;

    @Autowired
    private RegisteredClientService clientService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private ObjectMapper objectMapper;

    private RegisteredClient testClient;
    private User adminUser;
    private Role adminRole;
    private UUID clientId;

    @BeforeEach
    void setUp() {
        clientRepository.deleteAll();
        userRepository.deleteAll();
        roleRepository.deleteAll();

        // Create admin role and user
        adminRole = roleRepository.save(Role.builder()
                .name("ROLE_ADMIN")
                .description("Administrator role")
                .build());

        adminUser = User.builder()
                .username("admin")
                .email("admin@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(adminRole)))
                .build();
        userRepository.save(adminUser);

        // Create test client
        clientId = UUID.randomUUID();
        testClient = RegisteredClient.builder()
                .id(clientId)
                .clientId("test-client-1")
                .clientSecretHash("$2a$13$hashedSecret123456789")
                .clientName("Test Client 1")
                .description("Test client for integration tests")
                .redirectUris("https://localhost:8080/callback")
                .scopes("read,write")
                .accessTokenTtl(900)
                .refreshTokenTtl(2592000)
                .contactEmail("admin@example.com")
                .owner("Test Owner")
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .enabled(true)
                .deleted(false)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        clientRepository.save(testClient);
    }

    @Test
    @DisplayName("Should return 403 when creating client without authentication")
    void testCreateClientWithoutAdminRole() throws Exception {
        // Given
        ClientCreateRequest request = ClientCreateRequest.builder()
                .clientId("new-client")
                .clientName("New Client")
                .redirectUris("https://app.example.com/callback")
                .scopes("read,write")
                .build();

        // When & Then - should return 403 because no authentication
        mockMvc.perform(post("/api/admin/clients")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should return 403 when creating client without authentication")
    void testCreateClientUnauthenticated() throws Exception {
        // Given
        ClientCreateRequest request = ClientCreateRequest.builder()
                .clientId("new-client")
                .clientName("New Client")
                .build();

        // When & Then
        mockMvc.perform(post("/api/admin/clients")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should create client with admin role")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testCreateClientSuccess() throws Exception {
        // Given
        ClientCreateRequest request = ClientCreateRequest.builder()
                .clientId("new-client")
                .clientName("New Test Client")
                .description("A new test client")
                .redirectUris("https://newapp.example.com/callback")
                .scopes("read,write,admin")
                .accessTokenTtl(1800)
                .refreshTokenTtl(3600000)
                .contactEmail("contact@example.com")
                .owner("New Owner")
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .build();

        // When & Then
        mockMvc.perform(post("/api/admin/clients")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.client_id").value("new-client"))
                .andExpect(jsonPath("$.client_name").value("New Test Client"))
                .andExpect(jsonPath("$.client_secret").exists())
                .andExpect(jsonPath("$.client_secret").isNotEmpty())
                .andExpect(jsonPath("$.warning").exists());
    }

    @Test
    @DisplayName("Should return 400 when creating client with invalid data")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testCreateClientInvalidData() throws Exception {
        // Given - invalid request (missing required fields)
        ClientCreateRequest request = ClientCreateRequest.builder()
                .build();

        // When & Then
        mockMvc.perform(post("/api/admin/clients")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Should list all clients with admin role")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testGetAllClientsSuccess() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/admin/clients"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].client_id").value("test-client-1"))
                .andExpect(jsonPath("$[0].client_name").value("Test Client 1"));
    }

    @Test
    @DisplayName("Should return 403 when listing clients without admin role")
    void testGetAllClientsWithoutAdminRole() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/admin/clients"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should return 404 when getting nonexistent client")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testGetClientByIdNotFound() throws Exception {
        // When & Then
        UUID nonexistentId = UUID.randomUUID();
        mockMvc.perform(get("/api/admin/clients/" + nonexistentId))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Should return 403 when updating client without admin role")
    void testUpdateClientWithoutAdminRole() throws Exception {
        // Given
        ClientCreateRequest updateRequest = ClientCreateRequest.builder()
                .clientId("test-client-1")
                .clientName("Updated Name")
                .build();

        // When & Then
        mockMvc.perform(put("/api/admin/clients/" + clientId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(updateRequest)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should return 404 when regenerating secret for nonexistent client")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testRegenerateSecretNotFound() throws Exception {
        // When & Then
        UUID nonexistentId = UUID.randomUUID();
        mockMvc.perform(post("/api/admin/clients/" + nonexistentId + "/regenerate-secret"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Should return 404 when disabling nonexistent client")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testDisableClientNotFound() throws Exception {
        // When & Then
        UUID nonexistentId = UUID.randomUUID();
        mockMvc.perform(post("/api/admin/clients/" + nonexistentId + "/disable"))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Should return 403 when deleting client without admin role")
    void testDeleteClientWithoutAdminRole() throws Exception {
        // When & Then
        mockMvc.perform(delete("/api/admin/clients/" + clientId))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Should return 404 when deleting nonexistent client")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testDeleteClientNotFound() throws Exception {
        // When & Then
        UUID nonexistentId = UUID.randomUUID();
        mockMvc.perform(delete("/api/admin/clients/" + nonexistentId))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Should not expose client secret in list response")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testListClientsDoesNotExposeSecret() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/admin/clients"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].client_secret").doesNotExist());
    }

    @Test
    @DisplayName("Should expose client secret only in creation response")
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testCreateClientExposesSecretOnce() throws Exception {
        // Given
        ClientCreateRequest request = ClientCreateRequest.builder()
                .clientId("secret-client")
                .clientName("Secret Test Client")
                .build();

        // When
        mockMvc.perform(post("/api/admin/clients")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.client_secret").exists())
                .andExpect(jsonPath("$.client_secret").isNotEmpty());
    }
}
