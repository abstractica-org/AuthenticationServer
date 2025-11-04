package com.auth.server.service;

import com.auth.server.dto.ClientCreateRequest;
import com.auth.server.dto.ClientCreatedResponse;
import com.auth.server.dto.ClientResponse;
import com.auth.server.entity.RegisteredClient;
import com.auth.server.exception.ResourceNotFoundException;
import com.auth.server.repository.RegisteredClientRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RegisteredClientService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("RegisteredClientService Tests")
public class RegisteredClientServiceTest {

    @Mock
    private RegisteredClientRepository clientRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private RegisteredClientService clientService;

    private ClientCreateRequest createRequest;
    private RegisteredClient testClient;
    private UUID clientId;

    @BeforeEach
    void setUp() {
        clientId = UUID.randomUUID();

        createRequest = ClientCreateRequest.builder()
                .clientId("test-client")
                .clientName("Test Client")
                .description("A test client")
                .redirectUris("https://localhost:8080/callback")
                .scopes("read,write")
                .accessTokenTtl(900)
                .refreshTokenTtl(2592000)
                .contactEmail("admin@example.com")
                .owner("Test Owner")
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .build();

        testClient = RegisteredClient.builder()
                .id(clientId)
                .clientId("test-client")
                .clientSecretHash("$2a$13$hashedSecret123456789")
                .clientName("Test Client")
                .description("A test client")
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
    }

    @Test
    @DisplayName("Should create client successfully")
    void testCreateClientSuccess() {
        // Given
        when(clientRepository.existsByClientIdAndDeletedFalse("test-client")).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$13$hashedSecret");
        when(clientRepository.save(any(RegisteredClient.class))).thenReturn(testClient);

        // When
        ClientCreatedResponse response = clientService.createClient(createRequest);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getClientId()).isEqualTo("test-client");
        assertThat(response.getClientName()).isEqualTo("Test Client");
        assertThat(response.getClientSecret()).isNotNull();
        assertThat(response.getClientSecret()).isNotEmpty();
        assertThat(response.getWarning()).containsIgnoringCase("save");
        verify(clientRepository, times(1)).existsByClientIdAndDeletedFalse("test-client");
        verify(clientRepository, times(1)).save(any(RegisteredClient.class));
    }

    @Test
    @DisplayName("Should throw exception when client ID already exists")
    void testCreateClientThrowsExceptionWhenClientIdExists() {
        // Given
        when(clientRepository.existsByClientIdAndDeletedFalse("test-client")).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> clientService.createClient(createRequest))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Client ID already exists");

        verify(clientRepository, never()).save(any(RegisteredClient.class));
    }

    @Test
    @DisplayName("Should get client by ID")
    void testGetClientById() {
        // Given
        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.of(testClient));

        // When
        ClientResponse response = clientService.getClient(clientId);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getClientId()).isEqualTo("test-client");
        assertThat(response.getClientName()).isEqualTo("Test Client");
        verify(clientRepository, times(1)).findByIdAndDeletedFalse(clientId);
    }

    @Test
    @DisplayName("Should throw exception when client not found by ID")
    void testGetClientByIdNotFound() {
        // Given
        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> clientService.getClient(clientId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Client not found");
    }

    @Test
    @DisplayName("Should get client by client ID")
    void testGetClientByClientId() {
        // Given
        when(clientRepository.findByClientIdAndDeletedFalse("test-client")).thenReturn(Optional.of(testClient));
        when(clientRepository.save(any(RegisteredClient.class))).thenReturn(testClient);

        // When
        ClientResponse response = clientService.getClientByClientId("test-client");

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getClientId()).isEqualTo("test-client");
        verify(clientRepository, times(1)).findByClientIdAndDeletedFalse("test-client");
        verify(clientRepository, times(1)).save(any(RegisteredClient.class));
    }

    @Test
    @DisplayName("Should throw exception when client not found by client ID")
    void testGetClientByClientIdNotFound() {
        // Given
        when(clientRepository.findByClientIdAndDeletedFalse("nonexistent")).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> clientService.getClientByClientId("nonexistent"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Client not found");
    }

    @Test
    @DisplayName("Should get all active clients")
    void testGetAllClients() {
        // Given
        RegisteredClient client2 = RegisteredClient.builder()
                .id(UUID.randomUUID())
                .clientId("test-client-2")
                .clientSecretHash("$2a$13$anotherHash")
                .clientName("Test Client 2")
                .scopes("read")
                .accessTokenTtl(900)
                .refreshTokenTtl(2592000)
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .enabled(true)
                .deleted(false)
                .build();
        when(clientRepository.findByDeletedFalse()).thenReturn(List.of(testClient, client2));

        // When
        List<ClientResponse> responses = clientService.getAllClients();

        // Then
        assertThat(responses)
                .hasSize(2)
                .extracting(ClientResponse::getClientId)
                .contains("test-client", "test-client-2");
        verify(clientRepository, times(1)).findByDeletedFalse();
    }

    @Test
    @DisplayName("Should get clients by owner")
    void testGetClientsByOwner() {
        // Given
        when(clientRepository.findClientsByOwner("Test Owner")).thenReturn(List.of(testClient));

        // When
        List<ClientResponse> responses = clientService.getClientsByOwner("Test Owner");

        // Then
        assertThat(responses)
                .hasSize(1)
                .allMatch(r -> r.getOwner().equals("Test Owner"));
        verify(clientRepository, times(1)).findClientsByOwner("Test Owner");
    }

    @Test
    @DisplayName("Should update client successfully")
    void testUpdateClientSuccess() {
        // Given
        ClientCreateRequest updateRequest = ClientCreateRequest.builder()
                .clientId("test-client")
                .clientName("Updated Name")
                .description("Updated description")
                .redirectUris("https://newapp.example.com/callback")
                .scopes("read,write,admin")
                .accessTokenTtl(1800)
                .refreshTokenTtl(3600000)
                .contactEmail("newemail@example.com")
                .owner("New Owner")
                .clientCredentialsEnabled(false)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .build();

        RegisteredClient updatedClient = RegisteredClient.builder()
                .id(clientId)
                .clientId("test-client")
                .clientSecretHash("$2a$13$hashedSecret123456789")
                .clientName("Updated Name")
                .description("Updated description")
                .redirectUris("https://newapp.example.com/callback")
                .scopes("read,write,admin")
                .accessTokenTtl(1800)
                .refreshTokenTtl(3600000)
                .contactEmail("newemail@example.com")
                .owner("New Owner")
                .clientCredentialsEnabled(false)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .enabled(true)
                .deleted(false)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.of(testClient));
        when(clientRepository.save(any(RegisteredClient.class))).thenReturn(updatedClient);

        // When
        ClientResponse response = clientService.updateClient(clientId, updateRequest);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getClientName()).isEqualTo("Updated Name");
        assertThat(response.getDescription()).isEqualTo("Updated description");
        assertThat(response.getAccessTokenTtl()).isEqualTo(1800);
        verify(clientRepository, times(1)).findByIdAndDeletedFalse(clientId);
        verify(clientRepository, times(1)).save(any(RegisteredClient.class));
    }

    @Test
    @DisplayName("Should regenerate client secret")
    void testRegenerateSecretSuccess() {
        // Given
        String newSecret = "newGeneratedSecret123";
        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.of(testClient));
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$13$newHashedSecret");
        when(clientRepository.save(any(RegisteredClient.class))).thenReturn(testClient);

        // When
        ClientCreatedResponse response = clientService.regenerateSecret(clientId);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getClientSecret()).isNotNull();
        assertThat(response.getClientSecret()).isNotEmpty();
        assertThat(response.getWarning()).containsIgnoringCase("invalid");
        verify(clientRepository, times(1)).findByIdAndDeletedFalse(clientId);
        verify(clientRepository, times(1)).save(any(RegisteredClient.class));
    }

    @Test
    @DisplayName("Should throw exception when regenerating secret for nonexistent client")
    void testRegenerateSecretClientNotFound() {
        // Given
        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> clientService.regenerateSecret(clientId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Client not found");
    }

    @Test
    @DisplayName("Should enable client")
    void testSetClientEnabledTrue() {
        // Given
        RegisteredClient enabledClient = RegisteredClient.builder()
                .id(clientId)
                .clientId("test-client")
                .clientSecretHash("$2a$13$hashedSecret123456789")
                .clientName("Test Client")
                .scopes("read,write")
                .accessTokenTtl(900)
                .refreshTokenTtl(2592000)
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .enabled(true)
                .deleted(false)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.of(testClient));
        when(clientRepository.save(any(RegisteredClient.class))).thenReturn(enabledClient);

        // When
        ClientResponse response = clientService.setClientEnabled(clientId, true);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getEnabled()).isTrue();
        verify(clientRepository, times(1)).findByIdAndDeletedFalse(clientId);
        verify(clientRepository, times(1)).save(any(RegisteredClient.class));
    }

    @Test
    @DisplayName("Should disable client")
    void testSetClientEnabledFalse() {
        // Given
        RegisteredClient disabledClient = RegisteredClient.builder()
                .id(clientId)
                .clientId("test-client")
                .clientSecretHash("$2a$13$hashedSecret123456789")
                .clientName("Test Client")
                .scopes("read,write")
                .accessTokenTtl(900)
                .refreshTokenTtl(2592000)
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .enabled(false)
                .deleted(false)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.of(testClient));
        when(clientRepository.save(any(RegisteredClient.class))).thenReturn(disabledClient);

        // When
        ClientResponse response = clientService.setClientEnabled(clientId, false);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getEnabled()).isFalse();
        verify(clientRepository, times(1)).findByIdAndDeletedFalse(clientId);
        verify(clientRepository, times(1)).save(any(RegisteredClient.class));
    }

    @Test
    @DisplayName("Should delete client (soft delete)")
    void testDeleteClientSuccess() {
        // Given
        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.of(testClient));
        when(clientRepository.save(any(RegisteredClient.class))).thenReturn(testClient);

        // When
        clientService.deleteClient(clientId);

        // Then
        verify(clientRepository, times(1)).findByIdAndDeletedFalse(clientId);
        verify(clientRepository, times(1)).save(argThat(client ->
                client.getDeleted() && client.getDeletedAt() != null && !client.getEnabled()
        ));
    }

    @Test
    @DisplayName("Should throw exception when deleting nonexistent client")
    void testDeleteClientNotFound() {
        // Given
        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> clientService.deleteClient(clientId))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Client not found");
    }

    @Test
    @DisplayName("Should verify correct client secret")
    void testVerifyClientSecretCorrect() {
        // Given
        when(clientRepository.findByClientIdAndDeletedFalse("test-client"))
                .thenReturn(Optional.of(testClient));
        when(passwordEncoder.matches("plainSecret", "$2a$13$hashedSecret123456789"))
                .thenReturn(true);

        // When
        boolean verified = clientService.verifyClientSecret("test-client", "plainSecret");

        // Then
        assertThat(verified).isTrue();
        verify(clientRepository, times(1)).findByClientIdAndDeletedFalse("test-client");
    }

    @Test
    @DisplayName("Should reject incorrect client secret")
    void testVerifyClientSecretIncorrect() {
        // Given
        when(clientRepository.findByClientIdAndDeletedFalse("test-client"))
                .thenReturn(Optional.of(testClient));
        when(passwordEncoder.matches("wrongSecret", "$2a$13$hashedSecret123456789"))
                .thenReturn(false);

        // When
        boolean verified = clientService.verifyClientSecret("test-client", "wrongSecret");

        // Then
        assertThat(verified).isFalse();
    }

    @Test
    @DisplayName("Should return false when client not found during verification")
    void testVerifyClientSecretClientNotFound() {
        // Given
        when(clientRepository.findByClientIdAndDeletedFalse("nonexistent"))
                .thenReturn(Optional.empty());

        // When
        boolean verified = clientService.verifyClientSecret("nonexistent", "anySecret");

        // Then
        assertThat(verified).isFalse();
    }

    @Test
    @DisplayName("Should check if client is active")
    void testIsClientActiveTrue() {
        // Given
        RegisteredClient activeClient = RegisteredClient.builder()
                .id(clientId)
                .clientId("test-client")
                .clientSecretHash("$2a$13$hashedSecret123456789")
                .clientName("Test Client")
                .scopes("read,write")
                .accessTokenTtl(900)
                .refreshTokenTtl(2592000)
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .enabled(true)
                .deleted(false)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        when(clientRepository.findByClientIdAndDeletedFalse("test-client"))
                .thenReturn(Optional.of(activeClient));

        // When
        boolean active = clientService.isClientActive("test-client");

        // Then
        assertThat(active).isTrue();
    }

    @Test
    @DisplayName("Should return false when client is disabled")
    void testIsClientActiveFalseWhenDisabled() {
        // Given
        RegisteredClient inactiveClient = RegisteredClient.builder()
                .id(clientId)
                .clientId("test-client")
                .clientSecretHash("$2a$13$hashedSecret123456789")
                .clientName("Test Client")
                .scopes("read,write")
                .accessTokenTtl(900)
                .refreshTokenTtl(2592000)
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .enabled(false)
                .deleted(false)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
        when(clientRepository.findByClientIdAndDeletedFalse("test-client"))
                .thenReturn(Optional.of(inactiveClient));

        // When
        boolean active = clientService.isClientActive("test-client");

        // Then
        assertThat(active).isFalse();
    }

    @Test
    @DisplayName("Should return false when client not found")
    void testIsClientActiveFalseWhenNotFound() {
        // Given
        when(clientRepository.findByClientIdAndDeletedFalse("nonexistent"))
                .thenReturn(Optional.empty());

        // When
        boolean active = clientService.isClientActive("nonexistent");

        // Then
        assertThat(active).isFalse();
    }

    @Test
    @DisplayName("Should count clients by owner")
    void testCountClientsByOwner() {
        // Given
        when(clientRepository.countByOwnerAndDeletedFalse("Test Owner")).thenReturn(3L);

        // When
        long count = clientService.countClientsByOwner("Test Owner");

        // Then
        assertThat(count).isEqualTo(3L);
        verify(clientRepository, times(1)).countByOwnerAndDeletedFalse("Test Owner");
    }

    @Test
    @DisplayName("Should generate secure client secret with 32 bytes entropy")
    void testClientSecretGeneration() {
        // Given
        when(clientRepository.existsByClientIdAndDeletedFalse("test-client")).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$13$hashedSecret");
        when(clientRepository.save(any(RegisteredClient.class))).thenReturn(testClient);

        // When
        ClientCreatedResponse response = clientService.createClient(createRequest);

        // Then
        assertThat(response.getClientSecret())
                .isNotNull()
                .isNotEmpty()
                .hasSizeGreaterThan(30);  // Base64 encoded 32 bytes is ~44 chars
    }

    @Test
    @DisplayName("Should apply default TTL values when not provided")
    void testDefaultTtlValues() {
        // Given
        ClientCreateRequest requestWithoutTtl = ClientCreateRequest.builder()
                .clientId("test-client")
                .clientName("Test Client")
                .build();

        when(clientRepository.existsByClientIdAndDeletedFalse("test-client")).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$13$hashedSecret");
        when(clientRepository.save(any(RegisteredClient.class))).thenReturn(testClient);

        // When
        ClientCreatedResponse response = clientService.createClient(requestWithoutTtl);

        // Then
        // Verify that save was called with default values
        verify(clientRepository).save(argThat(client ->
                client.getAccessTokenTtl() == 900 &&  // 15 minutes
                        client.getRefreshTokenTtl() == 2592000  // 30 days
        ));
    }

    @Test
    @DisplayName("Should not expose client secret in response DTO")
    void testClientResponseDoesNotIncludeSecret() {
        // Given
        when(clientRepository.findByIdAndDeletedFalse(clientId)).thenReturn(Optional.of(testClient));

        // When
        ClientResponse response = clientService.getClient(clientId);

        // Then
        // ClientResponse should not have clientSecret field
        assertThat(response).isNotNull();
        assertThat(response.getClientId()).isEqualTo("test-client");

        // Verify through reflection that clientSecret field doesn't exist
        try {
            response.getClass().getDeclaredField("clientSecret");
            throw new AssertionError("ClientResponse should not expose clientSecret field");
        } catch (NoSuchFieldException e) {
            // Expected - field should not exist
        }
    }
}
