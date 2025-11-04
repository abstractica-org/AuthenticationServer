package com.auth.server.repository;

import com.auth.server.entity.RegisteredClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for RegisteredClientRepository.
 */
@DataJpaTest
@ActiveProfiles("test")
@DisplayName("RegisteredClientRepository Tests")
public class RegisteredClientRepositoryTest {

    @Autowired
    private RegisteredClientRepository clientRepository;

    private RegisteredClient testClient;
    private RegisteredClient testClient2;

    @BeforeEach
    void setUp() {
        // Create first test client
        testClient = RegisteredClient.builder()
                .clientId("test-client-1")
                .clientSecretHash("$2a$13$hashedSecret123456789")
                .clientName("Test Client 1")
                .description("Test client for unit tests")
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
                .build();

        // Create second test client
        testClient2 = RegisteredClient.builder()
                .clientId("test-client-2")
                .clientSecretHash("$2a$13$anotherHashedSecret123")
                .clientName("Test Client 2")
                .description("Another test client")
                .redirectUris("https://app.example.com/oauth/callback")
                .scopes("read")
                .accessTokenTtl(1800)
                .refreshTokenTtl(2592000)
                .contactEmail("support@example.com")
                .owner("Another Owner")
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(false)
                .refreshTokenEnabled(true)
                .enabled(true)
                .deleted(false)
                .build();

        clientRepository.save(testClient);
        clientRepository.save(testClient2);
    }

    @Test
    @DisplayName("Should save and retrieve client by ID")
    void testSaveAndFindById() {
        // When
        Optional<RegisteredClient> found = clientRepository.findById(testClient.getId());

        // Then
        assertThat(found)
                .isPresent()
                .hasValueSatisfying(client -> {
                    assertThat(client.getClientId()).isEqualTo("test-client-1");
                    assertThat(client.getClientName()).isEqualTo("Test Client 1");
                });
    }

    @Test
    @DisplayName("Should find client by client ID when not deleted")
    void testFindByClientIdAndDeletedFalse() {
        // When
        Optional<RegisteredClient> found = clientRepository.findByClientIdAndDeletedFalse("test-client-1");

        // Then
        assertThat(found)
                .isPresent()
                .hasValueSatisfying(client -> {
                    assertThat(client.getClientId()).isEqualTo("test-client-1");
                    assertThat(client.getDeleted()).isFalse();
                });
    }

    @Test
    @DisplayName("Should not find deleted client")
    void testFindByClientIdIgnoresDeletedClients() {
        // Given
        testClient.setDeleted(true);
        clientRepository.save(testClient);

        // When
        Optional<RegisteredClient> found = clientRepository.findByClientIdAndDeletedFalse("test-client-1");

        // Then
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("Should find client by ID when not deleted")
    void testFindByIdAndDeletedFalse() {
        // When
        Optional<RegisteredClient> found = clientRepository.findByIdAndDeletedFalse(testClient.getId());

        // Then
        assertThat(found)
                .isPresent()
                .hasValueSatisfying(client -> assertThat(client.getDeleted()).isFalse());
    }

    @Test
    @DisplayName("Should return empty for deleted client by ID")
    void testFindByIdIgnoresDeletedClients() {
        // Given
        testClient.setDeleted(true);
        clientRepository.save(testClient);

        // When
        Optional<RegisteredClient> found = clientRepository.findByIdAndDeletedFalse(testClient.getId());

        // Then
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("Should find all non-deleted clients")
    void testFindByDeletedFalse() {
        // When
        List<RegisteredClient> found = clientRepository.findByDeletedFalse();

        // Then
        assertThat(found)
                .hasSize(2)
                .allMatch(client -> !client.getDeleted());
    }

    @Test
    @DisplayName("Should find clients by owner")
    void testFindClientsByOwner() {
        // When
        List<RegisteredClient> found = clientRepository.findClientsByOwner("Test Owner");

        // Then
        assertThat(found)
                .hasSize(1)
                .allMatch(client -> client.getOwner().equals("Test Owner"))
                .allMatch(client -> !client.getDeleted());
    }

    @Test
    @DisplayName("Should not include deleted clients in owner search")
    void testFindClientsByOwnerIgnoresDeletedClients() {
        // Given
        testClient.setDeleted(true);
        clientRepository.save(testClient);

        // When
        List<RegisteredClient> found = clientRepository.findClientsByOwner("Test Owner");

        // Then
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("Should count clients by owner")
    void testCountByOwnerAndDeletedFalse() {
        // When
        long count = clientRepository.countByOwnerAndDeletedFalse("Test Owner");

        // Then
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("Should not count deleted clients")
    void testCountByOwnerIgnoresDeletedClients() {
        // Given
        testClient.setDeleted(true);
        clientRepository.save(testClient);

        // When
        long count = clientRepository.countByOwnerAndDeletedFalse("Test Owner");

        // Then
        assertThat(count).isEqualTo(0);
    }

    @Test
    @DisplayName("Should check if client ID exists")
    void testExistsByClientIdAndDeletedFalse() {
        // When
        boolean exists = clientRepository.existsByClientIdAndDeletedFalse("test-client-1");
        boolean notExists = clientRepository.existsByClientIdAndDeletedFalse("nonexistent");

        // Then
        assertThat(exists).isTrue();
        assertThat(notExists).isFalse();
    }

    @Test
    @DisplayName("Should not find deleted client ID as existing")
    void testExistsByClientIdIgnoresDeletedClients() {
        // Given
        testClient.setDeleted(true);
        clientRepository.save(testClient);

        // When
        boolean exists = clientRepository.existsByClientIdAndDeletedFalse("test-client-1");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    @DisplayName("Should update client properties")
    void testUpdateClient() {
        // When
        testClient.setClientName("Updated Name");
        testClient.setDescription("Updated description");
        testClient.setAccessTokenTtl(3600);
        clientRepository.save(testClient);

        // Then
        Optional<RegisteredClient> updated = clientRepository.findById(testClient.getId());
        assertThat(updated)
                .isPresent()
                .hasValueSatisfying(client -> {
                    assertThat(client.getClientName()).isEqualTo("Updated Name");
                    assertThat(client.getDescription()).isEqualTo("Updated description");
                    assertThat(client.getAccessTokenTtl()).isEqualTo(3600);
                });
    }

    @Test
    @DisplayName("Should update client secret hash")
    void testUpdateClientSecretHash() {
        // When
        testClient.setClientSecretHash("$2a$13$newHashedSecret123456");
        clientRepository.save(testClient);

        // Then
        Optional<RegisteredClient> updated = clientRepository.findById(testClient.getId());
        assertThat(updated)
                .isPresent()
                .hasValueSatisfying(client ->
                        assertThat(client.getClientSecretHash()).isEqualTo("$2a$13$newHashedSecret123456")
                );
    }

    @Test
    @DisplayName("Should disable client")
    void testDisableClient() {
        // When
        testClient.setEnabled(false);
        clientRepository.save(testClient);

        // Then
        Optional<RegisteredClient> disabled = clientRepository.findById(testClient.getId());
        assertThat(disabled)
                .isPresent()
                .hasValueSatisfying(client -> assertThat(client.getEnabled()).isFalse());
    }

    @Test
    @DisplayName("Should soft delete client")
    void testSoftDeleteClient() {
        // When
        LocalDateTime now = LocalDateTime.now();
        testClient.setDeleted(true);
        testClient.setDeletedAt(now);
        clientRepository.save(testClient);

        // Then
        Optional<RegisteredClient> deleted = clientRepository.findById(testClient.getId());
        assertThat(deleted)
                .isPresent()
                .hasValueSatisfying(client -> {
                    assertThat(client.getDeleted()).isTrue();
                    assertThat(client.getDeletedAt()).isNotNull();
                });

        // And should not be found by non-deleted query
        Optional<RegisteredClient> notFound = clientRepository.findByClientIdAndDeletedFalse("test-client-1");
        assertThat(notFound).isEmpty();
    }

    @Test
    @DisplayName("Should record last usage timestamp")
    void testRecordLastUsedAt() {
        // When
        LocalDateTime now = LocalDateTime.now();
        testClient.recordUsage();
        clientRepository.save(testClient);

        // Then
        Optional<RegisteredClient> client = clientRepository.findById(testClient.getId());
        assertThat(client)
                .isPresent()
                .hasValueSatisfying(c -> assertThat(c.getLastUsedAt()).isNotNull());
    }

    @Test
    @DisplayName("Should update client enabled status")
    void testToggleClientEnabled() {
        // When
        testClient.setEnabled(false);
        RegisteredClient disabled = clientRepository.save(testClient);
        assertThat(disabled.getEnabled()).isFalse();

        // And
        testClient.setEnabled(true);
        RegisteredClient enabled = clientRepository.save(testClient);

        // Then
        assertThat(enabled.getEnabled()).isTrue();
    }

    @Test
    @DisplayName("Should retrieve multiple clients")
    void testFindMultipleClients() {
        // When
        List<RegisteredClient> clients = clientRepository.findByDeletedFalse();

        // Then
        assertThat(clients)
                .hasSize(2)
                .extracting(RegisteredClient::getClientId)
                .contains("test-client-1", "test-client-2");
    }

    @Test
    @DisplayName("Should maintain client ID uniqueness")
    void testClientIdUniqueness() {
        // Given - verify that testClient with clientId "test-client-1" exists
        assertThat(clientRepository.existsByClientIdAndDeletedFalse("test-client-1")).isTrue();

        // When - try to create another client with same clientId
        RegisteredClient duplicateClient = RegisteredClient.builder()
                .clientId("test-client-1")  // Same as testClient
                .clientSecretHash("$2a$13$different")
                .clientName("Duplicate")
                .scopes("read")
                .accessTokenTtl(900)
                .refreshTokenTtl(2592000)
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .enabled(true)
                .deleted(false)
                .build();

        // Then - attempting to save should violate unique constraint
        assertThatThrownBy(() -> {
            clientRepository.save(duplicateClient);
            clientRepository.flush();
        }).isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("Should return empty list when no clients found")
    void testFindByOwnerReturnsEmptyList() {
        // When
        List<RegisteredClient> clients = clientRepository.findClientsByOwner("Nonexistent Owner");

        // Then
        assertThat(clients).isEmpty();
    }
}
