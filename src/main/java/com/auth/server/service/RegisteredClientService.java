package com.auth.server.service;

import com.auth.server.dto.ClientCreateRequest;
import com.auth.server.dto.ClientCreatedResponse;
import com.auth.server.dto.ClientResponse;
import com.auth.server.entity.RegisteredClient;
import com.auth.server.exception.ResourceNotFoundException;
import com.auth.server.repository.RegisteredClientRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service for managing OAuth2 registered clients.
 * Handles client creation, updates, secret regeneration, and lifecycle management.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class RegisteredClientService {

    private final RegisteredClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Create a new OAuth2 client.
     * Generates a secure client secret that is ONLY returned once.
     *
     * @param request Client creation request
     * @return Response with client data and plain-text secret
     */
    public ClientCreatedResponse createClient(ClientCreateRequest request) {
        log.info("Creating new OAuth2 client: {}", request.getClientId());

        // Check if client ID already exists
        if (clientRepository.existsByClientIdAndDeletedFalse(request.getClientId())) {
            throw new IllegalArgumentException("Client ID already exists: " + request.getClientId());
        }

        // Generate secure client secret
        String plainSecret = generateClientSecret();
        String hashedSecret = passwordEncoder.encode(plainSecret);

        // Create client
        RegisteredClient client = RegisteredClient.builder()
                .clientId(request.getClientId())
                .clientSecretHash(hashedSecret)
                .clientName(request.getClientName())
                .description(request.getDescription())
                .redirectUris(request.getRedirectUris())
                .scopes(request.getScopes() != null ? request.getScopes() : "read,write")
                .accessTokenTtl(request.getAccessTokenTtl() != null ? request.getAccessTokenTtl() : 900)
                .refreshTokenTtl(request.getRefreshTokenTtl() != null ? request.getRefreshTokenTtl() : 2592000)
                .contactEmail(request.getContactEmail())
                .owner(request.getOwner())
                .clientCredentialsEnabled(request.getClientCredentialsEnabled() != null ? request.getClientCredentialsEnabled() : true)
                .authorizationCodeEnabled(request.getAuthorizationCodeEnabled() != null ? request.getAuthorizationCodeEnabled() : true)
                .refreshTokenEnabled(request.getRefreshTokenEnabled() != null ? request.getRefreshTokenEnabled() : true)
                .enabled(true)
                .deleted(false)
                .build();

        RegisteredClient saved = clientRepository.save(client);
        log.info("OAuth2 client created successfully: {} (ID: {})", request.getClientId(), saved.getId());

        // Return response with plain-text secret (only time it's shown)
        return ClientCreatedResponse.builder()
                .id(saved.getId())
                .clientId(saved.getClientId())
                .clientSecret(plainSecret)  // ONLY time plain secret is returned
                .clientName(saved.getClientName())
                .description(saved.getDescription())
                .enabled(saved.getEnabled())
                .createdAt(saved.getCreatedAt())
                .build();
    }

    /**
     * Get client by ID.
     *
     * @param id Client UUID
     * @return Client response
     */
    public ClientResponse getClient(UUID id) {
        log.debug("Retrieving client: {}", id);

        RegisteredClient client = clientRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ResourceNotFoundException("Client not found"));

        return mapToResponse(client);
    }

    /**
     * Get client by client ID.
     *
     * @param clientId Client identifier
     * @return Client response
     */
    public ClientResponse getClientByClientId(String clientId) {
        log.debug("Retrieving client by ID: {}", clientId);

        RegisteredClient client = clientRepository.findByClientIdAndDeletedFalse(clientId)
                .orElseThrow(() -> new ResourceNotFoundException("Client not found"));

        client.recordUsage();
        clientRepository.save(client);

        return mapToResponse(client);
    }

    /**
     * Get all clients for an owner.
     *
     * @param owner Owner name
     * @return List of client responses
     */
    public List<ClientResponse> getClientsByOwner(String owner) {
        log.debug("Retrieving clients for owner: {}", owner);

        return clientRepository.findClientsByOwner(owner)
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    /**
     * Get all active clients.
     *
     * @return List of client responses
     */
    public List<ClientResponse> getAllClients() {
        log.debug("Retrieving all active clients");

        return clientRepository.findByDeletedFalse()
                .stream()
                .map(this::mapToResponse)
                .collect(Collectors.toList());
    }

    /**
     * Update client configuration.
     *
     * @param id Client UUID
     * @param request Update request
     * @return Updated client response
     */
    public ClientResponse updateClient(UUID id, ClientCreateRequest request) {
        log.info("Updating client: {}", id);

        RegisteredClient client = clientRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ResourceNotFoundException("Client not found"));

        // Update fields
        if (request.getClientName() != null) client.setClientName(request.getClientName());
        if (request.getDescription() != null) client.setDescription(request.getDescription());
        if (request.getRedirectUris() != null) client.setRedirectUris(request.getRedirectUris());
        if (request.getScopes() != null) client.setScopes(request.getScopes());
        if (request.getAccessTokenTtl() != null) client.setAccessTokenTtl(request.getAccessTokenTtl());
        if (request.getRefreshTokenTtl() != null) client.setRefreshTokenTtl(request.getRefreshTokenTtl());
        if (request.getContactEmail() != null) client.setContactEmail(request.getContactEmail());
        if (request.getOwner() != null) client.setOwner(request.getOwner());
        if (request.getClientCredentialsEnabled() != null) client.setClientCredentialsEnabled(request.getClientCredentialsEnabled());
        if (request.getAuthorizationCodeEnabled() != null) client.setAuthorizationCodeEnabled(request.getAuthorizationCodeEnabled());
        if (request.getRefreshTokenEnabled() != null) client.setRefreshTokenEnabled(request.getRefreshTokenEnabled());

        RegisteredClient updated = clientRepository.save(client);
        log.info("Client updated successfully: {}", id);

        return mapToResponse(updated);
    }

    /**
     * Regenerate client secret.
     * The old secret becomes invalid immediately.
     *
     * @param id Client UUID
     * @return Response with new secret
     */
    public ClientCreatedResponse regenerateSecret(UUID id) {
        log.warn("Regenerating secret for client: {}", id);

        RegisteredClient client = clientRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ResourceNotFoundException("Client not found"));

        // Generate new secret
        String newPlainSecret = generateClientSecret();
        String newHashedSecret = passwordEncoder.encode(newPlainSecret);

        client.setClientSecretHash(newHashedSecret);
        RegisteredClient updated = clientRepository.save(client);

        log.warn("Client secret regenerated: {}", id);

        return ClientCreatedResponse.builder()
                .id(updated.getId())
                .clientId(updated.getClientId())
                .clientSecret(newPlainSecret)
                .clientName(updated.getClientName())
                .enabled(updated.getEnabled())
                .warning("New secret generated. Old secret is now invalid.")
                .build();
    }

    /**
     * Enable/disable a client.
     *
     * @param id Client UUID
     * @param enabled Whether to enable the client
     * @return Updated client response
     */
    public ClientResponse setClientEnabled(UUID id, boolean enabled) {
        log.info("Setting client {} enabled: {}", id, enabled);

        RegisteredClient client = clientRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ResourceNotFoundException("Client not found"));

        client.setEnabled(enabled);
        RegisteredClient updated = clientRepository.save(client);

        return mapToResponse(updated);
    }

    /**
     * Soft delete a client (mark as deleted, but don't remove from DB).
     *
     * @param id Client UUID
     */
    public void deleteClient(UUID id) {
        log.warn("Deleting client: {}", id);

        RegisteredClient client = clientRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> new ResourceNotFoundException("Client not found"));

        client.setDeleted(true);
        client.setDeletedAt(LocalDateTime.now());
        client.setEnabled(false);
        clientRepository.save(client);

        log.warn("Client deleted: {}", id);
    }

    /**
     * Verify client secret.
     * Used during OAuth2 authentication flows.
     *
     * @param clientId Client identifier
     * @param plainSecret Plain-text secret to verify
     * @return true if secret matches
     */
    public boolean verifyClientSecret(String clientId, String plainSecret) {
        return clientRepository.findByClientIdAndDeletedFalse(clientId)
                .map(client -> passwordEncoder.matches(plainSecret, client.getClientSecretHash()))
                .orElse(false);
    }

    /**
     * Check if client exists and is active.
     *
     * @param clientId Client identifier
     * @return true if client is active
     */
    public boolean isClientActive(String clientId) {
        return clientRepository.findByClientIdAndDeletedFalse(clientId)
                .map(RegisteredClient::isActive)
                .orElse(false);
    }

    /**
     * Count active clients for owner.
     *
     * @param owner Owner name
     * @return Number of active clients
     */
    public long countClientsByOwner(String owner) {
        return clientRepository.countByOwnerAndDeletedFalse(owner);
    }

    /**
     * Generate a secure client secret.
     * 32 bytes = 256 bits of entropy, Base64 encoded.
     *
     * @return Secure random client secret
     */
    private String generateClientSecret() {
        byte[] randomBytes = new byte[32];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Map RegisteredClient entity to response DTO.
     */
    private ClientResponse mapToResponse(RegisteredClient client) {
        return ClientResponse.builder()
                .id(client.getId())
                .clientId(client.getClientId())
                .clientName(client.getClientName())
                .description(client.getDescription())
                .redirectUris(client.getRedirectUris())
                .scopes(client.getScopes())
                .accessTokenTtl(client.getAccessTokenTtl())
                .refreshTokenTtl(client.getRefreshTokenTtl())
                .enabled(client.getEnabled())
                .clientCredentialsEnabled(client.getClientCredentialsEnabled())
                .authorizationCodeEnabled(client.getAuthorizationCodeEnabled())
                .refreshTokenEnabled(client.getRefreshTokenEnabled())
                .contactEmail(client.getContactEmail())
                .owner(client.getOwner())
                .createdAt(client.getCreatedAt())
                .updatedAt(client.getUpdatedAt())
                .lastUsedAt(client.getLastUsedAt())
                .build();
    }
}
