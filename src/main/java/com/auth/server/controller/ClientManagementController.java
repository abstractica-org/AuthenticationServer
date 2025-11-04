package com.auth.server.controller;

import com.auth.server.dto.ClientCreateRequest;
import com.auth.server.dto.ClientCreatedResponse;
import com.auth.server.dto.ClientResponse;
import com.auth.server.dto.MessageResponse;
import com.auth.server.service.AuditService;
import com.auth.server.service.RegisteredClientService;
import com.auth.server.util.IpAddressUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Controller for OAuth2 client management.
 * Restricted to ADMIN role for security.
 * All endpoints require authentication.
 */
@Slf4j
@RestController
@RequestMapping("/api/admin/clients")
@RequiredArgsConstructor
@Tag(name = "Client Management", description = "OAuth2 client management endpoints (ADMIN only)")
@PreAuthorize("hasRole('ADMIN')")
public class ClientManagementController {

    private final RegisteredClientService clientService;
    private final AuditService auditService;

    /**
     * Create a new OAuth2 client.
     * Client secret is generated and returned ONLY in this response.
     *
     * @param request Client creation request
     * @param authentication Admin authentication
     * @param httpRequest HTTP request
     * @return Created client with plain-text secret
     */
    @PostMapping
    @Operation(summary = "Create new OAuth2 client", description = "Create a new OAuth2 client. Client secret is only shown once!")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Client created successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid client data"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - admin authentication required"),
            @ApiResponse(responseCode = "403", description = "Forbidden - admin role required")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<ClientCreatedResponse> createClient(
            @Valid @RequestBody ClientCreateRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Creating new OAuth2 client: {}", request.getClientId());

        String adminUsername = authentication.getName();
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);

        ClientCreatedResponse response = clientService.createClient(request);

        // Log client creation (clientId, adminUserId, adminUsername, ipAddress)
        auditService.logClientCreated(
                request.getClientId(),
                null,
                adminUsername,
                ipAddress
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Get all OAuth2 clients.
     *
     * @return List of all active clients
     */
    @GetMapping
    @Operation(summary = "List all OAuth2 clients", description = "Get all active OAuth2 clients")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Clients retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - admin role required")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<List<ClientResponse>> getAllClients() {
        log.debug("Retrieving all OAuth2 clients");

        List<ClientResponse> clients = clientService.getAllClients();

        return ResponseEntity.ok(clients);
    }

    /**
     * Get a specific client by ID.
     *
     * @param id Client UUID
     * @return Client details
     */
    @GetMapping("/{id}")
    @Operation(summary = "Get client by ID", description = "Retrieve a specific OAuth2 client by its ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Client retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - admin role required"),
            @ApiResponse(responseCode = "404", description = "Client not found")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<ClientResponse> getClient(@PathVariable UUID id) {
        log.debug("Retrieving client: {}", id);

        ClientResponse response = clientService.getClient(id);

        return ResponseEntity.ok(response);
    }

    /**
     * Update a client.
     *
     * @param id Client UUID
     * @param request Update request
     * @param authentication Admin authentication
     * @param httpRequest HTTP request
     * @return Updated client
     */
    @PutMapping("/{id}")
    @Operation(summary = "Update OAuth2 client", description = "Update an OAuth2 client configuration")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Client updated successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid data"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - admin role required"),
            @ApiResponse(responseCode = "404", description = "Client not found")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<ClientResponse> updateClient(
            @PathVariable UUID id,
            @Valid @RequestBody ClientCreateRequest request,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Updating client: {}", id);

        String adminUsername = authentication.getName();
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);

        ClientResponse response = clientService.updateClient(id, request);

        // Log client update
        auditService.logClientUpdated(
                response.getClientId(),
                null,
                adminUsername,
                ipAddress
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Regenerate client secret.
     * The old secret becomes invalid immediately.
     *
     * @param id Client UUID
     * @param authentication Admin authentication
     * @param httpRequest HTTP request
     * @return New client secret (shown only once)
     */
    @PostMapping("/{id}/regenerate-secret")
    @Operation(summary = "Regenerate client secret", description = "Generate a new client secret. Old secret becomes invalid immediately!")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Secret regenerated successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - admin role required"),
            @ApiResponse(responseCode = "404", description = "Client not found")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<ClientCreatedResponse> regenerateSecret(
            @PathVariable UUID id,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.warn("Regenerating secret for client: {}", id);

        String adminUsername = authentication.getName();
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);

        ClientCreatedResponse response = clientService.regenerateSecret(id);

        // Log secret regeneration
        auditService.logClientSecretRegenerated(
                response.getClientId(),
                null,
                adminUsername,
                ipAddress
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Enable a client.
     *
     * @param id Client UUID
     * @param authentication Admin authentication
     * @param httpRequest HTTP request
     * @return Updated client
     */
    @PostMapping("/{id}/enable")
    @Operation(summary = "Enable OAuth2 client", description = "Enable an OAuth2 client")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Client enabled successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - admin role required"),
            @ApiResponse(responseCode = "404", description = "Client not found")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<ClientResponse> enableClient(
            @PathVariable UUID id,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Enabling client: {}", id);

        String adminUsername = authentication.getName();
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);

        ClientResponse response = clientService.setClientEnabled(id, true);

        // Log client enable
        auditService.logClientUpdated(
                response.getClientId(),
                null,
                adminUsername,
                ipAddress
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Disable a client.
     *
     * @param id Client UUID
     * @param authentication Admin authentication
     * @param httpRequest HTTP request
     * @return Updated client
     */
    @PostMapping("/{id}/disable")
    @Operation(summary = "Disable OAuth2 client", description = "Disable an OAuth2 client")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Client disabled successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - admin role required"),
            @ApiResponse(responseCode = "404", description = "Client not found")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<ClientResponse> disableClient(
            @PathVariable UUID id,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Disabling client: {}", id);

        String adminUsername = authentication.getName();
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);

        ClientResponse response = clientService.setClientEnabled(id, false);

        // Log client disable
        auditService.logClientUpdated(
                response.getClientId(),
                null,
                adminUsername,
                ipAddress
        );

        return ResponseEntity.ok(response);
    }

    /**
     * Delete a client (soft delete).
     *
     * @param id Client UUID
     * @param authentication Admin authentication
     * @param httpRequest HTTP request
     * @return Success message
     */
    @DeleteMapping("/{id}")
    @Operation(summary = "Delete OAuth2 client", description = "Delete (soft delete) an OAuth2 client")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Client deleted successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized"),
            @ApiResponse(responseCode = "403", description = "Forbidden - admin role required"),
            @ApiResponse(responseCode = "404", description = "Client not found")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<MessageResponse> deleteClient(
            @PathVariable UUID id,
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.warn("Deleting client: {}", id);

        String adminUsername = authentication.getName();
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);

        // Get client ID for logging before deletion
        ClientResponse client = clientService.getClient(id);

        clientService.deleteClient(id);

        // Log client deletion
        auditService.logClientDeleted(
                client.getClientId(),
                null,
                adminUsername,
                ipAddress
        );

        return ResponseEntity.ok(MessageResponse.builder()
                .message("Client deleted successfully")
                .build());
    }
}
