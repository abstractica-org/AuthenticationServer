package com.auth.server.repository;

import com.auth.server.entity.RegisteredClient;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for RegisteredClient entity.
 * Handles OAuth2 client CRUD operations.
 */
@Repository
public interface RegisteredClientRepository extends JpaRepository<RegisteredClient, UUID> {

    /**
     * Find active client by client ID.
     */
    Optional<RegisteredClient> findByClientIdAndDeletedFalse(String clientId);

    /**
     * Find client by client ID (including deleted).
     */
    Optional<RegisteredClient> findByClientId(String clientId);

    /**
     * Find client by ID and ensure not deleted.
     */
    Optional<RegisteredClient> findByIdAndDeletedFalse(UUID id);

    /**
     * Get all active clients with pagination.
     */
    Page<RegisteredClient> findByDeletedFalseAndEnabledTrue(Pageable pageable);

    /**
     * Get all clients for owner (active only).
     */
    List<RegisteredClient> findByOwnerAndDeletedFalse(String owner);

    /**
     * Get all active clients.
     */
    List<RegisteredClient> findByDeletedFalse();

    /**
     * Check if client ID is already taken (active clients only).
     */
    boolean existsByClientIdAndDeletedFalse(String clientId);

    /**
     * Find clients by enabled status.
     */
    List<RegisteredClient> findByEnabledAndDeletedFalse(Boolean enabled);

    /**
     * Find all clients for a specific owner.
     */
    @Query("SELECT rc FROM RegisteredClient rc WHERE rc.owner = :owner AND rc.deleted = false ORDER BY rc.createdAt DESC")
    List<RegisteredClient> findClientsByOwner(@Param("owner") String owner);

    /**
     * Count active clients for an owner.
     */
    long countByOwnerAndDeletedFalse(String owner);

    /**
     * Delete old deleted clients (soft delete cleanup).
     */
    @Query("DELETE FROM RegisteredClient rc WHERE rc.deleted = true AND rc.deletedAt < :beforeTime")
    void deleteOldDeletedClients(@Param("beforeTime") java.time.LocalDateTime beforeTime);
}
