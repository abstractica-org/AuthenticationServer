package com.auth.server.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * OAuth2 Registered Client entity.
 * Stores OAuth2 client credentials for third-party applications.
 */
@Entity
@Table(name = "registered_clients", indexes = {
        @Index(name = "idx_client_id", columnList = "client_id"),
        @Index(name = "idx_client_secret_hash", columnList = "client_secret_hash")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisteredClient {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Unique client identifier used in OAuth2 flows.
     * Example: "mobile-app", "web-dashboard"
     */
    @Column(unique = true, nullable = false, length = 100)
    private String clientId;

    /**
     * BCrypt hashed client secret.
     * NEVER stored in plain text.
     */
    @Column(nullable = false, length = 255)
    private String clientSecretHash;

    /**
     * Human-readable client name.
     * Example: "Mobile App", "Admin Dashboard"
     */
    @Column(nullable = false, length = 255)
    private String clientName;

    /**
     * Description of what this client does.
     */
    @Column(length = 500)
    private String description;

    /**
     * Comma-separated list of allowed redirect URIs.
     * Used for OAuth2 authorization code callback.
     */
    @Column(columnDefinition = "VARCHAR(2000)")
    private String redirectUris;

    /**
     * Comma-separated list of allowed scopes.
     * Example: "read,write,delete"
     */
    @Column(columnDefinition = "VARCHAR(1000)")
    private String scopes;

    /**
     * Access token time-to-live in seconds.
     * Default: 900 seconds (15 minutes)
     */
    @Column(nullable = false)
    @Builder.Default
    private Integer accessTokenTtl = 900;

    /**
     * Refresh token time-to-live in seconds.
     * Default: 2592000 seconds (30 days)
     */
    @Column(nullable = false)
    @Builder.Default
    private Integer refreshTokenTtl = 2592000;

    /**
     * Whether this client is enabled/active.
     */
    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    /**
     * Whether client credentials flow is allowed (service-to-service auth).
     */
    @Column(nullable = false)
    @Builder.Default
    private Boolean clientCredentialsEnabled = true;

    /**
     * Whether authorization code flow is allowed (user auth).
     */
    @Column(nullable = false)
    @Builder.Default
    private Boolean authorizationCodeEnabled = true;

    /**
     * Whether refresh token flow is allowed.
     */
    @Column(nullable = false)
    @Builder.Default
    private Boolean refreshTokenEnabled = true;

    /**
     * Contact email for client owner.
     */
    @Column(length = 255)
    private String contactEmail;

    /**
     * Client owner/organization.
     */
    @Column(length = 255)
    private String owner;

    /**
     * Timestamp when client was created.
     */
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Timestamp when client was last updated.
     */
    @UpdateTimestamp
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    /**
     * Last time this client was used.
     * Useful for tracking active vs inactive clients.
     */
    @Column
    private LocalDateTime lastUsedAt;

    /**
     * Whether client is marked for deletion (soft delete).
     */
    @Column(nullable = false)
    @Builder.Default
    private Boolean deleted = false;

    /**
     * Timestamp when client was deleted (if applicable).
     */
    @Column
    private LocalDateTime deletedAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (updatedAt == null) {
            updatedAt = LocalDateTime.now();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Check if client is active and accessible.
     */
    public boolean isActive() {
        return enabled && !deleted;
    }

    /**
     * Record this client was used just now.
     */
    public void recordUsage() {
        this.lastUsedAt = LocalDateTime.now();
    }
}
