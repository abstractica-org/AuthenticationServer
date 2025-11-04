package com.auth.server.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * User entity representing an authentication user.
 * Stores user credentials, status flags, and relationships.
 */
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_users_username", columnList = "username"),
        @Index(name = "idx_users_email", columnList = "email")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(unique = true, nullable = false, length = 100)
    private String username;

    @Column(unique = true, nullable = false, length = 255)
    private String email;

    @Column(nullable = false, length = 255)
    private String passwordHash;

    @Column(nullable = false)
    @Builder.Default
    private Boolean emailVerified = false;

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    @Column(nullable = false)
    @Builder.Default
    private Boolean locked = false;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Column
    private LocalDateTime lastLogin;

    /**
     * Two-Factor Authentication (2FA) enabled flag.
     */
    @Column(nullable = false)
    @Builder.Default
    private Boolean twoFactorEnabled = false;

    /**
     * TOTP secret for two-factor authentication.
     * Base32-encoded secret key for authenticator apps.
     */
    @Column(length = 255)
    private String twoFactorSecret;

    /**
     * Backup codes for 2FA account recovery.
     * Comma-separated Base64-encoded codes.
     */
    @Column(columnDefinition = "VARCHAR(2000)")
    private String twoFactorBackupCodes;

    /**
     * Many-to-many relationship with roles.
     * Cascade: roles are not deleted when user is deleted.
     * Using EAGER fetch to avoid lazy initialization issues in tests and API responses.
     */
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();

    /**
     * One-to-one relationship with 2FA settings.
     */
    @OneToOne(mappedBy = "user", cascade = CascadeType.REMOVE, orphanRemoval = true)
    private TwoFactorAuth twoFactorAuth;

    /**
     * One-to-many relationship with login attempts.
     */
    @OneToMany(mappedBy = "user", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @Builder.Default
    private Set<LoginAttempt> loginAttempts = new HashSet<>();

    /**
     * One-to-many relationship with refresh tokens.
     */
    @OneToMany(mappedBy = "user", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @Builder.Default
    private Set<RefreshToken> refreshTokens = new HashSet<>();

    /**
     * One-to-many relationship with verification tokens.
     */
    @OneToMany(mappedBy = "user", cascade = CascadeType.REMOVE, orphanRemoval = true)
    @Builder.Default
    private Set<VerificationToken> verificationTokens = new HashSet<>();

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
     * Check if the user account is fully enabled and not locked.
     */
    public boolean isAccountActive() {
        return enabled && !locked;
    }

    /**
     * Check if the user is verified (email verified).
     */
    public boolean isVerified() {
        return emailVerified;
    }
}
