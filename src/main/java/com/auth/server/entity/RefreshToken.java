package com.auth.server.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * RefreshToken entity for managing refresh tokens.
 * Supports token rotation by tracking replaced tokens.
 */
@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_refresh_tokens_user_id", columnList = "user_id"),
        @Index(name = "idx_refresh_tokens_token_value", columnList = "token_value")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, unique = true, length = 500)
    private String tokenValue;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    @Column(nullable = false)
    @Builder.Default
    private Boolean revoked = false;

    /**
     * Reference to the token that replaced this one (for rotation tracking)
     */
    @ManyToOne
    @JoinColumn(name = "replaced_by_token_id")
    private RefreshToken replacedByToken;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Check if token is valid (not expired, not revoked, not replaced)
     */
    public boolean isValid() {
        return !revoked
                && replacedByToken == null
                && expiryDate.isAfter(LocalDateTime.now());
    }

    /**
     * Check if token is expired
     */
    public boolean isExpired() {
        return expiryDate.isBefore(LocalDateTime.now());
    }

    /**
     * Check if token is replaced
     */
    public boolean isReplaced() {
        return replacedByToken != null;
    }
}
