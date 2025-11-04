package com.auth.server.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * VerificationToken entity for email verification and password reset tokens.
 * Supports different token types and expiration.
 */
@Entity
@Table(name = "verification_tokens", indexes = {
        @Index(name = "idx_verification_tokens_token", columnList = "token"),
        @Index(name = "idx_verification_tokens_user_id", columnList = "user_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerificationToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 500)
    private String token;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private TokenType tokenType;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    @Column
    private LocalDateTime confirmedDate;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * Enum for token types
     */
    public enum TokenType {
        EMAIL_VERIFICATION,
        PASSWORD_RESET
    }

    /**
     * Check if token is valid (not expired, not confirmed)
     */
    public boolean isValid() {
        return !isExpired() && !isConfirmed();
    }

    /**
     * Check if token is expired
     */
    public boolean isExpired() {
        return expiryDate.isBefore(LocalDateTime.now());
    }

    /**
     * Check if token has been confirmed/used
     */
    public boolean isConfirmed() {
        return confirmedDate != null;
    }

    /**
     * Mark token as confirmed
     */
    public void confirm() {
        this.confirmedDate = LocalDateTime.now();
    }
}
