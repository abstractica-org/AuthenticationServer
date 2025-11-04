package com.auth.server.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * LoginAttempt entity for tracking login attempts.
 * Used for rate limiting and account lockout functionality.
 */
@Entity
@Table(name = "login_attempts", indexes = {
        @Index(name = "idx_login_attempts_user_id", columnList = "user_id"),
        @Index(name = "idx_login_attempts_username_or_email", columnList = "username_or_email"),
        @Index(name = "idx_login_attempts_attempt_time", columnList = "attempt_time")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginAttempt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    @Column(nullable = false, length = 255)
    private String usernameOrEmail;

    @Column(length = 45)
    private String ipAddress;

    @Column(length = 500)
    private String userAgent;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime attemptTime;

    @Column(nullable = false)
    private Boolean success;

    @Column(length = 255)
    private String failureReason;

    /**
     * Create a successful login attempt
     */
    public static LoginAttempt successAttempt(User user, String usernameOrEmail, String ipAddress, String userAgent) {
        return LoginAttempt.builder()
                .user(user)
                .usernameOrEmail(usernameOrEmail)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .success(true)
                .build();
    }

    /**
     * Create a failed login attempt
     */
    public static LoginAttempt failureAttempt(String usernameOrEmail, String ipAddress, String userAgent, String reason) {
        return LoginAttempt.builder()
                .usernameOrEmail(usernameOrEmail)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .success(false)
                .failureReason(reason)
                .build();
    }
}
