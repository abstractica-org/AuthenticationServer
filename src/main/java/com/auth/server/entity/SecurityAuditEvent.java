package com.auth.server.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Security Audit Event entity
 * Logs all security-related events for audit trail and forensic analysis
 */
@Entity
@Table(name = "security_audit_events", indexes = {
        @Index(name = "idx_event_type", columnList = "event_type"),
        @Index(name = "idx_user_id", columnList = "user_id"),
        @Index(name = "idx_event_time", columnList = "event_time"),
        @Index(name = "idx_status", columnList = "status")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecurityAuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Type of security event (e.g., LOGIN_ATTEMPT, PASSWORD_CHANGE, 2FA_ENABLED)
     */
    @Column(nullable = false, length = 100)
    private String eventType;

    /**
     * User ID affected by the event (may be null for public operations)
     */
    @Column(length = 36)
    private String userId;

    /**
     * Username affected by the event
     */
    @Column(length = 255)
    private String username;

    /**
     * IP address from which the action originated
     */
    @Column(length = 45)
    private String ipAddress;

    /**
     * User agent of the client
     */
    @Column(columnDefinition = "VARCHAR(500)")
    private String userAgent;

    /**
     * Description of the event
     */
    @Column(columnDefinition = "VARCHAR(1000)")
    private String description;

    /**
     * Status of the event (SUCCESS, FAILURE)
     */
    @Column(nullable = false, length = 50)
    @Builder.Default
    private String status = "SUCCESS";

    /**
     * Error message if status is FAILURE
     */
    @Column(columnDefinition = "VARCHAR(1000)")
    private String errorMessage;

    /**
     * Additional details as JSON
     */
    @Column(columnDefinition = "TEXT")
    private String details;

    /**
     * Timestamp when the event occurred
     */
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private LocalDateTime eventTime;

    /**
     * Severity level: LOW, MEDIUM, HIGH, CRITICAL
     */
    @Column(nullable = false, length = 50)
    @Builder.Default
    private String severity = "MEDIUM";

    /**
     * Enum for event types
     */
    public enum EventType {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGIN_ATTEMPT_RATE_LIMIT,
        PASSWORD_CHANGED,
        PASSWORD_RESET_REQUESTED,
        PASSWORD_RESET_COMPLETED,
        PASSWORD_RESET_FAILED,
        EMAIL_VERIFICATION_SENT,
        EMAIL_VERIFIED,
        TWO_FACTOR_SETUP_INITIATED,
        TWO_FACTOR_ENABLED,
        TWO_FACTOR_DISABLED,
        TWO_FACTOR_BACKUP_CODES_GENERATED,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        CLIENT_CREATED,
        CLIENT_UPDATED,
        CLIENT_DELETED,
        CLIENT_SECRET_REGENERATED,
        CLIENT_ENABLED,
        CLIENT_DISABLED,
        UNAUTHORIZED_ACCESS_ATTEMPT,
        SUSPICIOUS_ACTIVITY_DETECTED,
        ADMIN_ACTION_PERFORMED,
        ROLE_ASSIGNED,
        ROLE_REVOKED,
        USER_DISABLED,
        USER_ENABLED
    }

    /**
     * Enum for severity levels
     */
    public enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /**
     * Enum for status
     */
    public enum Status {
        SUCCESS,
        FAILURE
    }
}
