package com.auth.server.service;

import com.auth.server.entity.SecurityAuditEvent;
import com.auth.server.repository.SecurityAuditEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Security Audit Service
 * <p>
 * Centralized service for logging all security-related events.
 * Provides structured audit logging for compliance, forensic analysis, and security monitoring.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AuditService {

    private final SecurityAuditEventRepository auditEventRepository;
    private final ObjectMapper objectMapper;

    /**
     * Log an authentication event
     */
    public void logAuthenticationEvent(String username, String userId, String ipAddress, String userAgent, boolean success) {
        String eventType = success ? SecurityAuditEvent.EventType.LOGIN_SUCCESS.name() : SecurityAuditEvent.EventType.LOGIN_FAILURE.name();
        String severity = success ? SecurityAuditEvent.Severity.MEDIUM.name() : SecurityAuditEvent.Severity.HIGH.name();
        String status = success ? SecurityAuditEvent.Status.SUCCESS.name() : SecurityAuditEvent.Status.FAILURE.name();
        String description = success ? "User logged in successfully" : "Login attempt failed";

        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(eventType)
                .userId(userId)
                .username(username)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .description(description)
                .status(status)
                .severity(severity)
                .build();

        auditEventRepository.save(event);
        if (success) {
            log.info("Audit: {} logged in from IP: {}", username, ipAddress);
        } else {
            log.warn("Audit: Failed login attempt for {} from IP: {}", username, ipAddress);
        }
    }

    /**
     * Log a password change event
     */
    public void logPasswordChangeEvent(String userId, String username, String ipAddress, boolean success) {
        String status = success ? SecurityAuditEvent.Status.SUCCESS.name() : SecurityAuditEvent.Status.FAILURE.name();
        String description = success ? "Password changed successfully" : "Password change failed";

        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.PASSWORD_CHANGED.name())
                .userId(userId)
                .username(username)
                .ipAddress(ipAddress)
                .description(description)
                .status(status)
                .severity(SecurityAuditEvent.Severity.MEDIUM.name())
                .build();

        auditEventRepository.save(event);
        log.info("Audit: Password changed for user: {}", username);
    }

    /**
     * Log a password reset request event
     */
    public void logPasswordResetRequest(String email, String ipAddress) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.PASSWORD_RESET_REQUESTED.name())
                .username(email)
                .ipAddress(ipAddress)
                .description("Password reset request initiated")
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.MEDIUM.name())
                .build();

        auditEventRepository.save(event);
        log.info("Audit: Password reset requested for email: {}", email);
    }

    /**
     * Log a password reset completion event
     */
    public void logPasswordResetCompleted(String username, String userId, String ipAddress, boolean success) {
        String status = success ? SecurityAuditEvent.Status.SUCCESS.name() : SecurityAuditEvent.Status.FAILURE.name();
        String description = success ? "Password reset completed" : "Password reset failed";

        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.PASSWORD_RESET_COMPLETED.name())
                .userId(userId)
                .username(username)
                .ipAddress(ipAddress)
                .description(description)
                .status(status)
                .severity(SecurityAuditEvent.Severity.MEDIUM.name())
                .build();

        auditEventRepository.save(event);
        log.info("Audit: Password reset completed for user: {}", username);
    }

    /**
     * Log a two-factor authentication enable event
     */
    public void logTwoFactorAuthEnabled(String userId, String username, String ipAddress) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.TWO_FACTOR_ENABLED.name())
                .userId(userId)
                .username(username)
                .ipAddress(ipAddress)
                .description("Two-factor authentication enabled")
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.MEDIUM.name())
                .build();

        auditEventRepository.save(event);
        log.info("Audit: 2FA enabled for user: {}", username);
    }

    /**
     * Log a two-factor authentication disable event
     */
    public void logTwoFactorAuthDisabled(String userId, String username, String ipAddress) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.TWO_FACTOR_DISABLED.name())
                .userId(userId)
                .username(username)
                .ipAddress(ipAddress)
                .description("Two-factor authentication disabled")
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.HIGH.name())
                .build();

        auditEventRepository.save(event);
        log.warn("Audit: 2FA disabled for user: {}", username);
    }

    /**
     * Log backup codes generation event
     */
    public void logBackupCodesGenerated(String userId, String username, String ipAddress) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.TWO_FACTOR_BACKUP_CODES_GENERATED.name())
                .userId(userId)
                .username(username)
                .ipAddress(ipAddress)
                .description("New backup codes generated")
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.MEDIUM.name())
                .build();

        auditEventRepository.save(event);
        log.info("Audit: Backup codes generated for user: {}", username);
    }

    /**
     * Log account lockout event
     */
    public void logAccountLocked(String userId, String username, String ipAddress, String reason) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.ACCOUNT_LOCKED.name())
                .userId(userId)
                .username(username)
                .ipAddress(ipAddress)
                .description("Account locked: " + reason)
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.HIGH.name())
                .build();

        auditEventRepository.save(event);
        log.warn("Audit: Account locked for user: {} - Reason: {}", username, reason);
    }

    /**
     * Log account unlock event
     */
    public void logAccountUnlocked(String userId, String username) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.ACCOUNT_UNLOCKED.name())
                .userId(userId)
                .username(username)
                .description("Account unlocked")
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.MEDIUM.name())
                .build();

        auditEventRepository.save(event);
        log.info("Audit: Account unlocked for user: {}", username);
    }

    /**
     * Log OAuth2 client creation event
     */
    public void logClientCreated(String clientId, String adminUserId, String adminUsername, String ipAddress) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.CLIENT_CREATED.name())
                .userId(adminUserId)
                .username(adminUsername)
                .ipAddress(ipAddress)
                .description("OAuth2 client created: " + clientId)
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.HIGH.name())
                .details(clientId)
                .build();

        auditEventRepository.save(event);
        log.info("Audit: OAuth2 client created: {} by user: {}", clientId, adminUsername);
    }

    /**
     * Log OAuth2 client update event
     */
    public void logClientUpdated(String clientId, String adminUserId, String adminUsername, String ipAddress) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.CLIENT_UPDATED.name())
                .userId(adminUserId)
                .username(adminUsername)
                .ipAddress(ipAddress)
                .description("OAuth2 client updated: " + clientId)
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.MEDIUM.name())
                .details(clientId)
                .build();

        auditEventRepository.save(event);
        log.info("Audit: OAuth2 client updated: {} by user: {}", clientId, adminUsername);
    }

    /**
     * Log OAuth2 client deletion event
     */
    public void logClientDeleted(String clientId, String adminUserId, String adminUsername, String ipAddress) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.CLIENT_DELETED.name())
                .userId(adminUserId)
                .username(adminUsername)
                .ipAddress(ipAddress)
                .description("OAuth2 client deleted: " + clientId)
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.HIGH.name())
                .details(clientId)
                .build();

        auditEventRepository.save(event);
        log.warn("Audit: OAuth2 client deleted: {} by user: {}", clientId, adminUsername);
    }

    /**
     * Log client secret regeneration event
     */
    public void logClientSecretRegenerated(String clientId, String adminUserId, String adminUsername, String ipAddress) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.CLIENT_SECRET_REGENERATED.name())
                .userId(adminUserId)
                .username(adminUsername)
                .ipAddress(ipAddress)
                .description("Client secret regenerated: " + clientId)
                .status(SecurityAuditEvent.Status.SUCCESS.name())
                .severity(SecurityAuditEvent.Severity.HIGH.name())
                .details(clientId)
                .build();

        auditEventRepository.save(event);
        log.warn("Audit: Client secret regenerated for: {} by user: {}", clientId, adminUsername);
    }

    /**
     * Log unauthorized access attempt
     */
    public void logUnauthorizedAccessAttempt(String endpoint, String username, String ipAddress, String reason) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.UNAUTHORIZED_ACCESS_ATTEMPT.name())
                .username(username)
                .ipAddress(ipAddress)
                .description("Unauthorized access attempt to: " + endpoint + " - " + reason)
                .status(SecurityAuditEvent.Status.FAILURE.name())
                .severity(SecurityAuditEvent.Severity.CRITICAL.name())
                .errorMessage(reason)
                .build();

        auditEventRepository.save(event);
        log.error("Audit: CRITICAL - Unauthorized access attempt to {} by {} from IP: {} - Reason: {}", endpoint, username, ipAddress, reason);
    }

    /**
     * Log suspicious activity
     */
    public void logSuspiciousActivity(String username, String ipAddress, String description) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
                .eventType(SecurityAuditEvent.EventType.SUSPICIOUS_ACTIVITY_DETECTED.name())
                .username(username)
                .ipAddress(ipAddress)
                .description(description)
                .status(SecurityAuditEvent.Status.FAILURE.name())
                .severity(SecurityAuditEvent.Severity.CRITICAL.name())
                .build();

        auditEventRepository.save(event);
        log.error("Audit: CRITICAL - Suspicious activity detected: {} from IP: {}", description, ipAddress);
    }

    /**
     * Get all events for a specific user
     */
    public List<SecurityAuditEvent> getUserAuditLog(String userId) {
        return auditEventRepository.findByUserIdOrderByEventTimeDesc(userId);
    }

    /**
     * Get high-severity events
     */
    public List<SecurityAuditEvent> getHighSeverityEvents() {
        return auditEventRepository.findHighSeverityEvents();
    }

    /**
     * Get recent failed login attempts for a user
     */
    public long getRecentFailedLoginCount(String username, int minutesBack) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(minutesBack);
        return auditEventRepository.countRecentFailedLogins(username, since);
    }

    /**
     * Get recent event count from IP
     */
    public long getRecentEventCountByIp(String ipAddress, int minutesBack) {
        LocalDateTime since = LocalDateTime.now().minusMinutes(minutesBack);
        return auditEventRepository.countRecentEventsByIp(ipAddress, since);
    }
}
