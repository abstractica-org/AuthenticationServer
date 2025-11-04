package com.auth.server.service;

import com.auth.server.entity.SecurityAuditEvent;
import com.auth.server.repository.SecurityAuditEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuditService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AuditService Tests")
public class AuditServiceTest {

    @Mock
    private SecurityAuditEventRepository auditEventRepository;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private AuditService auditService;

    private String userId;
    private String username;
    private String ipAddress;

    @BeforeEach
    void setUp() {
        userId = UUID.randomUUID().toString();
        username = "testuser";
        ipAddress = "192.168.1.1";
    }

    @Test
    @DisplayName("Should log successful authentication event")
    void testLogSuccessfulAuthentication() {
        // Given
        boolean success = true;

        // When
        auditService.logAuthenticationEvent(username, userId, ipAddress, "Mozilla/5.0", success);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.LOGIN_SUCCESS.name());
        assertThat(savedEvent.getUsername()).isEqualTo(username);
        assertThat(savedEvent.getUserId()).isEqualTo(userId);
        assertThat(savedEvent.getIpAddress()).isEqualTo(ipAddress);
        assertThat(savedEvent.getStatus()).isEqualTo(SecurityAuditEvent.Status.SUCCESS.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.MEDIUM.name());
    }

    @Test
    @DisplayName("Should log failed authentication event")
    void testLogFailedAuthentication() {
        // Given
        boolean success = false;

        // When
        auditService.logAuthenticationEvent(username, userId, ipAddress, "Mozilla/5.0", success);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.LOGIN_FAILURE.name());
        assertThat(savedEvent.getStatus()).isEqualTo(SecurityAuditEvent.Status.FAILURE.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.HIGH.name());
    }

    @Test
    @DisplayName("Should log password change event")
    void testLogPasswordChangeEvent() {
        // Given
        boolean success = true;

        // When
        auditService.logPasswordChangeEvent(userId, username, ipAddress, success);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.PASSWORD_CHANGED.name());
        assertThat(savedEvent.getStatus()).isEqualTo(SecurityAuditEvent.Status.SUCCESS.name());
    }

    @Test
    @DisplayName("Should log password reset request")
    void testLogPasswordResetRequest() {
        // Given
        String email = "test@example.com";

        // When
        auditService.logPasswordResetRequest(email, ipAddress);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.PASSWORD_RESET_REQUESTED.name());
        assertThat(savedEvent.getUsername()).isEqualTo(email);
        assertThat(savedEvent.getIpAddress()).isEqualTo(ipAddress);
    }

    @Test
    @DisplayName("Should log password reset completion")
    void testLogPasswordResetCompleted() {
        // Given
        boolean success = true;

        // When
        auditService.logPasswordResetCompleted(username, userId, ipAddress, success);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.PASSWORD_RESET_COMPLETED.name());
        assertThat(savedEvent.getStatus()).isEqualTo(SecurityAuditEvent.Status.SUCCESS.name());
    }

    @Test
    @DisplayName("Should log 2FA enabled event")
    void testLogTwoFactorAuthEnabled() {
        // When
        auditService.logTwoFactorAuthEnabled(userId, username, ipAddress);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.TWO_FACTOR_ENABLED.name());
        assertThat(savedEvent.getStatus()).isEqualTo(SecurityAuditEvent.Status.SUCCESS.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.MEDIUM.name());
    }

    @Test
    @DisplayName("Should log 2FA disabled event")
    void testLogTwoFactorAuthDisabled() {
        // When
        auditService.logTwoFactorAuthDisabled(userId, username, ipAddress);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.TWO_FACTOR_DISABLED.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.HIGH.name());
    }

    @Test
    @DisplayName("Should log backup codes generated")
    void testLogBackupCodesGenerated() {
        // When
        auditService.logBackupCodesGenerated(userId, username, ipAddress);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.TWO_FACTOR_BACKUP_CODES_GENERATED.name());
    }

    @Test
    @DisplayName("Should log account locked event")
    void testLogAccountLocked() {
        // Given
        String reason = "Excessive failed login attempts";

        // When
        auditService.logAccountLocked(userId, username, ipAddress, reason);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.ACCOUNT_LOCKED.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.HIGH.name());
        assertThat(savedEvent.getDescription()).contains(reason);
    }

    @Test
    @DisplayName("Should log account unlocked event")
    void testLogAccountUnlocked() {
        // When
        auditService.logAccountUnlocked(userId, username);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.ACCOUNT_UNLOCKED.name());
        assertThat(savedEvent.getStatus()).isEqualTo(SecurityAuditEvent.Status.SUCCESS.name());
    }

    @Test
    @DisplayName("Should log OAuth2 client created event")
    void testLogClientCreated() {
        // Given
        String clientId = "test-client-123";

        // When
        auditService.logClientCreated(clientId, userId, username, ipAddress);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.CLIENT_CREATED.name());
        assertThat(savedEvent.getDescription()).contains(clientId);
        assertThat(savedEvent.getDetails()).isEqualTo(clientId);
    }

    @Test
    @DisplayName("Should log OAuth2 client updated event")
    void testLogClientUpdated() {
        // Given
        String clientId = "test-client-123";

        // When
        auditService.logClientUpdated(clientId, userId, username, ipAddress);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.CLIENT_UPDATED.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.MEDIUM.name());
    }

    @Test
    @DisplayName("Should log OAuth2 client deleted event")
    void testLogClientDeleted() {
        // Given
        String clientId = "test-client-123";

        // When
        auditService.logClientDeleted(clientId, userId, username, ipAddress);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.CLIENT_DELETED.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.HIGH.name());
    }

    @Test
    @DisplayName("Should log client secret regenerated event")
    void testLogClientSecretRegenerated() {
        // Given
        String clientId = "test-client-123";

        // When
        auditService.logClientSecretRegenerated(clientId, userId, username, ipAddress);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.CLIENT_SECRET_REGENERATED.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.HIGH.name());
    }

    @Test
    @DisplayName("Should log unauthorized access attempt")
    void testLogUnauthorizedAccessAttempt() {
        // Given
        String endpoint = "/api/admin/clients";
        String reason = "User lacks required role";

        // When
        auditService.logUnauthorizedAccessAttempt(endpoint, username, ipAddress, reason);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.UNAUTHORIZED_ACCESS_ATTEMPT.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.CRITICAL.name());
        assertThat(savedEvent.getStatus()).isEqualTo(SecurityAuditEvent.Status.FAILURE.name());
    }

    @Test
    @DisplayName("Should log suspicious activity")
    void testLogSuspiciousActivity() {
        // Given
        String description = "Multiple failed login attempts from different IPs";

        // When
        auditService.logSuspiciousActivity(username, ipAddress, description);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository, times(1)).save(eventCaptor.capture());

        SecurityAuditEvent savedEvent = eventCaptor.getValue();
        assertThat(savedEvent.getEventType()).isEqualTo(SecurityAuditEvent.EventType.SUSPICIOUS_ACTIVITY_DETECTED.name());
        assertThat(savedEvent.getSeverity()).isEqualTo(SecurityAuditEvent.Severity.CRITICAL.name());
    }

    @Test
    @DisplayName("Should retrieve user audit log")
    void testGetUserAuditLog() {
        // Given
        List<SecurityAuditEvent> mockEvents = new ArrayList<>();
        when(auditEventRepository.findByUserIdOrderByEventTimeDesc(userId))
                .thenReturn(mockEvents);

        // When
        List<SecurityAuditEvent> events = auditService.getUserAuditLog(userId);

        // Then
        assertThat(events).isEqualTo(mockEvents);
        verify(auditEventRepository, times(1)).findByUserIdOrderByEventTimeDesc(userId);
    }

    @Test
    @DisplayName("Should retrieve high severity events")
    void testGetHighSeverityEvents() {
        // Given
        List<SecurityAuditEvent> mockEvents = new ArrayList<>();
        when(auditEventRepository.findHighSeverityEvents())
                .thenReturn(mockEvents);

        // When
        List<SecurityAuditEvent> events = auditService.getHighSeverityEvents();

        // Then
        assertThat(events).isEqualTo(mockEvents);
        verify(auditEventRepository, times(1)).findHighSeverityEvents();
    }

    @Test
    @DisplayName("Should count recent failed logins for user")
    void testGetRecentFailedLoginCount() {
        // Given
        when(auditEventRepository.countRecentFailedLogins(eq(username), any(LocalDateTime.class)))
                .thenReturn(3L);

        // When
        long count = auditService.getRecentFailedLoginCount(username, 15);

        // Then
        assertThat(count).isEqualTo(3L);
        verify(auditEventRepository, times(1)).countRecentFailedLogins(eq(username), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should count recent events by IP address")
    void testGetRecentEventCountByIp() {
        // Given
        when(auditEventRepository.countRecentEventsByIp(eq(ipAddress), any(LocalDateTime.class)))
                .thenReturn(5L);

        // When
        long count = auditService.getRecentEventCountByIp(ipAddress, 30);

        // Then
        assertThat(count).isEqualTo(5L);
        verify(auditEventRepository, times(1)).countRecentEventsByIp(eq(ipAddress), any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should include user agent in authentication event")
    void testAuthEventIncludesUserAgent() {
        // Given
        String userAgent = "Mozilla/5.0 (Windows NT 10.0)";

        // When
        auditService.logAuthenticationEvent(username, userId, ipAddress, userAgent, true);

        // Then
        ArgumentCaptor<SecurityAuditEvent> eventCaptor = ArgumentCaptor.forClass(SecurityAuditEvent.class);
        verify(auditEventRepository).save(eventCaptor.capture());

        assertThat(eventCaptor.getValue().getUserAgent()).isEqualTo(userAgent);
    }
}
