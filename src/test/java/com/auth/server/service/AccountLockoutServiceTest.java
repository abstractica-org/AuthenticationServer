package com.auth.server.service;

import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AccountLockoutService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AccountLockoutService Tests")
public class AccountLockoutServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuditService auditService;

    @InjectMocks
    private AccountLockoutService accountLockoutService;

    private User testUser;
    private Role userRole;

    @BeforeEach
    void setUp() {
        // Set configuration values via reflection
        ReflectionTestUtils.setField(accountLockoutService, "lockoutThreshold", 5);
        ReflectionTestUtils.setField(accountLockoutService, "lockoutDurationMinutes", 30);

        userRole = Role.builder()
                .id(1L)
                .name("ROLE_USER")
                .description("Standard user role")
                .build();

        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .lastLogin(LocalDateTime.now())
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
    }

    @Test
    @DisplayName("Should not lock unlocked account")
    void testIsAccountLockedWhenNotLocked() {
        // Given
        testUser.setLocked(false);

        // When
        boolean isLocked = accountLockoutService.isAccountLocked(testUser);

        // Then
        assertThat(isLocked).isFalse();
    }

    @Test
    @DisplayName("Should return true when account is locked and lockout not expired")
    void testIsAccountLockedWithValidLockout() {
        // Given
        testUser.setLocked(true);
        testUser.setLastLogin(LocalDateTime.now().minusMinutes(5));

        // When
        boolean isLocked = accountLockoutService.isAccountLocked(testUser);

        // Then
        assertThat(isLocked).isTrue();
    }

    @Test
    @DisplayName("Should auto-unlock account when lockout period expired")
    void testAutoUnlockAccountOnExpiry() {
        // Given
        testUser.setLocked(true);
        testUser.setLastLogin(LocalDateTime.now().minusMinutes(31));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        boolean isLocked = accountLockoutService.isAccountLocked(testUser);

        // Then
        assertThat(isLocked).isFalse();
        assertThat(testUser.getLocked()).isFalse();
        verify(userRepository, times(1)).save(testUser);
        verify(auditService, times(1)).logAccountUnlocked(testUser.getId().toString(), testUser.getUsername());
    }

    @Test
    @DisplayName("Should lock account successfully")
    void testLockAccount() {
        // Given
        testUser.setLocked(false);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        accountLockoutService.lockAccount(testUser, "192.168.1.1");

        // Then
        assertThat(testUser.getLocked()).isTrue();
        verify(userRepository, times(1)).save(testUser);
        verify(auditService, times(1)).logAccountLocked(
                testUser.getId().toString(),
                testUser.getUsername(),
                "192.168.1.1",
                "Excessive failed login attempts"
        );
    }

    @Test
    @DisplayName("Should lock account without IP address")
    void testLockAccountWithoutIpAddress() {
        // Given
        testUser.setLocked(false);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        accountLockoutService.lockAccount(testUser);

        // Then
        assertThat(testUser.getLocked()).isTrue();
        verify(userRepository, times(1)).save(testUser);
        verify(auditService, times(1)).logAccountLocked(
                testUser.getId().toString(),
                testUser.getUsername(),
                "unknown",
                "Excessive failed login attempts"
        );
    }

    @Test
    @DisplayName("Should unlock account successfully")
    void testUnlockAccount() {
        // Given
        testUser.setLocked(true);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        accountLockoutService.unlockAccount(testUser, "192.168.1.1");

        // Then
        assertThat(testUser.getLocked()).isFalse();
        verify(userRepository, times(1)).save(testUser);
        verify(auditService, times(1)).logAccountUnlocked(
                testUser.getId().toString(),
                testUser.getUsername()
        );
    }

    @Test
    @DisplayName("Should unlock account without IP address")
    void testUnlockAccountWithoutIpAddress() {
        // Given
        testUser.setLocked(true);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        accountLockoutService.unlockAccount(testUser);

        // Then
        assertThat(testUser.getLocked()).isFalse();
        verify(userRepository, times(1)).save(testUser);
    }

    @Test
    @DisplayName("Should return true when threshold exceeded")
    void testHasExceededThreshold() {
        // Given
        long failedAttempts = 5;

        // When
        boolean exceeded = accountLockoutService.hasExceededThreshold(failedAttempts);

        // Then
        assertThat(exceeded).isTrue();
    }

    @Test
    @DisplayName("Should return true when failed attempts exceed threshold")
    void testHasExceededThresholdWithMoreAttempts() {
        // Given
        long failedAttempts = 10;

        // When
        boolean exceeded = accountLockoutService.hasExceededThreshold(failedAttempts);

        // Then
        assertThat(exceeded).isTrue();
    }

    @Test
    @DisplayName("Should return false when threshold not exceeded")
    void testHasNotExceededThreshold() {
        // Given
        long failedAttempts = 3;

        // When
        boolean exceeded = accountLockoutService.hasExceededThreshold(failedAttempts);

        // Then
        assertThat(exceeded).isFalse();
    }

    @Test
    @DisplayName("Should return false for zero failed attempts")
    void testZeroFailedAttempts() {
        // Given
        long failedAttempts = 0;

        // When
        boolean exceeded = accountLockoutService.hasExceededThreshold(failedAttempts);

        // Then
        assertThat(exceeded).isFalse();
    }

    @Test
    @DisplayName("Should return lockout threshold configuration")
    void testGetLockoutThreshold() {
        // When
        int threshold = accountLockoutService.getLockoutThreshold();

        // Then
        assertThat(threshold).isEqualTo(5);
    }

    @Test
    @DisplayName("Should return lockout duration configuration")
    void testGetLockoutDurationMinutes() {
        // When
        int duration = accountLockoutService.getLockoutDurationMinutes();

        // Then
        assertThat(duration).isEqualTo(30);
    }

    @Test
    @DisplayName("Should handle account with no last login")
    void testAccountLockedWithNoLastLogin() {
        // Given
        testUser.setLocked(true);
        testUser.setLastLogin(null);

        // When
        boolean isLocked = accountLockoutService.isAccountLocked(testUser);

        // Then
        assertThat(isLocked).isTrue();
    }

    @Test
    @DisplayName("Should correctly check lockout expiry boundary")
    void testLockoutExpiryBoundary() {
        // Given
        testUser.setLocked(true);
        // Exactly 30 minutes ago
        testUser.setLastLogin(LocalDateTime.now().minusMinutes(30));
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        boolean isLocked = accountLockoutService.isAccountLocked(testUser);

        // Then
        // Should be auto-unlocked since 30 minutes have passed
        assertThat(testUser.getLocked()).isFalse();
    }

    @Test
    @DisplayName("Should respect threshold configuration in has exceeded check")
    void testThresholdRespectConfiguration() {
        // Given
        // Change threshold to 10 via reflection
        ReflectionTestUtils.setField(accountLockoutService, "lockoutThreshold", 10);

        // When
        boolean exceeded5 = accountLockoutService.hasExceededThreshold(5);
        boolean exceeded10 = accountLockoutService.hasExceededThreshold(10);

        // Then
        assertThat(exceeded5).isFalse();
        assertThat(exceeded10).isTrue();
    }

    @Test
    @DisplayName("Should log account lock with detailed information")
    void testAccountLockLoggedWithDetails() {
        // Given
        testUser.setLocked(false);
        String ipAddress = "203.0.113.45";
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        accountLockoutService.lockAccount(testUser, ipAddress);

        // Then
        verify(auditService, times(1)).logAccountLocked(
                testUser.getId().toString(),
                "testuser",
                ipAddress,
                "Excessive failed login attempts"
        );
    }

    @Test
    @DisplayName("Should log account unlock with details")
    void testAccountUnlockLoggedWithDetails() {
        // Given
        testUser.setLocked(true);
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When
        accountLockoutService.unlockAccount(testUser, "203.0.113.45");

        // Then
        verify(auditService, times(1)).logAccountUnlocked(
                testUser.getId().toString(),
                "testuser"
        );
    }

    @Test
    @DisplayName("Should handle multiple lock/unlock operations")
    void testMultipleLockUnlockOperations() {
        // Given
        when(userRepository.save(testUser)).thenReturn(testUser);

        // When & Then
        // Lock
        accountLockoutService.lockAccount(testUser);
        assertThat(testUser.getLocked()).isTrue();

        // Unlock
        accountLockoutService.unlockAccount(testUser);
        assertThat(testUser.getLocked()).isFalse();

        // Lock again
        accountLockoutService.lockAccount(testUser);
        assertThat(testUser.getLocked()).isTrue();

        verify(userRepository, times(3)).save(testUser);
    }
}
