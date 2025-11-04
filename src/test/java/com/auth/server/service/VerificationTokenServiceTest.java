package com.auth.server.service;

import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.entity.VerificationToken;
import com.auth.server.exception.ResourceNotFoundException;
import com.auth.server.repository.VerificationTokenRepository;
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
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for VerificationTokenService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("VerificationTokenService Tests")
public class VerificationTokenServiceTest {

    @Mock
    private VerificationTokenRepository verificationTokenRepository;

    @InjectMocks
    private VerificationTokenService verificationTokenService;

    private User testUser;
    private VerificationToken verificationToken;

    @BeforeEach
    void setUp() {
        // Set expiration values via reflection (since they're @Value injected)
        ReflectionTestUtils.setField(verificationTokenService, "emailVerificationExpirationHours", 24);
        ReflectionTestUtils.setField(verificationTokenService, "passwordResetExpirationHours", 1);

        Role userRole = Role.builder()
                .id(1L)
                .name("ROLE_USER")
                .description("Standard user role")
                .build();

        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(false)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();

        verificationToken = VerificationToken.builder()
                .token("test-token-123456789")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .expiryDate(LocalDateTime.now().plusHours(24))
                .build();
    }

    @Test
    @DisplayName("Should create email verification token")
    void testCreateEmailVerificationToken() {
        // Given
        when(verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.empty());
        when(verificationTokenRepository.save(any(VerificationToken.class)))
                .thenReturn(verificationToken);

        // When
        VerificationToken createdToken = verificationTokenService.createEmailVerificationToken(testUser);

        // Then
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getUser()).isEqualTo(testUser);
        assertThat(createdToken.getTokenType()).isEqualTo(VerificationToken.TokenType.EMAIL_VERIFICATION);
        verify(verificationTokenRepository, times(1)).save(any(VerificationToken.class));
    }

    @Test
    @DisplayName("Should create password reset token")
    void testCreatePasswordResetToken() {
        // Given
        VerificationToken resetToken = VerificationToken.builder()
                .token("reset-token-123456789")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .expiryDate(LocalDateTime.now().plusHours(1))
                .build();

        when(verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.PASSWORD_RESET))
                .thenReturn(Optional.empty());
        when(verificationTokenRepository.save(any(VerificationToken.class)))
                .thenReturn(resetToken);

        // When
        VerificationToken createdToken = verificationTokenService.createPasswordResetToken(testUser);

        // Then
        assertThat(createdToken).isNotNull();
        assertThat(createdToken.getTokenType()).isEqualTo(VerificationToken.TokenType.PASSWORD_RESET);
        verify(verificationTokenRepository, times(1)).save(any(VerificationToken.class));
    }

    @Test
    @DisplayName("Should verify valid token")
    void testVerifyValidToken() {
        // Given
        when(verificationTokenRepository.findByToken("test-token-123456789"))
                .thenReturn(Optional.of(verificationToken));

        // When
        VerificationToken verifiedToken = verificationTokenService.verifyToken("test-token-123456789");

        // Then
        assertThat(verifiedToken).isEqualTo(verificationToken);
        verify(verificationTokenRepository, times(1)).findByToken("test-token-123456789");
    }

    @Test
    @DisplayName("Should throw exception when token not found")
    void testVerifyTokenNotFound() {
        // Given
        when(verificationTokenRepository.findByToken("nonexistent-token"))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> verificationTokenService.verifyToken("nonexistent-token"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("Invalid verification token");
    }

    @Test
    @DisplayName("Should throw exception when token is expired")
    void testVerifyExpiredToken() {
        // Given
        VerificationToken expiredToken = VerificationToken.builder()
                .token("expired-token")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .expiryDate(LocalDateTime.now().minusHours(1))  // Expired 1 hour ago
                .build();

        when(verificationTokenRepository.findByToken("expired-token"))
                .thenReturn(Optional.of(expiredToken));

        // When & Then
        assertThatThrownBy(() -> verificationTokenService.verifyToken("expired-token"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("expired");
    }

    @Test
    @DisplayName("Should throw exception when token already confirmed")
    void testVerifyConfirmedToken() {
        // Given
        verificationToken.confirm();
        when(verificationTokenRepository.findByToken("test-token-123456789"))
                .thenReturn(Optional.of(verificationToken));

        // When & Then
        assertThatThrownBy(() -> verificationTokenService.verifyToken("test-token-123456789"))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("already been used");
    }

    @Test
    @DisplayName("Should confirm token")
    void testConfirmToken() {
        // Given
        assertThat(verificationToken.isConfirmed()).isFalse();
        when(verificationTokenRepository.save(verificationToken))
                .thenReturn(verificationToken);

        // When
        verificationTokenService.confirmToken(verificationToken);

        // Then
        assertThat(verificationToken.isConfirmed()).isTrue();
        verify(verificationTokenRepository, times(1)).save(verificationToken);
    }

    @Test
    @DisplayName("Should get valid token by user and type")
    void testGetValidToken() {
        // Given
        when(verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.of(verificationToken));

        // When
        VerificationToken foundToken = verificationTokenService.getValidToken(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION);

        // Then
        assertThat(foundToken).isEqualTo(verificationToken);
        verify(verificationTokenRepository, times(1)).findByUserAndTokenType(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION);
    }

    @Test
    @DisplayName("Should throw exception when no token found for user")
    void testGetValidTokenNotFound() {
        // Given
        when(verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> verificationTokenService.getValidToken(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("No verification token found");
    }

    @Test
    @DisplayName("Should throw exception when token is expired for user")
    void testGetValidTokenExpired() {
        // Given
        VerificationToken expiredToken = VerificationToken.builder()
                .token("expired-token")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .expiryDate(LocalDateTime.now().minusHours(1))
                .build();

        when(verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.of(expiredToken));

        // When & Then
        assertThatThrownBy(() -> verificationTokenService.getValidToken(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION))
                .isInstanceOf(ResourceNotFoundException.class)
                .hasMessageContaining("not valid");
    }

    @Test
    @DisplayName("Should clean up expired tokens")
    void testCleanupExpiredTokens() {
        // When
        verificationTokenService.cleanupExpiredTokens();

        // Then
        verify(verificationTokenRepository, times(1)).deleteExpiredTokens(any(LocalDateTime.class));
    }

    @Test
    @DisplayName("Should check token is valid")
    void testTokenValid() {
        // Given
        assertThat(verificationToken.isValid()).isTrue();
        assertThat(verificationToken.isExpired()).isFalse();
        assertThat(verificationToken.isConfirmed()).isFalse();
    }

    @Test
    @DisplayName("Should invalidate existing tokens before creating new one")
    void testInvalidateExistingTokens() {
        // Given
        VerificationToken existingToken = VerificationToken.builder()
                .token("old-token")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .expiryDate(LocalDateTime.now().plusHours(24))
                .build();

        when(verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION))
                .thenReturn(Optional.of(existingToken));
        when(verificationTokenRepository.save(any(VerificationToken.class)))
                .thenReturn(verificationToken);

        // When
        VerificationToken newToken = verificationTokenService.createEmailVerificationToken(testUser);

        // Then
        assertThat(newToken).isNotNull();
        verify(verificationTokenRepository, times(2)).save(any(VerificationToken.class));
    }
}
