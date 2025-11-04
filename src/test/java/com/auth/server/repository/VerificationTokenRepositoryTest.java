package com.auth.server.repository;

import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.entity.VerificationToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for VerificationTokenRepository.
 */
@DataJpaTest
@ActiveProfiles("test")
@DisplayName("VerificationTokenRepository Tests")
public class VerificationTokenRepositoryTest {

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    private User testUser;
    private VerificationToken emailVerificationToken;

    @BeforeEach
    void setUp() {
        // Create default role
        Role userRole = roleRepository.save(Role.builder()
                .name("ROLE_USER")
                .description("Standard user role")
                .build());

        // Create test user
        testUser = userRepository.save(User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPasswordHash123456789")
                .emailVerified(false)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build());

        // Create email verification token
        emailVerificationToken = verificationTokenRepository.save(VerificationToken.builder()
                .token("test-token-12345678901234567890")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .expiryDate(LocalDateTime.now().plusHours(24))
                .build());
    }

    @Test
    @DisplayName("Should save and find token by token value")
    void testFindByToken() {
        // When
        Optional<VerificationToken> foundToken = verificationTokenRepository.findByToken("test-token-12345678901234567890");

        // Then
        assertThat(foundToken)
                .isPresent()
                .hasValueSatisfying(token -> {
                    assertThat(token.getToken()).isEqualTo("test-token-12345678901234567890");
                    assertThat(token.getTokenType()).isEqualTo(VerificationToken.TokenType.EMAIL_VERIFICATION);
                });
    }

    @Test
    @DisplayName("Should return empty when token not found")
    void testFindByTokenNotFound() {
        // When
        Optional<VerificationToken> foundToken = verificationTokenRepository.findByToken("nonexistent-token");

        // Then
        assertThat(foundToken).isEmpty();
    }

    @Test
    @DisplayName("Should find token by user and token type")
    void testFindByUserAndTokenType() {
        // When
        Optional<VerificationToken> foundToken = verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.EMAIL_VERIFICATION);

        // Then
        assertThat(foundToken)
                .isPresent()
                .hasValueSatisfying(token -> {
                    assertThat(token.getUser().getId()).isEqualTo(testUser.getId());
                    assertThat(token.getTokenType()).isEqualTo(VerificationToken.TokenType.EMAIL_VERIFICATION);
                });
    }

    @Test
    @DisplayName("Should return empty when user and token type not found")
    void testFindByUserAndTokenTypeNotFound() {
        // When
        Optional<VerificationToken> foundToken = verificationTokenRepository.findByUserAndTokenType(testUser, VerificationToken.TokenType.PASSWORD_RESET);

        // Then
        assertThat(foundToken).isEmpty();
    }

    @Test
    @DisplayName("Should confirm token")
    void testConfirmToken() {
        // When
        emailVerificationToken.confirm();
        verificationTokenRepository.save(emailVerificationToken);

        // Then
        Optional<VerificationToken> confirmedToken = verificationTokenRepository.findByToken("test-token-12345678901234567890");
        assertThat(confirmedToken)
                .isPresent()
                .hasValueSatisfying(token -> assertThat(token.isConfirmed()).isTrue());
    }

    @Test
    @DisplayName("Should check if token is valid")
    void testTokenValidity() {
        // Then
        assertThat(emailVerificationToken.isValid()).isTrue();
        assertThat(emailVerificationToken.isExpired()).isFalse();
        assertThat(emailVerificationToken.isConfirmed()).isFalse();
    }

    @Test
    @DisplayName("Should detect expired token")
    void testExpiredToken() {
        // When
        emailVerificationToken.setExpiryDate(LocalDateTime.now().minusHours(1));
        verificationTokenRepository.save(emailVerificationToken);

        // Then
        Optional<VerificationToken> expiredToken = verificationTokenRepository.findByToken("test-token-12345678901234567890");
        assertThat(expiredToken)
                .isPresent()
                .hasValueSatisfying(token -> {
                    assertThat(token.isExpired()).isTrue();
                    assertThat(token.isValid()).isFalse();
                });
    }

    @Test
    @DisplayName("Should create password reset token")
    void testPasswordResetToken() {
        // When
        VerificationToken resetToken = verificationTokenRepository.save(VerificationToken.builder()
                .token("reset-token-12345678901234567890")
                .user(testUser)
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .expiryDate(LocalDateTime.now().plusHours(1))
                .build());

        // Then
        Optional<VerificationToken> foundToken = verificationTokenRepository.findByToken("reset-token-12345678901234567890");
        assertThat(foundToken)
                .isPresent()
                .hasValueSatisfying(token -> {
                    assertThat(token.getTokenType()).isEqualTo(VerificationToken.TokenType.PASSWORD_RESET);
                    assertThat(token.getUser().getId()).isEqualTo(testUser.getId());
                });
    }

    @Test
    @DisplayName("Should delete token")
    void testDeleteToken() {
        // When
        verificationTokenRepository.delete(emailVerificationToken);

        // Then
        Optional<VerificationToken> deletedToken = verificationTokenRepository.findByToken("test-token-12345678901234567890");
        assertThat(deletedToken).isEmpty();
    }
}
