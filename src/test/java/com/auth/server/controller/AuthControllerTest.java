package com.auth.server.controller;

import com.auth.server.AbstractTest;
import com.auth.server.config.TestConfig;
import com.auth.server.dto.ForgotPasswordRequest;
import com.auth.server.dto.RegisterRequest;
import com.auth.server.dto.ResetPasswordRequest;
import com.auth.server.dto.VerifyEmailRequest;
import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.entity.VerificationToken;
import com.auth.server.repository.RoleRepository;
import com.auth.server.repository.UserRepository;
import com.auth.server.repository.VerificationTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for AuthController.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestConfig.class)
@DisplayName("AuthController Integration Tests")
public class AuthControllerTest extends AbstractTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    private Role userRole;

    @BeforeEach
    void setUp() {
        verificationTokenRepository.deleteAll();
        userRepository.deleteAll();
        roleRepository.deleteAll();

        userRole = roleRepository.save(Role.builder()
                .name("ROLE_USER")
                .description("Standard user role")
                .build());
    }

    @Test
    @DisplayName("Should register user successfully")
    void testRegisterUserSuccess() throws Exception {
        // Given
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("Test@1234")
                .passwordConfirm("Test@1234")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(registerRequest)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.user.username").value("newuser"))
                .andExpect(jsonPath("$.user.email").value("newuser@example.com"))
                .andExpect(jsonPath("$.requires_email_verification").value(true));

        // Verify user was created
        Optional<User> createdUser = userRepository.findByUsername("newuser");
        assertThat(createdUser).isPresent();
        assertThat(createdUser.get().getEmail()).isEqualTo("newuser@example.com");
    }

    @Test
    @DisplayName("Should fail registration with duplicate username")
    void testRegisterUserWithDuplicateUsername() throws Exception {
        // Given - Create existing user
        User existingUser = User.builder()
                .username("existinguser")
                .email("existing@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(false)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(existingUser);

        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("existinguser")
                .email("different@example.com")
                .password("Test@1234")
                .passwordConfirm("Test@1234")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(registerRequest)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Username already exists"));
    }

    @Test
    @DisplayName("Should fail registration with duplicate email")
    void testRegisterUserWithDuplicateEmail() throws Exception {
        // Given - Create existing user
        User existingUser = User.builder()
                .username("existinguser")
                .email("existing@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(false)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(existingUser);

        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("existing@example.com")
                .password("Test@1234")
                .passwordConfirm("Test@1234")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(registerRequest)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.message").value("Email already exists"));
    }

    @Test
    @DisplayName("Should fail registration with weak password")
    void testRegisterUserWithWeakPassword() throws Exception {
        // Given - Password without special character
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("weak1234")  // Missing special character
                .passwordConfirm("weak1234")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(registerRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    @DisplayName("Should fail registration with mismatched passwords")
    void testRegisterUserWithMismatchedPasswords() throws Exception {
        // Given
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("Test@1234")
                .passwordConfirm("Different@1234")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(registerRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.passwordValid").exists());
    }

    @Test
    @DisplayName("Should verify email with valid token")
    void testVerifyEmailSuccess() throws Exception {
        // Given - Create user and verification token
        User user = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(false)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(user);

        VerificationToken token = VerificationToken.builder()
                .token("verification-token-123")
                .user(user)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .expiryDate(LocalDateTime.now().plusHours(24))
                .build();
        verificationTokenRepository.save(token);

        VerifyEmailRequest verifyRequest = VerifyEmailRequest.builder()
                .token("verification-token-123")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/verify-email")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(verifyRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Email verified successfully"));

        // Verify user email is now verified
        User verifiedUser = userRepository.findByUsername("testuser").get();
        assertThat(verifiedUser.getEmailVerified()).isTrue();
    }

    @Test
    @DisplayName("Should fail verification with invalid token")
    void testVerifyEmailWithInvalidToken() throws Exception {
        // Given
        VerifyEmailRequest verifyRequest = VerifyEmailRequest.builder()
                .token("invalid-token")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/verify-email")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(verifyRequest)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Invalid verification token"));
    }

    @Test
    @DisplayName("Should fail verification with expired token")
    void testVerifyEmailWithExpiredToken() throws Exception {
        // Given - Create user and expired verification token
        User user = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(false)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(user);

        VerificationToken token = VerificationToken.builder()
                .token("expired-token-123")
                .user(user)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .expiryDate(LocalDateTime.now().minusHours(1))  // Expired
                .build();
        verificationTokenRepository.save(token);

        VerifyEmailRequest verifyRequest = VerifyEmailRequest.builder()
                .token("expired-token-123")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/verify-email")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(verifyRequest)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value(containsString("expired")));
    }

    @Test
    @DisplayName("Should request password reset successfully")
    void testForgotPasswordSuccess() throws Exception {
        // Given - Create user
        User user = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(user);

        ForgotPasswordRequest forgotRequest = ForgotPasswordRequest.builder()
                .email("test@example.com")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/forgot-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(forgotRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password reset email sent successfully"));

        // Verify reset token was created
        Optional<VerificationToken> resetToken = verificationTokenRepository.findByUserAndTokenType(user, VerificationToken.TokenType.PASSWORD_RESET);
        assertThat(resetToken).isPresent();
        assertThat(resetToken.get().getTokenType()).isEqualTo(VerificationToken.TokenType.PASSWORD_RESET);
    }

    @Test
    @DisplayName("Should fail password reset request with non-existent email")
    void testForgotPasswordWithNonExistentEmail() throws Exception {
        // Given
        ForgotPasswordRequest forgotRequest = ForgotPasswordRequest.builder()
                .email("nonexistent@example.com")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/forgot-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(forgotRequest)))
                .andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("Should reset password with valid token")
    void testResetPasswordSuccess() throws Exception {
        // Given - Create user and reset token
        User user = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$oldhashedPassword")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(user);

        VerificationToken resetToken = VerificationToken.builder()
                .token("reset-token-123")
                .user(user)
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .expiryDate(LocalDateTime.now().plusHours(1))
                .build();
        verificationTokenRepository.save(resetToken);

        ResetPasswordRequest resetRequest = ResetPasswordRequest.builder()
                .token("reset-token-123")
                .newPassword("NewPassword@123")
                .newPasswordConfirm("NewPassword@123")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(resetRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Password reset successfully"));

        // Verify password was updated (hash should be different)
        User updatedUser = userRepository.findByUsername("testuser").get();
        assertThat(updatedUser.getPasswordHash()).isNotEqualTo("$2a$13$oldhashedPassword");
    }

    @Test
    @DisplayName("Should fail password reset with invalid token")
    void testResetPasswordWithInvalidToken() throws Exception {
        // Given
        ResetPasswordRequest resetRequest = ResetPasswordRequest.builder()
                .token("invalid-token")
                .newPassword("NewPassword@123")
                .newPasswordConfirm("NewPassword@123")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(resetRequest)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.message").value("Invalid verification token"));
    }

    @Test
    @DisplayName("Should fail password reset with weak password")
    void testResetPasswordWithWeakPassword() throws Exception {
        // Given
        ResetPasswordRequest resetRequest = ResetPasswordRequest.builder()
                .token("reset-token-123")
                .newPassword("weakpassword")
                .newPasswordConfirm("weakpassword")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(resetRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.newPassword").exists());
    }

    @Test
    @DisplayName("Should fail password reset with mismatched passwords")
    void testResetPasswordWithMismatchedPasswords() throws Exception {
        // Given
        ResetPasswordRequest resetRequest = ResetPasswordRequest.builder()
                .token("reset-token-123")
                .newPassword("NewPassword@123")
                .newPasswordConfirm("Different@123")
                .build();

        // When & Then
        mockMvc.perform(post("/api/auth/reset-password")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(resetRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.passwordValid").exists());
    }

    @Test
    @DisplayName("Should resend verification email")
    void testResendVerificationEmailSuccess() throws Exception {
        // Given - Create unverified user
        User user = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(false)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(user);

        // When & Then
        mockMvc.perform(post("/api/auth/resend-verification")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(new com.auth.server.dto.ResendVerificationRequest("test@example.com"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Verification email sent successfully"));

        // Verify new verification token was created
        Optional<VerificationToken> token = verificationTokenRepository.findByUserAndTokenType(user, VerificationToken.TokenType.EMAIL_VERIFICATION);
        assertThat(token).isPresent();
    }

    @Test
    @DisplayName("Should indicate already verified email on resend")
    void testResendVerificationEmailAlreadyVerified() throws Exception {
        // Given - Create verified user
        User user = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(true)  // Already verified
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(user);

        // When & Then
        mockMvc.perform(post("/api/auth/resend-verification")
                .contentType(MediaType.APPLICATION_JSON)
                .content(toJsonString(new com.auth.server.dto.ResendVerificationRequest("test@example.com"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Email is already verified"));
    }
}
