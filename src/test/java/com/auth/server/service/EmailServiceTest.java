package com.auth.server.service;

import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for EmailService.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("EmailService Tests")
public class EmailServiceTest {

    @Mock
    private JavaMailSender mailSender;

    @InjectMocks
    private EmailService emailService;

    private User testUser;
    private Role userRole;

    @BeforeEach
    void setUp() {
        // Inject configuration values using reflection
        ReflectionTestUtils.setField(emailService, "fromEmail", "noreply@auth-server.com");
        ReflectionTestUtils.setField(emailService, "applicationName", "Authentication Server");

        userRole = Role.builder()
                .id(1L)
                .name("ROLE_USER")
                .description("Standard user role")
                .build();

        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testuser")
                .email("testuser@example.com")
                .passwordHash("$2a$13$hashedPassword")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
    }

    @Test
    @DisplayName("Should send verification email successfully")
    void testSendVerificationEmail() {
        // Given
        String verificationUrl = "https://auth-server.com/verify?token=abc123";

        // When
        emailService.sendVerificationEmail(testUser, "token123", verificationUrl);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(1)).send(messageCaptor.capture());

        SimpleMailMessage sentMessage = messageCaptor.getValue();
        assertThat(sentMessage.getTo()).contains("testuser@example.com");
        assertThat(sentMessage.getFrom()).isEqualTo("noreply@auth-server.com");
        assertThat(sentMessage.getSubject()).contains("Email Verification");
        assertThat(sentMessage.getText()).contains("testuser");
        assertThat(sentMessage.getText()).contains("Authentication Server");
        assertThat(sentMessage.getText()).contains(verificationUrl);
    }

    @Test
    @DisplayName("Should send password reset email successfully")
    void testSendPasswordResetEmail() {
        // Given
        String resetUrl = "https://auth-server.com/reset?token=xyz789";

        // When
        emailService.sendPasswordResetEmail(testUser, "resetToken", resetUrl);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(1)).send(messageCaptor.capture());

        SimpleMailMessage sentMessage = messageCaptor.getValue();
        assertThat(sentMessage.getTo()).contains("testuser@example.com");
        assertThat(sentMessage.getFrom()).isEqualTo("noreply@auth-server.com");
        assertThat(sentMessage.getSubject()).contains("Password Reset");
        assertThat(sentMessage.getText()).contains("testuser");
        assertThat(sentMessage.getText()).contains(resetUrl);
    }

    @Test
    @DisplayName("Should send 2FA setup email successfully")
    void testSend2FASetupEmail() {
        // Given & When
        emailService.send2FASetupEmail(testUser);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender, times(1)).send(messageCaptor.capture());

        SimpleMailMessage sentMessage = messageCaptor.getValue();
        assertThat(sentMessage.getTo()).contains("testuser@example.com");
        assertThat(sentMessage.getFrom()).isEqualTo("noreply@auth-server.com");
        assertThat(sentMessage.getSubject()).contains("Two-Factor Authentication");
        assertThat(sentMessage.getText()).contains("testuser");
        assertThat(sentMessage.getText()).contains("authenticator app");
    }

    @Test
    @DisplayName("Should include correct from address in email")
    void testEmailFromAddress() {
        // Given
        String verificationUrl = "https://example.com/verify";

        // When
        emailService.sendVerificationEmail(testUser, "token", verificationUrl);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        assertThat(messageCaptor.getValue().getFrom())
                .isEqualTo("noreply@auth-server.com");
    }

    @Test
    @DisplayName("Should include application name in subject")
    void testApplicationNameInSubject() {
        // Given
        String verificationUrl = "https://example.com/verify";

        // When
        emailService.sendVerificationEmail(testUser, "token", verificationUrl);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        assertThat(messageCaptor.getValue().getSubject())
                .contains("Authentication Server");
    }

    @Test
    @DisplayName("Should include user details in verification email")
    void testVerificationEmailContent() {
        // Given
        String verificationUrl = "https://example.com/verify?token=test123";

        // When
        emailService.sendVerificationEmail(testUser, "test123", verificationUrl);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        String emailBody = messageCaptor.getValue().getText();
        assertThat(emailBody)
                .contains(testUser.getUsername())
                .contains("verify")
                .contains("email")
                .contains("24 hours");
    }

    @Test
    @DisplayName("Should include reset URL in password reset email")
    void testPasswordResetEmailContent() {
        // Given
        String resetUrl = "https://example.com/reset?token=test456";

        // When
        emailService.sendPasswordResetEmail(testUser, "test456", resetUrl);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        String emailBody = messageCaptor.getValue().getText();
        assertThat(emailBody)
                .contains(testUser.getUsername())
                .contains(resetUrl)
                .contains("password")
                .contains("1 hour");
    }

    @Test
    @DisplayName("Should handle email sending exception")
    void testEmailSendingException() {
        // Given
        doThrow(new RuntimeException("Mail server error"))
                .when(mailSender).send(any(SimpleMailMessage.class));

        String verificationUrl = "https://example.com/verify";

        // When & Then
        assertThatThrownBy(() -> emailService.sendVerificationEmail(testUser, "token", verificationUrl))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to send email");

        verify(mailSender, times(1)).send(any(SimpleMailMessage.class));
    }

    @Test
    @DisplayName("Should send email to correct recipient")
    void testEmailRecipient() {
        // Given
        String verificationUrl = "https://example.com/verify";

        // When
        emailService.sendVerificationEmail(testUser, "token", verificationUrl);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        assertThat(messageCaptor.getValue().getTo())
                .containsExactly("testuser@example.com");
    }

    @Test
    @DisplayName("Should include warning in verification email about non-account creation")
    void testVerificationEmailWarning() {
        // Given
        String verificationUrl = "https://example.com/verify";

        // When
        emailService.sendVerificationEmail(testUser, "token", verificationUrl);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        assertThat(messageCaptor.getValue().getText())
                .contains("did not create this account");
    }

    @Test
    @DisplayName("Should include warning in password reset email")
    void testPasswordResetEmailWarning() {
        // Given
        String resetUrl = "https://example.com/reset";

        // When
        emailService.sendPasswordResetEmail(testUser, "token", resetUrl);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        assertThat(messageCaptor.getValue().getText())
                .contains("did not request");
    }

    @Test
    @DisplayName("Should include security notice in 2FA setup email")
    void testTwoFASetupEmailSecurityNotice() {
        // Given & When
        emailService.send2FASetupEmail(testUser);

        // Then
        ArgumentCaptor<SimpleMailMessage> messageCaptor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(messageCaptor.capture());

        assertThat(messageCaptor.getValue().getText())
                .contains("contact support");
    }
}
