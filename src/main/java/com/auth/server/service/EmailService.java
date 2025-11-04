package com.auth.server.service;

import com.auth.server.entity.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * Service for sending emails (verification, password reset, etc.)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.from}")
    private String fromEmail;

    @Value("${spring.application.name:Authentication Server}")
    private String applicationName;

    /**
     * Send email verification email
     *
     * @param user User entity
     * @param verificationToken Verification token
     * @param verificationUrl URL for email verification
     */
    public void sendVerificationEmail(User user, String verificationToken, String verificationUrl) {
        log.info("Sending verification email to: {}", user.getEmail());

        String subject = "Email Verification - " + applicationName;
        String text = buildVerificationEmailBody(user, verificationUrl);

        sendEmail(user.getEmail(), subject, text);

        log.debug("Verification email sent to: {}", user.getEmail());
    }

    /**
     * Send password reset email
     *
     * @param user User entity
     * @param resetToken Reset token
     * @param resetUrl URL for password reset
     */
    public void sendPasswordResetEmail(User user, String resetToken, String resetUrl) {
        log.info("Sending password reset email to: {}", user.getEmail());

        String subject = "Password Reset - " + applicationName;
        String text = buildPasswordResetEmailBody(user, resetUrl);

        sendEmail(user.getEmail(), subject, text);

        log.debug("Password reset email sent to: {}", user.getEmail());
    }

    /**
     * Send 2FA setup confirmation email
     *
     * @param user User entity
     */
    public void send2FASetupEmail(User user) {
        log.info("Sending 2FA setup confirmation email to: {}", user.getEmail());

        String subject = "Two-Factor Authentication Enabled - " + applicationName;
        String text = build2FASetupEmailBody(user);

        sendEmail(user.getEmail(), subject, text);

        log.debug("2FA setup email sent to: {}", user.getEmail());
    }

    /**
     * Send generic email
     *
     * @param to Recipient email
     * @param subject Email subject
     * @param text Email body
     */
    private void sendEmail(String to, String subject, String text) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(text);

            mailSender.send(message);
            log.debug("Email sent successfully to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send email to: {}", to, e);
            throw new RuntimeException("Failed to send email", e);
        }
    }

    /**
     * Build verification email body
     */
    private String buildVerificationEmailBody(User user, String verificationUrl) {
        return String.format(
                "Hello %s,\n\n" +
                        "Thank you for registering with %s.\n" +
                        "Please verify your email address by clicking the link below:\n\n" +
                        "%s\n\n" +
                        "If you did not create this account, please ignore this email.\n\n" +
                        "This link will expire in 24 hours.\n\n" +
                        "Best regards,\n" +
                        "The %s Team",
                user.getUsername(),
                applicationName,
                verificationUrl,
                applicationName
        );
    }

    /**
     * Build password reset email body
     */
    private String buildPasswordResetEmailBody(User user, String resetUrl) {
        return String.format(
                "Hello %s,\n\n" +
                        "We received a request to reset your password.\n" +
                        "Please click the link below to reset your password:\n\n" +
                        "%s\n\n" +
                        "If you did not request a password reset, please ignore this email.\n\n" +
                        "This link will expire in 1 hour.\n\n" +
                        "Best regards,\n" +
                        "The %s Team",
                user.getUsername(),
                resetUrl,
                applicationName
        );
    }

    /**
     * Build 2FA setup email body
     */
    private String build2FASetupEmailBody(User user) {
        return String.format(
                "Hello %s,\n\n" +
                        "Two-factor authentication has been enabled on your account.\n" +
                        "From now on, you will need to provide a code from your authenticator app when logging in.\n\n" +
                        "If you did not enable this, please contact support immediately.\n\n" +
                        "Best regards,\n" +
                        "The %s Team",
                user.getUsername(),
                applicationName
        );
    }
}
