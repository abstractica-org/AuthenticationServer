package com.auth.server.service;

import com.auth.server.entity.User;
import com.auth.server.entity.VerificationToken;
import com.auth.server.exception.ResourceNotFoundException;
import com.auth.server.repository.VerificationTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Service for managing verification tokens (email verification and password reset).
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class VerificationTokenService {

    private final VerificationTokenRepository verificationTokenRepository;

    @Value("${verification.token.expiration.hours:24}")
    private int emailVerificationExpirationHours;

    @Value("${password.reset.token.expiration.hours:1}")
    private int passwordResetExpirationHours;

    /**
     * Create an email verification token
     *
     * @param user User entity
     * @return Verification token
     */
    public VerificationToken createEmailVerificationToken(User user) {
        log.info("Creating email verification token for user: {}", user.getUsername());

        // Invalidate any existing email verification tokens
        invalidateExistingTokens(user, VerificationToken.TokenType.EMAIL_VERIFICATION);

        String token = generateToken();
        LocalDateTime expiryDate = LocalDateTime.now().plusHours(emailVerificationExpirationHours);

        VerificationToken verificationToken = VerificationToken.builder()
                .token(token)
                .user(user)
                .tokenType(VerificationToken.TokenType.EMAIL_VERIFICATION)
                .expiryDate(expiryDate)
                .build();

        verificationToken = verificationTokenRepository.save(verificationToken);
        log.debug("Email verification token created for user: {}", user.getUsername());

        return verificationToken;
    }

    /**
     * Create a password reset token
     *
     * @param user User entity
     * @return Verification token
     */
    public VerificationToken createPasswordResetToken(User user) {
        log.info("Creating password reset token for user: {}", user.getUsername());

        // Invalidate any existing password reset tokens
        invalidateExistingTokens(user, VerificationToken.TokenType.PASSWORD_RESET);

        String token = generateToken();
        LocalDateTime expiryDate = LocalDateTime.now().plusHours(passwordResetExpirationHours);

        VerificationToken verificationToken = VerificationToken.builder()
                .token(token)
                .user(user)
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .expiryDate(expiryDate)
                .build();

        verificationToken = verificationTokenRepository.save(verificationToken);
        log.debug("Password reset token created for user: {}", user.getUsername());

        return verificationToken;
    }

    /**
     * Verify a token and return it if valid
     *
     * @param tokenValue Token value
     * @return VerificationToken
     * @throws ResourceNotFoundException if token not found or invalid
     */
    public VerificationToken verifyToken(String tokenValue) {
        log.debug("Verifying token: {}", maskToken(tokenValue));

        VerificationToken token = verificationTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> {
                    log.warn("Token not found: {}", maskToken(tokenValue));
                    return new ResourceNotFoundException("Invalid verification token");
                });

        if (token.isExpired()) {
            log.warn("Token expired: {}", maskToken(tokenValue));
            throw new ResourceNotFoundException("Verification token has expired");
        }

        if (token.isConfirmed()) {
            log.warn("Token already confirmed: {}", maskToken(tokenValue));
            throw new ResourceNotFoundException("Verification token has already been used");
        }

        log.debug("Token verified successfully");
        return token;
    }

    /**
     * Confirm a verification token
     *
     * @param token VerificationToken
     */
    public void confirmToken(VerificationToken token) {
        log.info("Confirming token for user: {}", token.getUser().getUsername());
        token.confirm();
        verificationTokenRepository.save(token);
    }

    /**
     * Get a valid token by user and type
     *
     * @param user User entity
     * @param tokenType Token type
     * @return VerificationToken
     * @throws ResourceNotFoundException if no valid token found
     */
    public VerificationToken getValidToken(User user, VerificationToken.TokenType tokenType) {
        VerificationToken token = verificationTokenRepository.findByUserAndTokenType(user, tokenType)
                .orElseThrow(() -> new ResourceNotFoundException("No verification token found"));

        if (token.isExpired() || token.isConfirmed()) {
            throw new ResourceNotFoundException("Verification token is not valid");
        }

        return token;
    }

    /**
     * Invalidate all existing tokens of a specific type for a user
     */
    private void invalidateExistingTokens(User user, VerificationToken.TokenType tokenType) {
        verificationTokenRepository.findByUserAndTokenType(user, tokenType)
                .ifPresent(token -> {
                    token.confirm();  // Mark as confirmed to invalidate
                    verificationTokenRepository.save(token);
                });
    }

    /**
     * Clean up expired tokens
     */
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Cleaning up expired verification tokens");
        verificationTokenRepository.deleteExpiredTokens(LocalDateTime.now());
    }

    /**
     * Generate a random token
     */
    private String generateToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * Mask token for logging (show only first 8 and last 8 characters)
     */
    private String maskToken(String token) {
        if (token == null || token.length() < 16) {
            return "****";
        }
        return token.substring(0, 8) + "..." + token.substring(token.length() - 8);
    }
}
