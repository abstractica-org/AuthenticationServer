package com.auth.server.service;

import com.auth.server.entity.LoginAttempt;
import com.auth.server.entity.User;
import com.auth.server.repository.LoginAttemptRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service for tracking login attempts and detecting brute force attacks.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class LoginAttemptService {

    private final LoginAttemptRepository loginAttemptRepository;
    private final AuditService auditService;

    @Value("${rate.limit.login.requests:5}")
    private int rateLimitRequests;

    @Value("${rate.limit.login.duration.minutes:15}")
    private int rateLimitDurationMinutes;

    /**
     * Record a login attempt
     *
     * @param usernameOrEmail Username or email
     * @param user User entity (can be null if user not found)
     * @param ipAddress Client IP address
     * @param success Whether login was successful
     */
    public void recordLoginAttempt(String usernameOrEmail, User user, String ipAddress, boolean success) {
        LoginAttempt attempt = LoginAttempt.builder()
                .usernameOrEmail(usernameOrEmail)
                .user(user)
                .ipAddress(ipAddress)
                .success(success)
                .attemptTime(LocalDateTime.now())
                .build();

        loginAttemptRepository.save(attempt);
        log.debug("Login attempt recorded for {}: success={}", usernameOrEmail, success);

        // Log failed attempts to audit service
        if (!success) {
            String userId = user != null ? user.getId().toString() : null;
            String username = user != null ? user.getUsername() : usernameOrEmail;
            auditService.logAuthenticationEvent(
                    username,
                    userId,
                    ipAddress,
                    "unknown",
                    false
            );
        }
    }

    /**
     * Get count of failed attempts for user in the last N minutes
     *
     * @param usernameOrEmail Username or email
     * @return Number of failed attempts
     */
    public long countFailedAttempts(String usernameOrEmail) {
        LocalDateTime afterTime = LocalDateTime.now().minusMinutes(rateLimitDurationMinutes);
        return loginAttemptRepository.countByUsernameOrEmailAndSuccessIsFalseAndAttemptTimeAfter(
                usernameOrEmail, afterTime);
    }

    /**
     * Get count of failed attempts from IP address in the last N minutes
     *
     * @param ipAddress Client IP address
     * @return Number of failed attempts from this IP
     */
    public long countFailedAttemptsByIp(String ipAddress) {
        LocalDateTime afterTime = LocalDateTime.now().minusMinutes(rateLimitDurationMinutes);
        return loginAttemptRepository.countByIpAddressAndSuccessIsFalseAndAttemptTimeAfter(
                ipAddress, afterTime);
    }

    /**
     * Check if user has too many failed attempts
     *
     * @param usernameOrEmail Username or email
     * @return true if exceeded limit
     */
    public boolean hasExceededAttemptLimit(String usernameOrEmail) {
        return countFailedAttempts(usernameOrEmail) >= rateLimitRequests;
    }

    /**
     * Check if IP address has too many failed attempts (rate limiting)
     *
     * @param ipAddress Client IP address
     * @return true if exceeded limit
     */
    public boolean hasExceededIpAttemptLimit(String ipAddress) {
        return countFailedAttemptsByIp(ipAddress) >= rateLimitRequests;
    }

    /**
     * Get rate limit configuration
     *
     * @return Max requests per duration
     */
    public int getRateLimitRequests() {
        return rateLimitRequests;
    }

    /**
     * Get rate limit duration configuration
     *
     * @return Duration in minutes
     */
    public int getRateLimitDurationMinutes() {
        return rateLimitDurationMinutes;
    }
}
