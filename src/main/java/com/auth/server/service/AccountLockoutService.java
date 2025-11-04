package com.auth.server.service;

import com.auth.server.entity.User;
import com.auth.server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service for managing account lockout due to failed login attempts.
 * Implements brute force protection.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class AccountLockoutService {

    private final UserRepository userRepository;
    private final AuditService auditService;

    @Value("${account.lockout.threshold:5}")
    private int lockoutThreshold;

    @Value("${account.lockout.duration.minutes:30}")
    private int lockoutDurationMinutes;

    /**
     * Check if user account is locked due to failed attempts
     *
     * @param user User entity
     * @return true if account is locked
     */
    public boolean isAccountLocked(User user) {
        if (!user.getLocked()) {
            return false;
        }

        // Check if lockout period has expired
        if (user.getLastLogin() != null) {
            LocalDateTime lockoutExpiry = user.getLastLogin().plusMinutes(lockoutDurationMinutes);
            if (LocalDateTime.now().isAfter(lockoutExpiry)) {
                // Auto-unlock account
                unlockAccount(user);
                return false;
            }
        }

        return true;
    }

    /**
     * Lock user account after too many failed attempts
     *
     * @param user User entity
     */
    public void lockAccount(User user) {
        lockAccount(user, "unknown");
    }

    /**
     * Lock user account after too many failed attempts
     *
     * @param user User entity
     * @param ipAddress Client IP address
     */
    public void lockAccount(User user, String ipAddress) {
        log.warn("Locking account: {}", user.getUsername());
        user.setLocked(true);
        userRepository.save(user);

        // Log account lock
        auditService.logAccountLocked(
                user.getId().toString(),
                user.getUsername(),
                ipAddress,
                "Excessive failed login attempts"
        );
    }

    /**
     * Unlock user account
     *
     * @param user User entity
     */
    public void unlockAccount(User user) {
        unlockAccount(user, "unknown");
    }

    /**
     * Unlock user account
     *
     * @param user User entity
     * @param ipAddress Client IP address
     */
    public void unlockAccount(User user, String ipAddress) {
        log.info("Unlocking account: {}", user.getUsername());
        user.setLocked(false);
        userRepository.save(user);

        // Log account unlock
        auditService.logAccountUnlocked(
                user.getId().toString(),
                user.getUsername()
        );
    }

    /**
     * Check if user has exceeded failed attempt threshold
     *
     * @param failedAttempts Number of failed attempts
     * @return true if threshold exceeded
     */
    public boolean hasExceededThreshold(long failedAttempts) {
        return failedAttempts >= lockoutThreshold;
    }

    /**
     * Get lockout threshold configuration
     *
     * @return Number of failed attempts before lockout
     */
    public int getLockoutThreshold() {
        return lockoutThreshold;
    }

    /**
     * Get lockout duration configuration
     *
     * @return Duration in minutes
     */
    public int getLockoutDurationMinutes() {
        return lockoutDurationMinutes;
    }
}
