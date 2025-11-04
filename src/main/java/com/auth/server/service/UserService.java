package com.auth.server.service;

import com.auth.server.dto.RegisterRequest;
import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.exception.AuthenticationException;
import com.auth.server.exception.ResourceNotFoundException;
import com.auth.server.exception.UserAlreadyExistsException;
import com.auth.server.repository.RoleRepository;
import com.auth.server.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Service for user management operations.
 * Handles user creation, lookup, and profile management.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;

    /**
     * Register a new user
     *
     * @param registerRequest Registration request with user details
     * @return Created user
     * @throws UserAlreadyExistsException if username or email already exists
     */
    public User registerUser(RegisterRequest registerRequest) {
        log.info("Registering new user: {}", registerRequest.getUsername());

        // Check if username already exists
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            log.warn("Registration failed: username already exists: {}", registerRequest.getUsername());
            throw new UserAlreadyExistsException("Username already exists");
        }

        // Check if email already exists
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            log.warn("Registration failed: email already exists: {}", registerRequest.getEmail());
            throw new UserAlreadyExistsException("Email already exists");
        }

        // Encode password
        String encodedPassword = passwordEncoder.encode(registerRequest.getPassword());

        // Get default ROLE_USER
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));

        // Create user
        User user = User.builder()
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .passwordHash(encodedPassword)
                .emailVerified(false)  // Email not verified until confirmation
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();

        user = userRepository.save(user);
        log.info("User registered successfully: {} (ID: {})", user.getUsername(), user.getId());

        return user;
    }

    /**
     * Find user by ID
     *
     * @param id User ID
     * @return User
     * @throws ResourceNotFoundException if user not found
     */
    public User findById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    /**
     * Find user by username
     *
     * @param username Username
     * @return User
     * @throws ResourceNotFoundException if user not found
     */
    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    /**
     * Find user by email
     *
     * @param email Email address
     * @return User
     * @throws ResourceNotFoundException if user not found
     */
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    /**
     * Find user by username or email
     *
     * @param usernameOrEmail Username or email
     * @return User
     * @throws ResourceNotFoundException if user not found
     */
    public User findByUsernameOrEmail(String usernameOrEmail) {
        return userRepository.findByUsernameOrEmail(usernameOrEmail)
                .orElseThrow(() -> new AuthenticationException("Invalid username or email"));
    }

    /**
     * Verify password for a user
     *
     * @param user User entity
     * @param rawPassword Raw password to verify
     * @return true if password matches, false otherwise
     */
    public boolean verifyPassword(User user, String rawPassword) {
        return passwordEncoder.matches(rawPassword, user.getPasswordHash());
    }

    /**
     * Update user password
     *
     * @param user User entity
     * @param newPassword New password (raw)
     */
    public void updatePassword(User user, String newPassword) {
        updatePassword(user, newPassword, "unknown");
    }

    /**
     * Update user password with audit logging
     *
     * @param user User entity
     * @param newPassword New password (raw)
     * @param ipAddress Client IP address (for audit logging)
     */
    public void updatePassword(User user, String newPassword, String ipAddress) {
        log.info("Updating password for user: {}", user.getUsername());
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Log password change
        auditService.logPasswordChangeEvent(
                user.getId().toString(),
                user.getUsername(),
                ipAddress,
                true
        );
    }

    /**
     * Verify user email
     *
     * @param user User entity
     */
    public void verifyEmail(User user) {
        log.info("Verifying email for user: {}", user.getUsername());
        user.setEmailVerified(true);
        userRepository.save(user);
    }

    /**
     * Lock user account
     *
     * @param user User entity
     */
    public void lockUser(User user) {
        log.info("Locking user account: {}", user.getUsername());
        user.setLocked(true);
        userRepository.save(user);
    }

    /**
     * Unlock user account
     *
     * @param user User entity
     */
    public void unlockUser(User user) {
        log.info("Unlocking user account: {}", user.getUsername());
        user.setLocked(false);
        userRepository.save(user);
    }

    /**
     * Disable user account
     *
     * @param user User entity
     */
    public void disableUser(User user) {
        log.info("Disabling user account: {}", user.getUsername());
        user.setEnabled(false);
        userRepository.save(user);
    }

    /**
     * Enable user account
     *
     * @param user User entity
     */
    public void enableUser(User user) {
        log.info("Enabling user account: {}", user.getUsername());
        user.setEnabled(true);
        userRepository.save(user);
    }

    /**
     * Save user changes to database
     *
     * @param user User entity to save
     * @return Saved user
     */
    public User save(User user) {
        log.debug("Saving user: {}", user.getUsername());
        return userRepository.save(user);
    }

    /**
     * Check if user exists by username
     *
     * @param username Username
     * @return true if user exists
     */
    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    /**
     * Check if user exists by email
     *
     * @param email Email address
     * @return true if user exists
     */
    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }
}
