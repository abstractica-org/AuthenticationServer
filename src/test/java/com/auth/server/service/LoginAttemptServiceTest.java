package com.auth.server.service;

import com.auth.server.entity.LoginAttempt;
import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.repository.LoginAttemptRepository;
import com.auth.server.repository.RoleRepository;
import com.auth.server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for LoginAttemptService - brute force detection and rate limiting
 */
@SpringBootTest
@TestPropertySource(locations = "classpath:application-test.properties")
@DisplayName("Login Attempt Service Tests")
class LoginAttemptServiceTest {

    @Autowired
    private LoginAttemptService loginAttemptService;

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    private User testUser;
    private String testIp = "192.168.1.100";

    @BeforeEach
    void setUp() {
        loginAttemptRepository.deleteAll();
        userRepository.deleteAll();
        roleRepository.deleteAll();

        Role userRole = Role.builder().name("USER").build();
        roleRepository.save(userRole);

        testUser = User.builder()
                .username("testuser")
                .email("test@example.com")
                .passwordHash("$2a$13$hash")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(testUser);
    }

    @Test
    @DisplayName("Should record successful login attempt")
    void testRecordSuccessfulLoginAttempt() {
        loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, true);

        LoginAttempt recorded = loginAttemptRepository.findAll().get(0);

        assertThat(recorded)
                .isNotNull()
                .extracting("usernameOrEmail", "success", "ipAddress")
                .containsExactly("testuser", true, testIp);
        assertThat(recorded.getAttemptTime()).isNotNull();
    }

    @Test
    @DisplayName("Should record failed login attempt")
    void testRecordFailedLoginAttempt() {
        loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, false);

        LoginAttempt recorded = loginAttemptRepository.findAll().get(0);

        assertThat(recorded.getSuccess()).isFalse();
        assertThat(recorded.getUsernameOrEmail()).isEqualTo("testuser");
    }

    @Test
    @DisplayName("Should record attempt for non-existent user")
    void testRecordAttemptForNonExistentUser() {
        String nonExistentUsername = "nonexistent@example.com";

        loginAttemptService.recordLoginAttempt(nonExistentUsername, null, testIp, false);

        LoginAttempt recorded = loginAttemptRepository.findAll().get(0);

        assertThat(recorded)
                .isNotNull()
                .extracting("usernameOrEmail", "success")
                .containsExactly(nonExistentUsername, false);
        assertThat(recorded.getUser()).isNull();
    }

    @Test
    @DisplayName("Should count failed attempts for user")
    void testCountFailedAttempts() {
        // Record 3 failed attempts
        for (int i = 0; i < 3; i++) {
            loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, false);
        }

        // Record 1 successful attempt
        loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, true);

        long failedCount = loginAttemptService.countFailedAttempts("testuser");

        assertThat(failedCount).isEqualTo(3);
    }

    @Test
    @DisplayName("Should not count successful attempts in failed count")
    void testFailedCountDoesNotIncludeSuccessful() {
        // Record 5 successful attempts
        for (int i = 0; i < 5; i++) {
            loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, true);
        }

        long failedCount = loginAttemptService.countFailedAttempts("testuser");

        assertThat(failedCount).isZero();
    }

    @Test
    @DisplayName("Should count failed attempts by IP address")
    void testCountFailedAttemptsByIp() {
        String ip1 = "192.168.1.100";
        String ip2 = "192.168.1.101";

        // 3 failed from IP1
        for (int i = 0; i < 3; i++) {
            loginAttemptService.recordLoginAttempt("testuser", testUser, ip1, false);
        }

        // 2 failed from IP2
        for (int i = 0; i < 2; i++) {
            loginAttemptService.recordLoginAttempt("testuser", testUser, ip2, false);
        }

        long countIp1 = loginAttemptService.countFailedAttemptsByIp(ip1);
        long countIp2 = loginAttemptService.countFailedAttemptsByIp(ip2);

        assertThat(countIp1).isEqualTo(3);
        assertThat(countIp2).isEqualTo(2);
    }

    @Test
    @DisplayName("Should detect when user exceeds attempt limit")
    void testHasExceededAttemptLimit() {
        int limit = loginAttemptService.getRateLimitRequests();

        // Record limit-1 failed attempts
        for (int i = 0; i < limit - 1; i++) {
            loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, false);
        }

        assertThat(loginAttemptService.hasExceededAttemptLimit("testuser")).isFalse();

        // Record one more to reach limit
        loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, false);

        assertThat(loginAttemptService.hasExceededAttemptLimit("testuser")).isTrue();
    }

    @Test
    @DisplayName("Should detect when IP exceeds attempt limit")
    void testHasExceededIpAttemptLimit() {
        int limit = loginAttemptService.getRateLimitRequests();

        // Record limit-1 failed attempts from same IP
        for (int i = 0; i < limit - 1; i++) {
            loginAttemptService.recordLoginAttempt("user" + i, null, testIp, false);
        }

        assertThat(loginAttemptService.hasExceededIpAttemptLimit(testIp)).isFalse();

        // Record one more to reach limit
        loginAttemptService.recordLoginAttempt("userN", null, testIp, false);

        assertThat(loginAttemptService.hasExceededIpAttemptLimit(testIp)).isTrue();
    }

    @Test
    @DisplayName("Should handle counting with time window correctly")
    void testCountWithTimeWindow() {
        // Record 3 attempts now
        for (int i = 0; i < 3; i++) {
            loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, false);
        }

        long count = loginAttemptService.countFailedAttempts("testuser");

        // Should count all recent attempts
        assertThat(count).isGreaterThanOrEqualTo(3);
    }

    @Test
    @DisplayName("Should distinguish between users in failed count")
    void testFailedCountIsPerUser() {
        // Create another user
        Role userRole = roleRepository.findByName("USER").orElseThrow();
        User user2 = User.builder()
                .username("testuser2")
                .email("test2@example.com")
                .passwordHash("$2a$13$hash2")
                .emailVerified(true)
                .enabled(true)
                .locked(false)
                .roles(new HashSet<>(Set.of(userRole)))
                .build();
        userRepository.save(user2);

        // 3 failed attempts for user1
        for (int i = 0; i < 3; i++) {
            loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, false);
        }

        // 5 failed attempts for user2
        for (int i = 0; i < 5; i++) {
            loginAttemptService.recordLoginAttempt("testuser2", user2, testIp, false);
        }

        long count1 = loginAttemptService.countFailedAttempts("testuser");
        long count2 = loginAttemptService.countFailedAttempts("testuser2");

        assertThat(count1).isEqualTo(3);
        assertThat(count2).isEqualTo(5);
    }

    @Test
    @DisplayName("Should return configured rate limit requests")
    void testGetRateLimitRequests() {
        int limit = loginAttemptService.getRateLimitRequests();

        assertThat(limit)
                .isPositive()
                .isGreaterThanOrEqualTo(3)
                .isLessThanOrEqualTo(10);
    }

    @Test
    @DisplayName("Should return configured rate limit duration")
    void testGetRateLimitDurationMinutes() {
        int duration = loginAttemptService.getRateLimitDurationMinutes();

        assertThat(duration)
                .isPositive()
                .isGreaterThanOrEqualTo(5)
                .isLessThanOrEqualTo(60);
    }

    @Test
    @DisplayName("Should handle multiple attempts from different IPs")
    void testMultipleIpsTracking() {
        String ip1 = "192.168.1.100";
        String ip2 = "192.168.1.101";
        String ip3 = "192.168.1.102";

        // Same user, different IPs
        loginAttemptService.recordLoginAttempt("testuser", testUser, ip1, false);
        loginAttemptService.recordLoginAttempt("testuser", testUser, ip2, false);
        loginAttemptService.recordLoginAttempt("testuser", testUser, ip3, false);

        // Total attempts for user
        long totalForUser = loginAttemptService.countFailedAttempts("testuser");

        assertThat(totalForUser).isEqualTo(3);

        // Individual IP counts
        assertThat(loginAttemptService.countFailedAttemptsByIp(ip1)).isEqualTo(1);
        assertThat(loginAttemptService.countFailedAttemptsByIp(ip2)).isEqualTo(1);
        assertThat(loginAttemptService.countFailedAttemptsByIp(ip3)).isEqualTo(1);
    }

    @Test
    @DisplayName("Should record attempt with email address")
    void testRecordAttemptWithEmail() {
        String email = "test@example.com";

        loginAttemptService.recordLoginAttempt(email, testUser, testIp, false);

        long count = loginAttemptService.countFailedAttempts(email);

        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("Should accurately detect limit at boundary")
    void testBoundaryConditionForLimit() {
        int limit = loginAttemptService.getRateLimitRequests();

        // Record exactly limit-1 attempts
        for (int i = 0; i < limit - 1; i++) {
            loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, false);
        }

        // Not exceeded yet
        assertThat(loginAttemptService.hasExceededAttemptLimit("testuser")).isFalse();

        // Record exactly one more
        loginAttemptService.recordLoginAttempt("testuser", testUser, testIp, false);

        // Now exceeded
        assertThat(loginAttemptService.hasExceededAttemptLimit("testuser")).isTrue();
    }
}
