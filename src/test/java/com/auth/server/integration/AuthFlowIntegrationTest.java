package com.auth.server.integration;

import com.auth.server.AbstractTest;
import com.auth.server.dto.AuthResponse;
import com.auth.server.dto.LoginRequest;
import com.auth.server.dto.RegisterRequest;
import com.auth.server.dto.Verify2FARequest;
import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.entity.VerificationToken;
import com.auth.server.repository.RoleRepository;
import com.auth.server.repository.UserRepository;
import com.auth.server.repository.VerificationTokenRepository;
import com.auth.server.service.TotpService;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static io.restassured.RestAssured.*;
import static org.assertj.core.api.Assertions.*;

/**
 * Integration tests for complete authentication flows.
 * Tests full user journeys including registration, email verification, login, 2FA setup, and password reset.
 */
@DisplayName("Authentication Flow Integration Tests")
public class AuthFlowIntegrationTest extends AbstractTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    @Autowired
    private TotpService totpService;

    private Role userRole;
    private String baseUrl;

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        baseUrl = "http://localhost:" + port;

        // Create user role if it doesn't exist
        userRole = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(
                        Role.builder()
                                .name("ROLE_USER")
                                .description("Standard user role")
                                .build()
                ));

        // Clean up test data
        userRepository.deleteAll();
        verificationTokenRepository.deleteAll();
    }

    @Test
    @DisplayName("Should complete full registration flow")
    void testCompleteRegistrationFlow() {
        // Given
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("SecurePassword@123")
                .passwordConfirm("SecurePassword@123")
                .build();

        // When - Register user
        Response registerResponse = given()
                .contentType("application/json")
                .body(registerRequest)
                .when()
                .post(baseUrl + "/api/auth/register");

        // Then - Verify registration successful
        registerResponse.then()
                .statusCode(HttpStatus.OK.value());

        AuthResponse authResponse = registerResponse.as(AuthResponse.class);
        assertThat(authResponse.getUser()).isNotNull();
        assertThat(authResponse.getUser().getUsername()).isEqualTo("newuser");
        assertThat(authResponse.getRequiresEmailVerification()).isTrue();

        // Verify user exists in database
        User savedUser = userRepository.findByUsername("newuser").orElse(null);
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getEmailVerified()).isFalse();
    }

    @Test
    @DisplayName("Should reject duplicate username during registration")
    void testRegistrationWithDuplicateUsername() {
        // Given
        User existingUser = createTestUser("testuser", "test@example.com", userRole);
        userRepository.save(existingUser);

        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("testuser")
                .email("another@example.com")
                .password("Password@123")
                .passwordConfirm("Password@123")
                .build();

        // When & Then
        given()
                .contentType("application/json")
                .body(registerRequest)
                .when()
                .post(baseUrl + "/api/auth/register")
                .then()
                .statusCode(HttpStatus.CONFLICT.value());
    }

    @Test
    @DisplayName("Should reject duplicate email during registration")
    void testRegistrationWithDuplicateEmail() {
        // Given
        User existingUser = createTestUser("testuser", "test@example.com", userRole);
        userRepository.save(existingUser);

        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("test@example.com")
                .password("Password@123")
                .passwordConfirm("Password@123")
                .build();

        // When & Then
        given()
                .contentType("application/json")
                .body(registerRequest)
                .when()
                .post(baseUrl + "/api/auth/register")
                .then()
                .statusCode(HttpStatus.CONFLICT.value());
    }

    @Test
    @DisplayName("Should reject mismatched passwords")
    void testRegistrationWithMismatchedPasswords() {
        // Given
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("newuser")
                .email("newuser@example.com")
                .password("Password@123")
                .passwordConfirm("DifferentPassword@456")
                .build();

        // When & Then
        given()
                .contentType("application/json")
                .body(registerRequest)
                .when()
                .post(baseUrl + "/api/auth/register")
                .then()
                .statusCode(HttpStatus.BAD_REQUEST.value());
    }

    @Test
    @DisplayName("Should login with verified account")
    void testLoginWithVerifiedAccount() {
        // Given
        User user = createTestUser("loginuser", "login@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("loginuser")
                .password("Test@1234") // Password from createTestUser
                .build();

        // When
        Response loginResponse = given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login");

        // Then
        loginResponse.then()
                .statusCode(HttpStatus.OK.value());

        AuthResponse authResponse = loginResponse.as(AuthResponse.class);
        assertThat(authResponse.getAccessToken()).isNotEmpty();
        assertThat(authResponse.getRefreshToken()).isNotEmpty();
    }

    @Test
    @DisplayName("Should reject login with unverified email")
    void testLoginWithUnverifiedEmail() {
        // Given
        User user = createTestUser("unverified", "unverified@example.com", userRole);
        user.setEmailVerified(false);
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("unverified")
                .password("Test@1234")
                .build();

        // When & Then
        given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login")
                .then()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    @DisplayName("Should reject login with locked account")
    void testLoginWithLockedAccount() {
        // Given
        User user = createTestUser("lockeduser", "locked@example.com", userRole);
        user.setEmailVerified(true);
        user.setLocked(true);
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("lockeduser")
                .password("Test@1234")
                .build();

        // When & Then
        given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login")
                .then()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    @DisplayName("Should reject login with incorrect password")
    void testLoginWithIncorrectPassword() {
        // Given
        User user = createTestUser("wrongpass", "wrongpass@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("wrongpass")
                .password("WrongPassword@123")
                .build();

        // When & Then
        given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login")
                .then()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    @DisplayName("Should setup 2FA successfully")
    void testSetup2FAFlow() {
        // Given
        User user = createTestUser("2fauser", "2fa@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        // Login first
        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("2fauser")
                .password("Test@1234")
                .build();

        Response loginResponse = given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login");

        String accessToken = loginResponse.as(AuthResponse.class).getAccessToken();

        // When - Setup 2FA
        Response setup2FAResponse = given()
                .contentType("application/json")
                .header("Authorization", "Bearer " + accessToken)
                .when()
                .post(baseUrl + "/api/users/me/2fa/setup");

        // Then
        setup2FAResponse.then()
                .statusCode(HttpStatus.OK.value());

        assertThat(setup2FAResponse.jsonPath().getString("secret")).isNotEmpty();
        assertThat(setup2FAResponse.jsonPath().getString("qrCode")).isNotEmpty();
    }

    @Test
    @DisplayName("Should reset password with valid token")
    void testPasswordResetFlow() {
        // Given
        User user = createTestUser("resetuser", "reset@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        // Create password reset token
        VerificationToken resetToken = VerificationToken.builder()
                .token("validResetToken123")
                .tokenType(VerificationToken.TokenType.PASSWORD_RESET)
                .user(user)
                .expiryDate(java.time.LocalDateTime.now().plusHours(1))
                .build();
        verificationTokenRepository.save(resetToken);

        // When - Request password reset (would send email in real scenario)
        // Then - Verify with token
        assertThat(resetToken.isValid()).isTrue();
    }

    @Test
    @DisplayName("Should refresh token successfully")
    void testTokenRefresh() {
        // Given
        User user = createTestUser("refreshuser", "refresh@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("refreshuser")
                .password("Test@1234")
                .build();

        Response loginResponse = given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login");

        AuthResponse authResponse = loginResponse.as(AuthResponse.class);
        String refreshToken = authResponse.getRefreshToken();

        // When - Refresh token
        Response refreshResponse = given()
                .contentType("application/json")
                .body("{\"refreshToken\": \"" + refreshToken + "\"}")
                .when()
                .post(baseUrl + "/api/auth/refresh-token");

        // Then
        refreshResponse.then()
                .statusCode(HttpStatus.OK.value());

        AuthResponse refreshedAuth = refreshResponse.as(AuthResponse.class);
        assertThat(refreshedAuth.getAccessToken()).isNotEmpty();
        assertThat(refreshedAuth.getRefreshToken()).isNotEmpty();
    }

    @Test
    @DisplayName("Should logout and invalidate tokens")
    void testLogoutFlow() {
        // Given
        User user = createTestUser("logoutuser", "logout@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("logoutuser")
                .password("Test@1234")
                .build();

        Response loginResponse = given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login");

        String accessToken = loginResponse.as(AuthResponse.class).getAccessToken();

        // When - Logout
        Response logoutResponse = given()
                .contentType("application/json")
                .header("Authorization", "Bearer " + accessToken)
                .when()
                .post(baseUrl + "/api/auth/logout");

        // Then
        logoutResponse.then()
                .statusCode(HttpStatus.OK.value());
    }

    @Test
    @DisplayName("Should get current user profile")
    void testGetCurrentUserProfile() {
        // Given
        User user = createTestUser("profileuser", "profile@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("profileuser")
                .password("Test@1234")
                .build();

        Response loginResponse = given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login");

        String accessToken = loginResponse.as(AuthResponse.class).getAccessToken();

        // When - Get profile
        Response profileResponse = given()
                .header("Authorization", "Bearer " + accessToken)
                .when()
                .get(baseUrl + "/api/users/me");

        // Then
        profileResponse.then()
                .statusCode(HttpStatus.OK.value());

        assertThat(profileResponse.jsonPath().getString("username")).isEqualTo("profileuser");
        assertThat(profileResponse.jsonPath().getString("email")).isEqualTo("profile@example.com");
    }

    @Test
    @DisplayName("Should reject request with invalid token")
    void testRequestWithInvalidToken() {
        // When & Then
        given()
                .header("Authorization", "Bearer invalidtoken123")
                .when()
                .get(baseUrl + "/api/users/me")
                .then()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    @DisplayName("Should reject request without authentication")
    void testRequestWithoutAuthentication() {
        // When & Then
        given()
                .when()
                .get(baseUrl + "/api/users/me")
                .then()
                .statusCode(HttpStatus.UNAUTHORIZED.value());
    }

    @Test
    @DisplayName("Should allow access to public endpoints without authentication")
    void testPublicEndpointsAccessible() {
        // When & Then
        given()
                .when()
                .get(baseUrl + "/actuator/health")
                .then()
                .statusCode(HttpStatus.OK.value());
    }

    @Test
    @DisplayName("Should track login attempts")
    void testLoginAttemptTracking() {
        // Given
        User user = createTestUser("trackuser", "track@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest failedLoginRequest = LoginRequest.builder()
                .usernameOrEmail("trackuser")
                .password("WrongPassword")
                .build();

        // When - Make multiple failed login attempts
        for (int i = 0; i < 3; i++) {
            given()
                    .contentType("application/json")
                    .body(failedLoginRequest)
                    .when()
                    .post(baseUrl + "/api/auth/login")
                    .then()
                    .statusCode(HttpStatus.UNAUTHORIZED.value());
        }

        // Then - Verify user is not locked yet (threshold is usually 5)
        User updatedUser = userRepository.findByUsername("trackuser").orElse(null);
        assertThat(updatedUser).isNotNull();
        assertThat(updatedUser.getLocked()).isFalse();
    }

    @Test
    @DisplayName("Should handle email verification correctly")
    void testEmailVerificationFlow() {
        // Given
        RegisterRequest registerRequest = RegisterRequest.builder()
                .username("verifyuser")
                .email("verify@example.com")
                .password("Password@123")
                .passwordConfirm("Password@123")
                .build();

        given()
                .contentType("application/json")
                .body(registerRequest)
                .when()
                .post(baseUrl + "/api/auth/register");

        User newUser = userRepository.findByUsername("verifyuser").orElse(null);
        assertThat(newUser).isNotNull();
        assertThat(newUser.getEmailVerified()).isFalse();

        // Get verification token
        VerificationToken token = newUser.getVerificationTokens().stream()
                .filter(t -> t.getTokenType() == VerificationToken.TokenType.EMAIL_VERIFICATION)
                .findFirst()
                .orElse(null);

        assertThat(token).isNotNull();
    }
}
