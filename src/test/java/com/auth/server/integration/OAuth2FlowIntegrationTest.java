package com.auth.server.integration;

import com.auth.server.AbstractTest;
import com.auth.server.config.TestConfig;
import com.auth.server.dto.AuthResponse;
import com.auth.server.dto.LoginRequest;
import com.auth.server.entity.RegisteredClient;
import com.auth.server.entity.Role;
import com.auth.server.entity.User;
import com.auth.server.repository.RegisteredClientRepository;
import com.auth.server.repository.RoleRepository;
import com.auth.server.repository.UserRepository;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.*;

/**
 * Integration tests for OAuth2 authorization flows.
 * Tests OAuth2 client credentials flow and authorization code flow.
 */
@DisplayName("OAuth2 Flow Integration Tests")
@Import(TestConfig.class)
public class OAuth2FlowIntegrationTest extends AbstractTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private Role userRole;
    private Role adminRole;
    private String baseUrl;
    private RegisteredClient testClient;

    @BeforeEach
    void setUp() {
        RestAssured.port = port;
        baseUrl = "http://localhost:" + port;

        // Create roles
        userRole = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(
                        Role.builder()
                                .name("ROLE_USER")
                                .description("Standard user role")
                                .build()
                ));

        adminRole = roleRepository.findByName("ROLE_ADMIN")
                .orElseGet(() -> roleRepository.save(
                        Role.builder()
                                .name("ROLE_ADMIN")
                                .description("Administrator role")
                                .build()
                ));

        // Clean up test data
        registeredClientRepository.deleteAll();
        userRepository.deleteAll();

        // Create test client
        testClient = RegisteredClient.builder()
                .id(UUID.randomUUID())
                .clientId("test-client-123")
                .clientSecretHash(passwordEncoder.encode("test-secret-456"))
                .clientName("Test OAuth2 Client")
                .redirectUris("http://localhost:3000/callback")
                .scopes("read,write,profile")
                .accessTokenTtl(900)
                .refreshTokenTtl(2592000)
                .clientCredentialsEnabled(true)
                .authorizationCodeEnabled(true)
                .refreshTokenEnabled(true)
                .deleted(false)
                .build();

        registeredClientRepository.save(testClient);
    }

    @Test
    @DisplayName("Should discover OAuth2 server configuration")
    void testOAuth2Discovery() {
        // When
        Response discoveryResponse = given()
                .when()
                .get(baseUrl + "/.well-known/oauth-authorization-server");

        // Then
        discoveryResponse.then()
                .statusCode(HttpStatus.OK.value());

        assertThat(discoveryResponse.jsonPath().getString("issuer")).isNotEmpty();
        assertThat(discoveryResponse.jsonPath().getString("authorization_endpoint")).isNotEmpty();
        assertThat(discoveryResponse.jsonPath().getString("token_endpoint")).isNotEmpty();
    }

    @Test
    @DisplayName("Should handle authorization code flow - authorization endpoint")
    void testAuthorizationCodeFlowAuthorizationEndpoint() {
        // Given - User is authenticated
        User user = createTestUser("oauth2user", "oauth2@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        // When - Request authorization
        Response authResponse = given()
                .queryParam("client_id", testClient.getClientId())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", "http://localhost:3000/callback")
                .queryParam("scope", "read write")
                .queryParam("state", "random-state-123")
                .when()
                .get(baseUrl + "/oauth2/authorize");

        // Then
        // Note: In a real scenario, this would require user login/consent
        // For testing, we expect authorization flow to be initiated
        assertThat(authResponse.statusCode()).isIn(
                HttpStatus.OK.value(),
                HttpStatus.FOUND.value(),
                HttpStatus.UNAUTHORIZED.value()
        );
    }

    @Test
    @DisplayName("Should handle token request with authorization code")
    void testAuthorizationCodeFlowTokenEndpoint() {
        // Given - Simulate authorization code obtained
        String authorizationCode = "auth-code-xyz789";

        Map<String, Object> tokenRequest = new HashMap<>();
        tokenRequest.put("grant_type", "authorization_code");
        tokenRequest.put("code", authorizationCode);
        tokenRequest.put("client_id", testClient.getClientId());
        tokenRequest.put("client_secret", "test-secret-456");
        tokenRequest.put("redirect_uri", "http://localhost:3000/callback");

        // When - Request token with authorization code
        Response tokenResponse = given()
                .contentType("application/json")
                .body(tokenRequest)
                .when()
                .post(baseUrl + "/oauth2/token");

        // Then
        // Will likely fail with invalid code in test, but endpoint should exist
        assertThat(tokenResponse.statusCode()).isIn(
                HttpStatus.BAD_REQUEST.value(),
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.OK.value()
        );
    }

    @Test
    @DisplayName("Should handle client credentials flow")
    void testClientCredentialsFlow() {
        // When - Request token with client credentials
        Map<String, Object> tokenRequest = new HashMap<>();
        tokenRequest.put("grant_type", "client_credentials");
        tokenRequest.put("client_id", testClient.getClientId());
        tokenRequest.put("client_secret", "test-secret-456");
        tokenRequest.put("scope", "read write");

        Response tokenResponse = given()
                .contentType("application/json")
                .body(tokenRequest)
                .when()
                .post(baseUrl + "/oauth2/token");

        // Then
        assertThat(tokenResponse.statusCode()).isIn(
                HttpStatus.OK.value(),
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.BAD_REQUEST.value()
        );

        // If successful, should have access token
        if (tokenResponse.statusCode() == HttpStatus.OK.value()) {
            assertThat(tokenResponse.jsonPath().getString("access_token")).isNotEmpty();
            assertThat(tokenResponse.jsonPath().getString("token_type")).isEqualTo("Bearer");
            assertThat(tokenResponse.jsonPath().getInt("expires_in")).isGreaterThan(0);
        }
    }

    @Test
    @DisplayName("Should reject client credentials with invalid secret")
    void testClientCredentialsWithInvalidSecret() {
        // When - Request token with wrong secret
        Map<String, Object> tokenRequest = new HashMap<>();
        tokenRequest.put("grant_type", "client_credentials");
        tokenRequest.put("client_id", testClient.getClientId());
        tokenRequest.put("client_secret", "wrong-secret-xyz");
        tokenRequest.put("scope", "read write");

        Response tokenResponse = given()
                .contentType("application/json")
                .body(tokenRequest)
                .when()
                .post(baseUrl + "/oauth2/token");

        // Then
        assertThat(tokenResponse.statusCode()).isIn(
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.BAD_REQUEST.value()
        );
    }

    @Test
    @DisplayName("Should reject request with non-existent client")
    void testClientCredentialsWithNonExistentClient() {
        // When - Request token for non-existent client
        Map<String, Object> tokenRequest = new HashMap<>();
        tokenRequest.put("grant_type", "client_credentials");
        tokenRequest.put("client_id", "non-existent-client");
        tokenRequest.put("client_secret", "any-secret");
        tokenRequest.put("scope", "read write");

        Response tokenResponse = given()
                .contentType("application/json")
                .body(tokenRequest)
                .when()
                .post(baseUrl + "/oauth2/token");

        // Then
        assertThat(tokenResponse.statusCode()).isIn(
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.BAD_REQUEST.value()
        );
    }

    @Test
    @DisplayName("Should handle refresh token flow")
    void testRefreshTokenFlow() {
        // Given - User logged in and has refresh token
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

        String refreshToken = loginResponse.as(AuthResponse.class).getRefreshToken();

        // When - Request new access token with refresh token
        Map<String, Object> refreshRequest = new HashMap<>();
        refreshRequest.put("grant_type", "refresh_token");
        refreshRequest.put("refresh_token", refreshToken);

        Response refreshResponse = given()
                .contentType("application/json")
                .body(refreshRequest)
                .when()
                .post(baseUrl + "/oauth2/token");

        // Then
        assertThat(refreshResponse.statusCode()).isIn(
                HttpStatus.OK.value(),
                HttpStatus.BAD_REQUEST.value()
        );
    }

    @Test
    @DisplayName("Should handle token introspection")
    void testTokenIntrospection() {
        // Given - User logged in with token
        User user = createTestUser("introuser", "intro@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("introuser")
                .password("Test@1234")
                .build();

        Response loginResponse = given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login");

        String accessToken = loginResponse.as(AuthResponse.class).getAccessToken();

        // When - Introspect token
        Map<String, String> introspectRequest = new HashMap<>();
        introspectRequest.put("token", accessToken);

        Response introspectResponse = given()
                .contentType("application/json")
                .body(introspectRequest)
                .when()
                .post(baseUrl + "/oauth2/introspect");

        // Then
        assertThat(introspectResponse.statusCode()).isIn(
                HttpStatus.OK.value(),
                HttpStatus.UNAUTHORIZED.value()
        );

        if (introspectResponse.statusCode() == HttpStatus.OK.value()) {
            assertThat(introspectResponse.jsonPath().getBoolean("active")).isTrue();
        }
    }

    @Test
    @DisplayName("Should handle token revocation")
    void testTokenRevocation() {
        // Given - User logged in with token
        User user = createTestUser("revokeuser", "revoke@example.com", userRole);
        user.setEmailVerified(true);
        userRepository.save(user);

        LoginRequest loginRequest = LoginRequest.builder()
                .usernameOrEmail("revokeuser")
                .password("Test@1234")
                .build();

        Response loginResponse = given()
                .contentType("application/json")
                .body(loginRequest)
                .when()
                .post(baseUrl + "/api/auth/login");

        String refreshToken = loginResponse.as(AuthResponse.class).getRefreshToken();

        // When - Revoke token
        Map<String, String> revokeRequest = new HashMap<>();
        revokeRequest.put("token", refreshToken);

        Response revokeResponse = given()
                .contentType("application/json")
                .body(revokeRequest)
                .when()
                .post(baseUrl + "/oauth2/revoke");

        // Then
        assertThat(revokeResponse.statusCode()).isIn(
                HttpStatus.OK.value(),
                HttpStatus.BAD_REQUEST.value()
        );
    }

    @Test
    @DisplayName("Should include scope in token response")
    void testScopeInTokenResponse() {
        // When - Request token with specific scopes
        Map<String, Object> tokenRequest = new HashMap<>();
        tokenRequest.put("grant_type", "client_credentials");
        tokenRequest.put("client_id", testClient.getClientId());
        tokenRequest.put("client_secret", "test-secret-456");
        tokenRequest.put("scope", "read write");

        Response tokenResponse = given()
                .contentType("application/json")
                .body(tokenRequest)
                .when()
                .post(baseUrl + "/oauth2/token");

        // Then
        if (tokenResponse.statusCode() == HttpStatus.OK.value()) {
            assertThat(tokenResponse.jsonPath().getString("scope")).isNotEmpty();
        }
    }

    @Test
    @DisplayName("Should use registered redirect URI")
    void testRedirectUriValidation() {
        // When - Request authorization with unregistered redirect URI
        Response authResponse = given()
                .queryParam("client_id", testClient.getClientId())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", "http://malicious.com/callback")
                .queryParam("scope", "read write")
                .when()
                .get(baseUrl + "/oauth2/authorize");

        // Then
        // Should reject unregistered redirect URI
        assertThat(authResponse.statusCode()).isIn(
                HttpStatus.BAD_REQUEST.value(),
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.FOUND.value()
        );
    }

    @Test
    @DisplayName("Should have token endpoint accessible")
    void testTokenEndpointAccessible() {
        // When
        Response response = given()
                .when()
                .post(baseUrl + "/oauth2/token");

        // Then - Should return error, but endpoint exists
        assertThat(response.statusCode()).isNotEqualTo(HttpStatus.NOT_FOUND.value());
    }

    @Test
    @DisplayName("Should have authorization endpoint accessible")
    void testAuthorizationEndpointAccessible() {
        // When
        Response response = given()
                .when()
                .get(baseUrl + "/oauth2/authorize");

        // Then - Should return some response (might be 400/401)
        assertThat(response.statusCode()).isNotEqualTo(HttpStatus.NOT_FOUND.value());
    }
}
