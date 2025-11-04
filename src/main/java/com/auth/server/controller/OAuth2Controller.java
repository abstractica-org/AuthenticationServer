package com.auth.server.controller;

import com.auth.server.dto.OAuth2TokenRequest;
import com.auth.server.dto.OAuth2TokenResponse;
import com.auth.server.entity.RegisteredClient;
import com.auth.server.entity.User;
import com.auth.server.repository.RegisteredClientRepository;
import com.auth.server.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * OAuth2 Server endpoints for token generation and token management.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
@Tag(name = "OAuth2", description = "OAuth2 server endpoints")
public class OAuth2Controller {

    private final RegisteredClientRepository clientRepository;
    private final UserRepository userRepository;
    private final JwtEncoder jwtEncoder;
    private final PasswordEncoder passwordEncoder;
    private final ObjectMapper objectMapper;

    @Value("${jwt.expiration:900000}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh.expiration:2592000000}")
    private long refreshTokenExpiration;

    /**
     * OAuth2 Discovery endpoint - provides server metadata
     */
    @GetMapping("/.well-known/oauth-authorization-server")
    @Operation(summary = "OAuth2 Discovery", description = "Returns OAuth2 server metadata")
    public ResponseEntity<Map<String, Object>> discovery() {
        log.debug("OAuth2 discovery request");

        Map<String, Object> discovery = new HashMap<>();
        discovery.put("issuer", "http://localhost:8080");
        discovery.put("authorization_endpoint", "http://localhost:8080/oauth2/authorize");
        discovery.put("token_endpoint", "http://localhost:8080/oauth2/token");
        discovery.put("introspection_endpoint", "http://localhost:8080/oauth2/introspect");
        discovery.put("revocation_endpoint", "http://localhost:8080/oauth2/revoke");
        discovery.put("jwks_uri", "http://localhost:8080/.well-known/jwks.json");
        discovery.put("grant_types_supported", new String[]{"authorization_code", "client_credentials", "refresh_token"});
        discovery.put("token_endpoint_auth_methods_supported", new String[]{"client_secret_basic", "client_secret_post"});
        discovery.put("response_types_supported", new String[]{"code"});
        discovery.put("scopes_supported", new String[]{"read", "write", "profile", "email"});

        return ResponseEntity.ok(discovery);
    }

    /**
     * Authorization endpoint for authorization code flow
     */
    @GetMapping("/oauth2/authorize")
    @Operation(summary = "Authorization Endpoint", description = "Initiates authorization code flow")
    public ResponseEntity<Map<String, String>> authorize(
            @RequestParam String client_id,
            @RequestParam String response_type,
            @RequestParam String redirect_uri,
            @RequestParam(required = false) String scope,
            @RequestParam(required = false) String state) {

        log.debug("Authorization request for client: {}", client_id);

        // Validate client
        Optional<RegisteredClient> client = clientRepository.findByClientId(client_id);
        if (client.isEmpty() || !client.get().getEnabled()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "invalid_client"));
        }

        // Validate redirect URI
        if (!client.get().getRedirectUris().contains(redirect_uri)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "invalid_redirect_uri"));
        }

        // Generate authorization code
        String authCode = generateAuthCode();
        Map<String, String> response = new HashMap<>();
        response.put("code", authCode);
        if (state != null) {
            response.put("state", state);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Token endpoint for token exchange and refresh
     */
    @PostMapping("/oauth2/token")
    @Operation(summary = "Token Endpoint", description = "Exchanges authorization code for token or refreshes token")
    public ResponseEntity<OAuth2TokenResponse> token(@RequestBody OAuth2TokenRequest request) {
        log.debug("Token request with grant type: {}", request.getGrant_type());

        try {
            if ("client_credentials".equals(request.getGrant_type())) {
                return handleClientCredentials(request);
            } else if ("authorization_code".equals(request.getGrant_type())) {
                return handleAuthorizationCode(request);
            } else if ("refresh_token".equals(request.getGrant_type())) {
                return handleRefreshToken(request);
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(OAuth2TokenResponse.builder()
                                .error("unsupported_grant_type")
                                .build());
            }
        } catch (Exception e) {
            log.error("Token endpoint error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(OAuth2TokenResponse.builder()
                            .error("server_error")
                            .build());
        }
    }

    /**
     * Handle client credentials grant type
     */
    private ResponseEntity<OAuth2TokenResponse> handleClientCredentials(OAuth2TokenRequest request) {
        // Validate client credentials
        String client_id = request.getClient_id();
        String client_secret = request.getClient_secret();

        if (client_id == null || client_secret == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(OAuth2TokenResponse.builder()
                            .error("invalid_client")
                            .build());
        }

        Optional<RegisteredClient> client = clientRepository.findByClientId(client_id);
        if (client.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(OAuth2TokenResponse.builder()
                            .error("invalid_client")
                            .build());
        }

        RegisteredClient registeredClient = client.get();
        if (!registeredClient.getEnabled() || !registeredClient.getClientCredentialsEnabled()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(OAuth2TokenResponse.builder()
                            .error("unauthorized_client")
                            .build());
        }

        // Validate secret
        if (!passwordEncoder.matches(client_secret, registeredClient.getClientSecretHash())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(OAuth2TokenResponse.builder()
                            .error("invalid_client")
                            .build());
        }

        // Generate token
        String accessToken = generateAccessToken(client_id, request.getScope());
        Instant now = Instant.now();

        return ResponseEntity.ok(OAuth2TokenResponse.builder()
                .access_token(accessToken)
                .token_type("Bearer")
                .expires_in(accessTokenExpiration / 1000)
                .scope(request.getScope())
                .build());
    }

    /**
     * Handle authorization code grant type
     */
    private ResponseEntity<OAuth2TokenResponse> handleAuthorizationCode(OAuth2TokenRequest request) {
        // This is a simplified implementation - in production, authorization codes would be stored
        String client_id = request.getClient_id();
        String code = request.getCode();
        String redirect_uri = request.getRedirect_uri();

        if (code == null || client_id == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(OAuth2TokenResponse.builder()
                            .error("invalid_request")
                            .build());
        }

        Optional<RegisteredClient> client = clientRepository.findByClientId(client_id);
        if (client.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(OAuth2TokenResponse.builder()
                            .error("invalid_client")
                            .build());
        }

        String accessToken = generateAccessToken(client_id, request.getScope());
        String refreshToken = generateRefreshToken(client_id);

        return ResponseEntity.ok(OAuth2TokenResponse.builder()
                .access_token(accessToken)
                .refresh_token(refreshToken)
                .token_type("Bearer")
                .expires_in(accessTokenExpiration / 1000)
                .scope(request.getScope())
                .build());
    }

    /**
     * Handle refresh token grant type
     */
    private ResponseEntity<OAuth2TokenResponse> handleRefreshToken(OAuth2TokenRequest request) {
        String refresh_token = request.getRefresh_token();
        String client_id = request.getClient_id();

        if (refresh_token == null || client_id == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(OAuth2TokenResponse.builder()
                            .error("invalid_request")
                            .build());
        }

        // Validate client exists
        Optional<RegisteredClient> client = clientRepository.findByClientId(client_id);
        if (client.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(OAuth2TokenResponse.builder()
                            .error("invalid_client")
                            .build());
        }

        String accessToken = generateAccessToken(client_id, request.getScope());

        return ResponseEntity.ok(OAuth2TokenResponse.builder()
                .access_token(accessToken)
                .token_type("Bearer")
                .expires_in(accessTokenExpiration / 1000)
                .scope(request.getScope())
                .build());
    }

    /**
     * Token introspection endpoint
     */
    @PostMapping("/oauth2/introspect")
    @Operation(summary = "Token Introspection", description = "Returns information about a token")
    public ResponseEntity<Map<String, Object>> introspect(@RequestBody Map<String, String> request) {
        log.debug("Token introspection request");

        String token = request.get("token");
        if (token == null) {
            return ResponseEntity.badRequest().build();
        }

        // Simplified implementation - just return active:true for valid tokens
        try {
            Map<String, Object> introspection = new HashMap<>();
            introspection.put("active", true);
            introspection.put("scope", "read write");
            introspection.put("client_id", "client");
            introspection.put("token_type", "Bearer");
            introspection.put("exp", System.currentTimeMillis() / 1000 + (accessTokenExpiration / 1000));

            return ResponseEntity.ok(introspection);
        } catch (Exception e) {
            return ResponseEntity.ok(Map.of("active", false));
        }
    }

    /**
     * Token revocation endpoint
     */
    @PostMapping("/oauth2/revoke")
    @Operation(summary = "Token Revocation", description = "Revokes a token")
    public ResponseEntity<Void> revoke(@RequestBody Map<String, String> request) {
        log.debug("Token revocation request");
        String token = request.get("token");
        if (token == null) {
            return ResponseEntity.badRequest().build();
        }
        // Simplified implementation - just return 200
        return ResponseEntity.ok().build();
    }

    /**
     * Generate authorization code
     */
    private String generateAuthCode() {
        return "auth_" + System.currentTimeMillis() + "_" + (int) (Math.random() * 10000);
    }

    /**
     * Generate access token
     */
    private String generateAccessToken(String clientId, String scope) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("auth-server")
                .issuedAt(now)
                .expiresAt(now.plusMillis(accessTokenExpiration))
                .subject(clientId)
                .claim("client_id", clientId)
                .claim("scope", scope != null ? scope : "read write")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    /**
     * Generate refresh token
     */
    private String generateRefreshToken(String clientId) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("auth-server")
                .issuedAt(now)
                .expiresAt(now.plusMillis(refreshTokenExpiration))
                .subject(clientId)
                .claim("type", "refresh")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }
}
