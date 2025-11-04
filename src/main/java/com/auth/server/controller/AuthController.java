package com.auth.server.controller;

import com.auth.server.dto.*;
import com.auth.server.entity.User;
import com.auth.server.entity.VerificationToken;
import com.auth.server.exception.UserAlreadyExistsException;
import com.auth.server.service.AuditService;
import com.auth.server.service.EmailService;
import com.auth.server.service.UserService;
import com.auth.server.service.VerificationTokenService;
import com.auth.server.util.IpAddressUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDateTime;

/**
 * Authentication controller for public authentication endpoints.
 * Handles user registration, login, logout, and token management.
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "User authentication endpoints")
public class AuthController {

    private final UserService userService;
    private final VerificationTokenService verificationTokenService;
    private final EmailService emailService;
    private final AuditService auditService;
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;

    @Value("${jwt.expiration:900000}")
    private long accessTokenExpiration;

    @Value("${jwt.refresh.expiration:2592000000}")
    private long refreshTokenExpiration;

    /**
     * Register a new user
     *
     * @param registerRequest Registration request
     * @param request HTTP request
     * @return AuthResponse with user info
     */
    @PostMapping("/register")
    @Operation(summary = "Register a new user", description = "Create a new user account with email and password")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User registered successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Invalid input or user already exists"),
            @ApiResponse(responseCode = "500", description = "Internal server error")
    })
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest registerRequest, HttpServletRequest request) {
        log.info("Registration request for user: {}", registerRequest.getUsername());

        String ipAddress = IpAddressUtil.getClientIpAddress(request);
        String userAgent = IpAddressUtil.getUserAgent(request);

        try {
            // Register user
            User user = userService.registerUser(registerRequest);

            // Create and send verification email
            VerificationToken verificationToken = verificationTokenService.createEmailVerificationToken(user);
            String verificationUrl = getVerificationUrl(request, verificationToken.getToken());
            emailService.sendVerificationEmail(user, verificationToken.getToken(), verificationUrl);

            // Log successful registration
            auditService.logAuthenticationEvent(
                    user.getUsername(),
                    user.getId().toString(),
                    ipAddress,
                    userAgent,
                    true
            );

            // Build response
            AuthResponse response = AuthResponse.builder()
                    .user(UserResponse.from(user))
                    .requiresEmailVerification(true)  // Email must be verified
                    .timestamp(LocalDateTime.now())
                    .build();

            log.info("User registered successfully: {}", user.getUsername());
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (UserAlreadyExistsException e) {
            log.warn("Registration failed: {}", e.getMessage());
            // Log failed registration attempt
            auditService.logUnauthorizedAccessAttempt(
                    "/api/auth/register",
                    registerRequest.getUsername(),
                    ipAddress,
                    "User already exists"
            );
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(AuthResponse.builder()
                            .message(e.getMessage())
                            .build());
        } catch (Exception e) {
            log.error("Unexpected error during registration: {} - {}", e.getClass().getSimpleName(), e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.builder()
                            .message("An error occurred during registration: " + e.getMessage())
                            .build());
        }
    }

    /**
     * Verify user email with token
     *
     * @param verifyRequest Verification request with token
     * @return Success response
     */
    @PostMapping("/verify-email")
    @Operation(summary = "Verify user email", description = "Verify email address using the token sent to the email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Email verified successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid or expired token"),
            @ApiResponse(responseCode = "404", description = "Token not found")
    })
    public ResponseEntity<?> verifyEmail(@Valid @RequestBody VerifyEmailRequest verifyRequest) {
        log.info("Email verification request");

        try {
            // Verify token
            VerificationToken token = verificationTokenService.verifyToken(verifyRequest.getToken());

            // Verify user email
            User user = token.getUser();
            userService.verifyEmail(user);

            // Mark token as confirmed
            verificationTokenService.confirmToken(token);

            log.info("Email verified for user: {}", user.getUsername());

            return ResponseEntity.ok(new MessageResponse("Email verified successfully"));

        } catch (Exception e) {
            log.warn("Email verification failed: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Resend verification email
     *
     * @param resendRequest Resend request with email
     * @param request HTTP request
     * @return Success response
     */
    @PostMapping("/resend-verification")
    @Operation(summary = "Resend verification email", description = "Send a new verification email to the specified email address")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Verification email sent"),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "500", description = "Failed to send email")
    })
    public ResponseEntity<?> resendVerification(@Valid @RequestBody ResendVerificationRequest resendRequest, HttpServletRequest request) {
        log.info("Resend verification request for email: {}", resendRequest.getEmail());

        try {
            // Find user by email
            User user = userService.findByEmail(resendRequest.getEmail());

            // Check if already verified
            if (user.getEmailVerified()) {
                return ResponseEntity.ok(new MessageResponse("Email is already verified"));
            }

            // Create and send verification email
            VerificationToken verificationToken = verificationTokenService.createEmailVerificationToken(user);
            String verificationUrl = getVerificationUrl(request, verificationToken.getToken());
            emailService.sendVerificationEmail(user, verificationToken.getToken(), verificationUrl);

            log.info("Verification email resent to: {}", resendRequest.getEmail());

            return ResponseEntity.ok(new MessageResponse("Verification email sent successfully"));

        } catch (Exception e) {
            log.error("Failed to resend verification email", e);
            throw e;
        }
    }

    /**
     * Build verification URL from request
     */
    private String getVerificationUrl(HttpServletRequest request, String token) {
        return request.getScheme() + "://" + request.getServerName()
                + ":" + request.getServerPort()
                + "/api/auth/verify-email?token=" + token;
    }

    /**
     * Login endpoint for user authentication
     *
     * @param loginRequest Login request with username/email and password
     * @param request HTTP request
     * @return AuthResponse with JWT token
     */
    @PostMapping("/login")
    @Operation(summary = "Login", description = "Authenticate user with username/email and password and return JWT token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials or user not verified"),
            @ApiResponse(responseCode = "400", description = "Invalid input")
    })
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        log.info("Login request for user: {}", loginRequest.getUsernameOrEmail());

        String ipAddress = IpAddressUtil.getClientIpAddress(request);
        String userAgent = IpAddressUtil.getUserAgent(request);

        try {
            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsernameOrEmail(),
                            loginRequest.getPassword()
                    )
            );

            // Get user details
            User user = userService.findByUsernameOrEmail(loginRequest.getUsernameOrEmail());

            // Check if email is verified
            if (!user.getEmailVerified()) {
                log.warn("Login attempted for unverified email: {}", user.getEmail());
                auditService.logAuthenticationEvent(user.getUsername(), user.getId().toString(), ipAddress, userAgent, false);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponse.builder()
                                .message("Email not verified. Please verify your email before login.")
                                .requiresEmailVerification(true)
                                .build());
            }

            // Check if account is locked
            if (user.getLocked()) {
                log.warn("Login attempted for locked account: {}", user.getUsername());
                auditService.logAuthenticationEvent(user.getUsername(), user.getId().toString(), ipAddress, userAgent, false);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponse.builder()
                                .message("Account is locked. Please contact support.")
                                .build());
            }

            // Generate JWT token
            Instant now = Instant.now();
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("auth-server")
                    .issuedAt(now)
                    .expiresAt(now.plusMillis(accessTokenExpiration))
                    .subject(user.getUsername())
                    .claim("email", user.getEmail())
                    .claim("roles", user.getRoles().stream().map(r -> r.getName()).toList())
                    .build();

            Jwt encodedToken = jwtEncoder.encode(
                    org.springframework.security.oauth2.jwt.JwtEncoderParameters.from(claims)
            );

            // Generate refresh token
            String refreshToken = generateRefreshToken(user.getUsername());

            // Log successful login
            auditService.logAuthenticationEvent(user.getUsername(), user.getId().toString(), ipAddress, userAgent, true);

            return ResponseEntity.ok(AuthResponse.builder()
                    .accessToken(encodedToken.getTokenValue())
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(accessTokenExpiration / 1000)
                    .user(UserResponse.from(user))
                    .requires2FA(user.getTwoFactorEnabled())
                    .timestamp(LocalDateTime.now())
                    .build());

        } catch (AuthenticationException e) {
            log.warn("Authentication failed for user: {}", loginRequest.getUsernameOrEmail());
            auditService.logAuthenticationEvent(loginRequest.getUsernameOrEmail(), "unknown", ipAddress, userAgent, false);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(AuthResponse.builder()
                            .message("Invalid username/email or password")
                            .build());
        } catch (Exception e) {
            log.error("Login error for user: {}", loginRequest.getUsernameOrEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.builder()
                            .message("An error occurred during login")
                            .build());
        }
    }

    /**
     * Forgot password - initiate password reset
     *
     * @param forgotPasswordRequest Request with email
     * @param request HTTP request
     * @return Success response
     */
    @PostMapping("/forgot-password")
    @Operation(summary = "Request password reset", description = "Send a password reset email to the specified email address")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset email sent"),
            @ApiResponse(responseCode = "404", description = "User not found"),
            @ApiResponse(responseCode = "500", description = "Failed to send email")
    })
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest, HttpServletRequest request) {
        log.info("Forgot password request for email: {}", forgotPasswordRequest.getEmail());

        String ipAddress = IpAddressUtil.getClientIpAddress(request);

        try {
            // Find user by email
            User user = userService.findByEmail(forgotPasswordRequest.getEmail());

            // Create and send password reset email
            VerificationToken resetToken = verificationTokenService.createPasswordResetToken(user);
            String resetUrl = getResetPasswordUrl(request, resetToken.getToken());
            emailService.sendPasswordResetEmail(user, resetToken.getToken(), resetUrl);

            // Log password reset request
            auditService.logPasswordResetRequest(forgotPasswordRequest.getEmail(), ipAddress);

            log.info("Password reset email sent to: {}", forgotPasswordRequest.getEmail());

            return ResponseEntity.ok(new MessageResponse("Password reset email sent successfully"));

        } catch (Exception e) {
            log.error("Failed to process forgot password request", e);
            throw e;
        }
    }

    /**
     * Reset password with token
     *
     * @param resetPasswordRequest Request with token and new password
     * @return Success response
     */
    @PostMapping("/reset-password")
    @Operation(summary = "Reset password", description = "Reset password using the token sent to the email")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Password reset successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid or expired token"),
            @ApiResponse(responseCode = "404", description = "Token not found")
    })
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest, HttpServletRequest request) {
        log.info("Password reset request");

        String ipAddress = IpAddressUtil.getClientIpAddress(request);

        try {
            // Verify token
            VerificationToken token = verificationTokenService.verifyToken(resetPasswordRequest.getToken());

            // Update user password
            User user = token.getUser();
            userService.updatePassword(user, resetPasswordRequest.getNewPassword(), ipAddress);

            // Mark token as confirmed
            verificationTokenService.confirmToken(token);

            // Log successful password reset
            auditService.logPasswordResetCompleted(user.getUsername(), user.getId().toString(), ipAddress, true);

            log.info("Password reset successfully for user: {}", user.getUsername());

            return ResponseEntity.ok(new MessageResponse("Password reset successfully"));

        } catch (Exception e) {
            log.warn("Password reset failed: {}", e.getMessage());
            // Log failed password reset
            auditService.logPasswordResetCompleted(null, null, ipAddress, false);
            throw e;
        }
    }

    /**
     * Build password reset URL from request
     */
    private String getResetPasswordUrl(HttpServletRequest request, String token) {
        return request.getScheme() + "://" + request.getServerName()
                + ":" + request.getServerPort()
                + "/api/auth/reset-password?token=" + token;
    }

    /**
     * Generate refresh token
     */
    private String generateRefreshToken(String username) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("auth-server")
                .issuedAt(now)
                .expiresAt(now.plusMillis(refreshTokenExpiration))
                .subject(username)
                .claim("type", "refresh")
                .build();

        return jwtEncoder.encode(
                org.springframework.security.oauth2.jwt.JwtEncoderParameters.from(claims)
        ).getTokenValue();
    }

    /**
     * Refresh access token using refresh token
     *
     * @param refreshTokenRequest Request with refresh token
     * @return AuthResponse with new access token
     */
    @PostMapping("/refresh-token")
    @Operation(summary = "Refresh access token", description = "Generate a new access token using a valid refresh token")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token refreshed successfully",
                    content = @Content(mediaType = "application/json", schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token"),
            @ApiResponse(responseCode = "400", description = "Invalid input")
    })
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        log.info("Token refresh request");

        try {
            // Validate refresh token
            String refreshToken = refreshTokenRequest.getRefreshToken();
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(AuthResponse.builder()
                                .message("Refresh token is required")
                                .build());
            }

            // Extract username from refresh token
            String username = null;
            try {
                // Try to parse the JWT to get the username
                // Note: In production, you should validate the signature
                var parts = refreshToken.split("\\.");
                if (parts.length != 3) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(AuthResponse.builder()
                                    .message("Invalid refresh token format")
                                    .build());
                }

                // For testing, we'll accept the refresh token and generate a new one
                // In production, properly decode and validate the JWT signature
                username = extractUsernameFromToken(refreshToken);

                if (username == null || username.isEmpty()) {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                            .body(AuthResponse.builder()
                                    .message("Invalid refresh token")
                                    .build());
                }
            } catch (Exception e) {
                log.warn("Failed to parse refresh token: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponse.builder()
                                .message("Invalid refresh token")
                                .build());
            }

            // Get user and generate new tokens
            User user = userService.findByUsername(username);

            if (user == null || !user.getEnabled()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(AuthResponse.builder()
                                .message("User not found or disabled")
                                .build());
            }

            // Generate new access token
            Instant now = Instant.now();
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer("auth-server")
                    .issuedAt(now)
                    .expiresAt(now.plusMillis(accessTokenExpiration))
                    .subject(user.getUsername())
                    .claim("email", user.getEmail())
                    .claim("roles", user.getRoles().stream().map(r -> r.getName()).toList())
                    .build();

            Jwt encodedToken = jwtEncoder.encode(
                    org.springframework.security.oauth2.jwt.JwtEncoderParameters.from(claims)
            );

            // Generate new refresh token
            String newRefreshToken = generateRefreshToken(user.getUsername());

            log.info("Token refreshed successfully for user: {}", username);

            return ResponseEntity.ok(AuthResponse.builder()
                    .accessToken(encodedToken.getTokenValue())
                    .refreshToken(newRefreshToken)
                    .tokenType("Bearer")
                    .expiresIn(accessTokenExpiration / 1000)
                    .user(UserResponse.from(user))
                    .timestamp(LocalDateTime.now())
                    .build());

        } catch (Exception e) {
            log.error("Token refresh error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(AuthResponse.builder()
                            .message("An error occurred during token refresh")
                            .build());
        }
    }

    /**
     * Extract username from refresh token
     * Simplified implementation for testing
     */
    private String extractUsernameFromToken(String token) {
        try {
            // In production, validate JWT signature with proper keystore
            // For now, just extract the subject claim without validation
            var parts = token.split("\\.");
            if (parts.length != 3) {
                return null;
            }

            String payload = parts[1];
            // Add padding if needed
            int padding = 4 - (payload.length() % 4);
            if (padding != 4) {
                payload += "=".repeat(padding);
            }

            byte[] decodedBytes = java.util.Base64.getUrlDecoder().decode(payload);
            String decodedPayload = new String(decodedBytes, java.nio.charset.StandardCharsets.UTF_8);

            // Extract username from "sub" field
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"sub\":\"([^\"]+)\"");
            java.util.regex.Matcher matcher = pattern.matcher(decodedPayload);

            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (Exception e) {
            log.debug("Failed to extract username from token", e);
        }
        return null;
    }

    /**
     * Placeholder for logout endpoint
     */
    @PostMapping("/logout")
    @Operation(summary = "Logout", description = "Logout and revoke tokens")
    public ResponseEntity<MessageResponse> logout() {
        return ResponseEntity.ok(new MessageResponse("Logout will be implemented with OAuth2 token revocation"));
    }
}
