package com.auth.server.controller;

import com.auth.server.dto.*;
import com.auth.server.entity.User;
import com.auth.server.service.AuditService;
import com.auth.server.service.TotpService;
import com.auth.server.service.UserService;
import com.auth.server.util.IpAddressUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * User controller for user profile and information endpoints.
 */
@Slf4j
@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "Users", description = "User profile and information endpoints")
public class UserController {

    private final UserService userService;
    private final TotpService totpService;
    private final AuditService auditService;

    /**
     * Get current authenticated user profile
     *
     * @param authentication Current authentication
     * @return UserResponse with current user details
     */
    @GetMapping("/me")
    @Operation(summary = "Get current user profile", description = "Get the profile of the currently authenticated user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User profile retrieved successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - user not authenticated"),
            @ApiResponse(responseCode = "404", description = "User not found")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<UserResponse> getCurrentUser(Authentication authentication) {
        log.info("Getting profile for current user: {}", authentication.getName());

        User user = userService.findByUsername(authentication.getName());
        return ResponseEntity.ok(UserResponse.from(user));
    }

    /**
     * Initiate 2FA setup for current user.
     * Returns secret and QR code for scanning with authenticator app.
     *
     * @param authentication Current authentication
     * @return Setup2FAResponse with secret and QR code
     */
    @PostMapping("/me/2fa/setup")
    @Operation(summary = "Initiate 2FA setup", description = "Get TOTP secret and QR code for setting up two-factor authentication")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "2FA setup initiated successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - user not authenticated")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<Setup2FAResponse> setup2FA(Authentication authentication) {
        log.info("Initiating 2FA setup for user: {}", authentication.getName());

        String username = authentication.getName();
        User user = userService.findByUsername(username);

        // Generate new secret
        String secret = totpService.generateSecret();

        // Generate QR code and URI
        String qrCodeBase64 = totpService.getQrCodeAsBase64(secret, user.getEmail(), "Auth Server");
        String totpUri = totpService.getQrCodeUrl(secret, user.getEmail(), "Auth Server");

        Setup2FAResponse response = Setup2FAResponse.builder()
                .secret(secret)
                .qrCodeImage(qrCodeBase64)
                .totpUri(totpUri)
                .setupInstructions(
                    "1. Scan the QR code with your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, etc.)\n" +
                    "2. Or manually enter the secret key above\n" +
                    "3. You will receive a 6-digit code that changes every 30 seconds\n" +
                    "4. Submit the code at the verify endpoint to complete setup\n" +
                    "5. Save your backup codes in a secure location for account recovery"
                )
                .message("2FA setup initiated. Scan the QR code with your authenticator app.")
                .build();

        return ResponseEntity.ok(response);
    }

    /**
     * Verify 2FA code and enable 2FA for current user.
     * User must enter the 6-digit code from their authenticator app.
     *
     * @param authentication Current authentication
     * @param request Contains the 6-digit verification code
     * @return Verify2FAResponse with backup codes
     */
    @PostMapping("/me/2fa/verify")
    @Operation(summary = "Verify and enable 2FA", description = "Verify TOTP code and enable two-factor authentication")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "2FA verified and enabled successfully"),
            @ApiResponse(responseCode = "400", description = "Invalid TOTP code"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - user not authenticated")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<Verify2FAResponse> verify2FA(
            Authentication authentication,
            @Valid @RequestBody Verify2FARequest request,
            HttpServletRequest httpRequest) {

        log.info("Verifying 2FA for user: {}", authentication.getName());

        String username = authentication.getName();
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);
        String userAgent = IpAddressUtil.getUserAgent(httpRequest);
        User user = userService.findByUsername(username);

        // Get the secret that was just generated in setup endpoint
        String secret = user.getTwoFactorSecret();
        if (secret == null || secret.isEmpty()) {
            log.warn("2FA verification failed for {}: no secret generated", username);
            auditService.logSuspiciousActivity(
                    username,
                    ipAddress,
                    "2FA verification attempted without setup"
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Verify2FAResponse.builder()
                            .message("2FA setup not initiated. Call setup endpoint first.")
                            .twoFactorEnabled(false)
                            .build());
        }

        // Verify the code
        if (!totpService.verifyCode(secret, request.getCode())) {
            log.warn("Invalid 2FA code provided for user: {}", username);
            auditService.logSuspiciousActivity(
                    username,
                    ipAddress,
                    "Invalid 2FA code during verification"
            );
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Verify2FAResponse.builder()
                            .message("Invalid or expired TOTP code. Please try again.")
                            .twoFactorEnabled(false)
                            .build());
        }

        // Generate backup codes
        List<String> backupCodes = totpService.generateBackupCodes(10);
        String encodedBackupCodes = totpService.encodeBackupCodesForStorage(backupCodes);

        // Enable 2FA for user
        user.setTwoFactorEnabled(true);
        user.setTwoFactorSecret(secret);
        user.setTwoFactorBackupCodes(encodedBackupCodes);
        userService.save(user);

        // Log successful 2FA enablement
        auditService.logTwoFactorAuthEnabled(
                user.getId().toString(),
                username,
                ipAddress
        );

        log.info("2FA enabled successfully for user: {}", username);

        Verify2FAResponse response = Verify2FAResponse.builder()
                .message("Two-factor authentication enabled successfully!")
                .twoFactorEnabled(true)
                .backupCodes(backupCodes)
                .backupCodesInstructions(
                    "IMPORTANT: Save these backup codes in a secure location.\n" +
                    "Each code can be used once if you lose access to your authenticator app.\n" +
                    "Do not share these codes with anyone."
                )
                .build();

        return ResponseEntity.ok(response);
    }

    /**
     * Generate new backup codes for 2FA account recovery.
     * Useful if user needs to replace lost codes.
     *
     * @param authentication Current authentication
     * @param httpRequest HTTP request
     * @return Backup2FACodesResponse with new codes
     */
    @PostMapping("/me/2fa/backup-codes")
    @Operation(summary = "Generate new backup codes", description = "Generate a new set of backup codes for 2FA recovery")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Backup codes generated successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - user not authenticated"),
            @ApiResponse(responseCode = "400", description = "2FA not enabled for user")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<Backup2FACodesResponse> generateBackupCodes(
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Generating new backup codes for user: {}", authentication.getName());

        String username = authentication.getName();
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);
        User user = userService.findByUsername(username);

        if (!user.getTwoFactorEnabled()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Backup2FACodesResponse.builder()
                            .message("2FA is not enabled for this user")
                            .build());
        }

        // Generate new backup codes
        List<String> backupCodes = totpService.generateBackupCodes(10);
        String encodedBackupCodes = totpService.encodeBackupCodesForStorage(backupCodes);

        // Update user
        user.setTwoFactorBackupCodes(encodedBackupCodes);
        userService.save(user);

        // Log backup codes generation
        auditService.logBackupCodesGenerated(
                user.getId().toString(),
                username,
                ipAddress
        );

        log.info("New backup codes generated for user: {}", username);

        Backup2FACodesResponse response = Backup2FACodesResponse.builder()
                .backupCodes(backupCodes)
                .message("New backup codes generated successfully")
                .instructions(
                    "Your old backup codes are no longer valid.\n" +
                    "Save these new codes in a secure location.\n" +
                    "Each code can be used once if you lose access to your authenticator app."
                )
                .build();

        return ResponseEntity.ok(response);
    }

    /**
     * Disable 2FA for current user.
     * This removes the requirement to enter a 2FA code on login.
     *
     * @param authentication Current authentication
     * @param httpRequest HTTP request
     * @return MessageResponse indicating 2FA was disabled
     */
    @DeleteMapping("/me/2fa")
    @Operation(summary = "Disable 2FA", description = "Disable two-factor authentication for current user")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "2FA disabled successfully"),
            @ApiResponse(responseCode = "401", description = "Unauthorized - user not authenticated")
    })
    @SecurityRequirement(name = "bearer-jwt")
    public ResponseEntity<MessageResponse> disable2FA(
            Authentication authentication,
            HttpServletRequest httpRequest) {
        log.info("Disabling 2FA for user: {}", authentication.getName());

        String username = authentication.getName();
        String ipAddress = IpAddressUtil.getClientIpAddress(httpRequest);
        User user = userService.findByUsername(username);

        // Disable 2FA
        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        user.setTwoFactorBackupCodes(null);
        userService.save(user);

        // Log 2FA disablement
        auditService.logTwoFactorAuthDisabled(
                user.getId().toString(),
                username,
                ipAddress
        );

        log.info("2FA disabled for user: {}", username);

        return ResponseEntity.ok(MessageResponse.builder()
                .message("Two-factor authentication has been disabled")
                .build());
    }
}
