package com.auth.server.service;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Service for handling Two-Factor Authentication using TOTP (Time-based One-Time Password).
 *
 * Uses Google Authenticator, Microsoft Authenticator, or similar apps.
 * Each code is valid for 30 seconds.
 */
@Slf4j
@Service
public class TotpService {

    private final SecretGenerator secretGenerator;
    private final CodeVerifier codeVerifier;
    private final CodeGenerator codeGenerator;
    private final QrGenerator qrGenerator;

    public TotpService() {
        this.secretGenerator = new DefaultSecretGenerator();
        this.codeGenerator = new DefaultCodeGenerator();
        this.codeVerifier = new DefaultCodeVerifier(codeGenerator, new SystemTimeProvider());
        this.qrGenerator = new ZxingPngQrGenerator();
    }

    /**
     * Generate a new TOTP secret for user.
     * Each user gets a unique secret key.
     *
     * @return Base32-encoded secret (can be shared with authenticator app)
     */
    public String generateSecret() {
        try {
            String secret = secretGenerator.generate();
            log.debug("Generated new TOTP secret");
            return secret;
        } catch (Exception e) {
            log.error("Error generating TOTP secret", e);
            throw new RuntimeException("Failed to generate TOTP secret", e);
        }
    }

    /**
     * Get QR code as Base64-encoded PNG for displaying to user.
     * User can scan this with authenticator app.
     *
     * @param secret The TOTP secret
     * @param email User's email
     * @param appName Application name (displayed in authenticator app)
     * @return Base64-encoded PNG image
     */
    public String getQrCodeAsBase64(String secret, String email, String appName) {
        try {
            QrData data = new QrData.Builder()
                    .label(email)
                    .secret(secret)
                    .issuer(appName)
                    .digits(6)                          // 6-digit codes
                    .period(30)                         // 30-second window
                    .build();

            byte[] qrCode = qrGenerator.generate(data);
            String base64 = Base64.getEncoder().encodeToString(qrCode);
            log.debug("Generated QR code for user: {}", email);
            return base64;
        } catch (Exception e) {
            log.error("Error generating QR code", e);
            throw new RuntimeException("Failed to generate QR code", e);
        }
    }

    /**
     * Get QR code URL (alternative to Base64, for external QR generators).
     * Can be used with services like qr-server.com
     *
     * @param secret The TOTP secret
     * @param email User's email
     * @param appName Application name
     * @return URL-encoded data for QR code
     */
    public String getQrCodeUrl(String secret, String email, String appName) {
        try {
            String label = URLEncoder.encode(email, StandardCharsets.UTF_8.toString());
            String issuer = URLEncoder.encode(appName, StandardCharsets.UTF_8.toString());

            String otpauthUrl = String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                issuer, label, secret, issuer
            );

            log.debug("Generated TOTP URL for user: {}", email);
            return otpauthUrl;
        } catch (UnsupportedEncodingException e) {
            log.error("Error generating QR code URL", e);
            throw new RuntimeException("Failed to generate QR code URL", e);
        }
    }

    /**
     * Verify a TOTP code against the secret.
     *
     * @param secret The TOTP secret
     * @param code The 6-digit code from authenticator app
     * @return true if code is valid, false otherwise
     */
    public boolean verifyCode(String secret, String code) {
        try {
            // Allow for time drift of ±1 time window (30 seconds)
            boolean isValid = codeVerifier.isValidCode(secret, code);

            if (isValid) {
                log.debug("TOTP code verified successfully");
            } else {
                log.warn("Invalid TOTP code provided");
            }

            return isValid;
        } catch (Exception e) {
            log.error("Error verifying TOTP code", e);
            return false;
        }
    }

    /**
     * Generate backup codes for account recovery if user loses authenticator.
     * These are single-use codes.
     *
     * @param count Number of backup codes to generate (typically 8-10)
     * @return List of backup codes (8 characters each)
     */
    public List<String> generateBackupCodes(int count) {
        SecureRandom random = new SecureRandom();
        List<String> backupCodes = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            // Generate 8 random bytes, encode as hex (16 chars), take first 8
            byte[] randomBytes = new byte[4];
            random.nextBytes(randomBytes);
            String code = String.format("%08X", random.nextInt()).substring(0, 8);
            backupCodes.add(code);
        }

        log.debug("Generated {} backup codes", count);
        return backupCodes;
    }

    /**
     * Validate a backup code format (8 alphanumeric characters).
     *
     * @param code The backup code to validate
     * @return true if format is valid
     */
    public boolean isValidBackupCodeFormat(String code) {
        return code != null && code.matches("^[A-Z0-9]{8}$");
    }

    /**
     * Hash backup codes before storing in database.
     * Uses Base64 encoding for storage.
     *
     * @param codes List of backup codes
     * @return Comma-separated Base64-encoded codes
     */
    public String encodeBackupCodesForStorage(List<String> codes) {
        StringBuilder encoded = new StringBuilder();
        for (int i = 0; i < codes.size(); i++) {
            String base64 = Base64.getEncoder().encodeToString(
                codes.get(i).getBytes(StandardCharsets.UTF_8)
            );
            encoded.append(base64);
            if (i < codes.size() - 1) {
                encoded.append(",");
            }
        }
        return encoded.toString();
    }

    /**
     * Decode backup codes from storage.
     *
     * @param encoded Comma-separated Base64-encoded codes
     * @return List of original backup codes
     */
    public List<String> decodeBackupCodesFromStorage(String encoded) {
        List<String> codes = new ArrayList<>();
        if (encoded == null || encoded.isEmpty()) {
            return codes;
        }

        String[] parts = encoded.split(",");
        for (String part : parts) {
            try {
                String decoded = new String(
                    Base64.getDecoder().decode(part),
                    StandardCharsets.UTF_8
                );
                codes.add(decoded);
            } catch (IllegalArgumentException e) {
                log.warn("Failed to decode backup code", e);
            }
        }
        return codes;
    }
}
