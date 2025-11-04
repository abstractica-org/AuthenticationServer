package com.auth.server.util;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * HMAC Signature Utility
 * <p>
 * Provides methods for generating and verifying HMAC-SHA256 signatures.
 * Used for webhook authentication and ensuring message integrity.
 * </p>
 * <p>
 * Usage:
 * - Generate signature: HmacSignatureUtil.generateSignature(payload, secret)
 * - Verify signature: HmacSignatureUtil.verifySignature(payload, providedSignature, secret)
 * </p>
 */
@Slf4j
@UtilityClass
public class HmacSignatureUtil {

    private static final String ALGORITHM = "HmacSHA256";
    private static final String ENCODING = "UTF-8";

    static {
        // Ensure UTF-8 charset is available
        try {
            java.nio.charset.Charset.forName(ENCODING);
        } catch (Exception e) {
            throw new ExceptionInInitializerError("UTF-8 charset not available");
        }
    }

    /**
     * Generate HMAC-SHA256 signature for the given payload
     *
     * @param payload Payload to sign
     * @param secret  Secret key (at least 32 bytes recommended)
     * @return Base64-encoded signature
     * @throws RuntimeException if signature generation fails
     */
    public static String generateSignature(String payload, String secret) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(ENCODING), 0, secret.getBytes(ENCODING).length, ALGORITHM);
            mac.init(secretKeySpec);

            byte[] digest = mac.doFinal(payload.getBytes(ENCODING));
            String signature = Base64.getEncoder().encodeToString(digest);

            log.debug("Generated HMAC-SHA256 signature for payload");
            return signature;
        } catch (NoSuchAlgorithmException e) {
            log.error("HMAC-SHA256 algorithm not available", e);
            throw new RuntimeException("Failed to generate signature: HMAC-SHA256 not available", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid secret key for HMAC signature", e);
            throw new RuntimeException("Failed to generate signature: Invalid secret key", e);
        } catch (Exception e) {
            log.error("Unexpected error generating signature", e);
            throw new RuntimeException("Failed to generate signature", e);
        }
    }

    /**
     * Verify HMAC-SHA256 signature using constant-time comparison
     * <p>
     * Uses constant-time comparison to prevent timing attacks.
     * </p>
     *
     * @param payload          Payload to verify
     * @param providedSignature Signature provided by client
     * @param secret           Secret key
     * @return true if signature is valid, false otherwise
     */
    public static boolean verifySignature(String payload, String providedSignature, String secret) {
        try {
            String expectedSignature = generateSignature(payload, secret);
            boolean isValid = constantTimeEquals(expectedSignature, providedSignature);

            if (!isValid) {
                log.warn("Signature verification failed - signature mismatch");
            } else {
                log.debug("Signature verification successful");
            }

            return isValid;
        } catch (Exception e) {
            log.error("Error verifying signature", e);
            return false;
        }
    }

    /**
     * Constant-time string comparison to prevent timing attacks
     * <p>
     * Regular string comparison (.equals()) can leak information about which
     * characters match/don't match based on comparison time. This method uses
     * constant time comparison.
     * </p>
     *
     * @param a First string
     * @param b Second string
     * @return true if strings are equal, false otherwise
     */
    private static boolean constantTimeEquals(String a, String b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }

        byte[] aBytes = a.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        return constantTimeEquals(aBytes, bBytes);
    }

    /**
     * Constant-time byte array comparison
     *
     * @param a First byte array
     * @param b Second byte array
     * @return true if arrays are equal, false otherwise
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }

        return result == 0;
    }

    /**
     * Generate signature for webhook header
     * <p>
     * Generates an HMAC-SHA256 signature suitable for use in webhook headers.
     * The signature is typically sent as: X-Signature: sha256={signature}
     * </p>
     *
     * @param payload Webhook payload (typically JSON)
     * @param secret  Webhook secret
     * @return Formatted signature for header (sha256=base64_encoded_signature)
     */
    public static String generateWebhookSignature(String payload, String secret) {
        String signature = generateSignature(payload, secret);
        return "sha256=" + signature;
    }

    /**
     * Verify webhook signature from header
     *
     * @param payload        Webhook payload
     * @param headerSignature Signature from header (e.g., "sha256=base64...")
     * @param secret         Webhook secret
     * @return true if signature is valid
     */
    public static boolean verifyWebhookSignature(String payload, String headerSignature, String secret) {
        if (headerSignature == null || !headerSignature.startsWith("sha256=")) {
            log.warn("Invalid webhook signature header format");
            return false;
        }

        String providedSignature = headerSignature.substring("sha256=".length());
        return verifySignature(payload, providedSignature, secret);
    }
}
