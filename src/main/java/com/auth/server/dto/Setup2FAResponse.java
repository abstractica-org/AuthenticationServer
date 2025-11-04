package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Response containing TOTP secret and QR code for user to set up 2FA.
 * User scans QR code with authenticator app (Google Authenticator, Microsoft Authenticator, etc.)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Setup2FAResponse {

    /**
     * The TOTP secret key (Base32-encoded).
     * User can enter this manually if QR code doesn't work.
     */
    @JsonProperty("secret")
    private String secret;

    /**
     * QR code as Base64-encoded PNG image.
     * User scans this with authenticator app.
     * Format: data:image/png;base64,iVBORw0KGgo...
     */
    @JsonProperty("qr_code_image")
    private String qrCodeImage;

    /**
     * TOTP authentication URL (otpauth://).
     * Alternative to QR code if preferred.
     */
    @JsonProperty("totp_uri")
    private String totpUri;

    /**
     * Instructions for user on how to set up 2FA.
     */
    @JsonProperty("setup_instructions")
    private String setupInstructions;

    /**
     * Message indicating setup success.
     */
    @JsonProperty("message")
    private String message;
}
