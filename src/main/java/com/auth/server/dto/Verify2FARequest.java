package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request to verify 2FA setup with a TOTP code.
 * User gets the 6-digit code from their authenticator app and sends it here.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Verify2FARequest {

    /**
     * The 6-digit TOTP code from authenticator app.
     * Must be exactly 6 digits.
     */
    @NotBlank(message = "TOTP code is required")
    @Pattern(regexp = "^[0-9]{6}$", message = "Code must be exactly 6 digits")
    @JsonProperty("code")
    private String code;
}
