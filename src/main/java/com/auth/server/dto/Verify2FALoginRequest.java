package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request to complete login when user has 2FA enabled.
 * User must enter 2FA code or backup code after successful username/password authentication.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Verify2FALoginRequest {

    /**
     * Temporary token from initial login (without 2FA verification).
     * Contains user info but is not valid for API access.
     */
    @NotBlank(message = "2FA token is required")
    @JsonProperty("two_factor_token")
    private String twoFactorToken;

    /**
     * The 6-digit TOTP code from authenticator app OR 8-character backup code.
     */
    @NotBlank(message = "Code is required")
    @JsonProperty("code")
    private String code;
}
