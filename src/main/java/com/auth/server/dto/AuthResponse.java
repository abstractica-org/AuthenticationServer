package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO for authentication response (returned after successful login/registration)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("token_type")
    @Builder.Default
    private String tokenType = "Bearer";

    @JsonProperty("expires_in")
    private Long expiresIn;

    private UserResponse user;

    @JsonProperty("requires_email_verification")
    private Boolean requiresEmailVerification;

    @JsonProperty("requires_2fa")
    private Boolean requires2FA;

    @JsonProperty("2fa_token")
    private String twoFAToken;

    private String message;

    private LocalDateTime timestamp;
}
