package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Response after successful 2FA verification.
 * Contains backup codes for account recovery.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Verify2FAResponse {

    /**
     * Status message.
     */
    @JsonProperty("message")
    private String message;

    /**
     * Indicates 2FA is now enabled.
     */
    @JsonProperty("two_factor_enabled")
    private boolean twoFactorEnabled;

    /**
     * List of backup codes for account recovery.
     * User should save these in a secure location.
     */
    @JsonProperty("backup_codes")
    private List<String> backupCodes;

    /**
     * Instructions on using backup codes.
     */
    @JsonProperty("backup_codes_instructions")
    private String backupCodesInstructions;
}
