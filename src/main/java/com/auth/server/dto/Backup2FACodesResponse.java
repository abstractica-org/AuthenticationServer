package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Response containing newly generated backup codes for 2FA recovery.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Backup2FACodesResponse {

    /**
     * List of new backup codes.
     * Each code is 8 alphanumeric characters.
     */
    @JsonProperty("backup_codes")
    private List<String> backupCodes;

    /**
     * Message indicating codes were generated.
     */
    @JsonProperty("message")
    private String message;

    /**
     * Instructions on using backup codes.
     */
    @JsonProperty("instructions")
    private String instructions;
}
