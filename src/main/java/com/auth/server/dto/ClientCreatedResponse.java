package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Response when creating a new OAuth2 client.
 * **IMPORTANT:** Client secret is ONLY returned in this response.
 * The client MUST save this secret immediately - it cannot be retrieved later.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientCreatedResponse {

    @JsonProperty("id")
    private UUID id;

    @JsonProperty("client_id")
    private String clientId;

    /**
     * **IMPORTANT:** This is the ONLY time the plain-text secret is shown.
     * The client must save this immediately. It cannot be retrieved later.
     */
    @JsonProperty("client_secret")
    private String clientSecret;

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("description")
    private String description;

    @JsonProperty("enabled")
    private Boolean enabled;

    @JsonProperty("created_at")
    private LocalDateTime createdAt;

    @JsonProperty("warning")
    @Builder.Default
    private String warning = "IMPORTANT: Save your client secret immediately. It will NOT be shown again!";
}
