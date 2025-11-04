package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Min;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request to create a new OAuth2 client.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientCreateRequest {

    /**
     * Unique client identifier (alphanumeric with hyphens/underscores).
     */
    @NotBlank(message = "Client ID is required")
    @Pattern(regexp = "^[a-zA-Z0-9_-]{3,100}$", message = "Client ID must be 3-100 alphanumeric characters (- and _ allowed)")
    @JsonProperty("client_id")
    private String clientId;

    /**
     * Human-readable client name.
     */
    @NotBlank(message = "Client name is required")
    @JsonProperty("client_name")
    private String clientName;

    /**
     * Client description.
     */
    @JsonProperty("description")
    private String description;

    /**
     * Comma-separated redirect URIs.
     */
    @JsonProperty("redirect_uris")
    private String redirectUris;

    /**
     * Comma-separated scopes (e.g., "read,write").
     */
    @JsonProperty("scopes")
    private String scopes;

    /**
     * Access token TTL in seconds.
     */
    @Min(value = 60, message = "Access token TTL must be at least 60 seconds")
    @JsonProperty("access_token_ttl")
    private Integer accessTokenTtl;

    /**
     * Refresh token TTL in seconds.
     */
    @Min(value = 3600, message = "Refresh token TTL must be at least 1 hour (3600 seconds)")
    @JsonProperty("refresh_token_ttl")
    private Integer refreshTokenTtl;

    /**
     * Contact email.
     */
    @JsonProperty("contact_email")
    private String contactEmail;

    /**
     * Client owner/organization name.
     */
    @JsonProperty("owner")
    private String owner;

    /**
     * Allow client credentials flow.
     */
    @JsonProperty("client_credentials_enabled")
    private Boolean clientCredentialsEnabled;

    /**
     * Allow authorization code flow.
     */
    @JsonProperty("authorization_code_enabled")
    private Boolean authorizationCodeEnabled;

    /**
     * Allow refresh token flow.
     */
    @JsonProperty("refresh_token_enabled")
    private Boolean refreshTokenEnabled;
}
