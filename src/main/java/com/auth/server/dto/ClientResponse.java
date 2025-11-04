package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Response containing OAuth2 client information.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientResponse {

    @JsonProperty("id")
    private UUID id;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_name")
    private String clientName;

    @JsonProperty("description")
    private String description;

    @JsonProperty("redirect_uris")
    private String redirectUris;

    @JsonProperty("scopes")
    private String scopes;

    @JsonProperty("access_token_ttl")
    private Integer accessTokenTtl;

    @JsonProperty("refresh_token_ttl")
    private Integer refreshTokenTtl;

    @JsonProperty("enabled")
    private Boolean enabled;

    @JsonProperty("client_credentials_enabled")
    private Boolean clientCredentialsEnabled;

    @JsonProperty("authorization_code_enabled")
    private Boolean authorizationCodeEnabled;

    @JsonProperty("refresh_token_enabled")
    private Boolean refreshTokenEnabled;

    @JsonProperty("contact_email")
    private String contactEmail;

    @JsonProperty("owner")
    private String owner;

    @JsonProperty("created_at")
    private LocalDateTime createdAt;

    @JsonProperty("updated_at")
    private LocalDateTime updatedAt;

    @JsonProperty("last_used_at")
    private LocalDateTime lastUsedAt;
}
