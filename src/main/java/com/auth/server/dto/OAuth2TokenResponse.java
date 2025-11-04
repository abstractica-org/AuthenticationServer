package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * OAuth2 Token Response DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class OAuth2TokenResponse {

    @JsonProperty("access_token")
    private String access_token;

    @JsonProperty("refresh_token")
    private String refresh_token;

    @JsonProperty("token_type")
    private String token_type;

    @JsonProperty("expires_in")
    private Long expires_in;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("error")
    private String error;

    @JsonProperty("error_description")
    private String error_description;
}
