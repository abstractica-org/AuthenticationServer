package com.auth.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * OAuth2 Token Request DTO
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuth2TokenRequest {

    @JsonProperty("grant_type")
    private String grant_type;

    @JsonProperty("client_id")
    private String client_id;

    @JsonProperty("client_secret")
    private String client_secret;

    @JsonProperty("code")
    private String code;

    @JsonProperty("redirect_uri")
    private String redirect_uri;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("refresh_token")
    private String refresh_token;

    @JsonProperty("username")
    private String username;

    @JsonProperty("password")
    private String password;
}
