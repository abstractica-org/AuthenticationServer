# OAuth2 Integration Guide

## Overview

The Central Authentication Server provides a complete OAuth2 Authorization Server implementation based on Spring Authorization Server. This guide explains how to integrate your applications with the authentication server.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Registration](#registration)
3. [OAuth2 Flows](#oauth2-flows)
4. [API Endpoints](#api-endpoints)
5. [Security Considerations](#security-considerations)
6. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Prerequisites

- The authentication server is running at `https://auth-server.com` (or your configured endpoint)
- Your application is registered as an OAuth2 client
- You have obtained a `client_id` and `client_secret`

### Configuration

All OAuth2 endpoints are available at:
- **Authorization Endpoint**: `/oauth2/authorize`
- **Token Endpoint**: `/oauth2/token`
- **Introspection Endpoint**: `/oauth2/introspect`
- **Revocation Endpoint**: `/oauth2/revoke`
- **Discovery Endpoint**: `/.well-known/oauth-authorization-server`

---

## Registration

### Register Your Application

To register an OAuth2 client with the authentication server:

**Endpoint**: `POST /api/admin/clients`

**Authentication**: Requires `ROLE_ADMIN` role

**Request Body**:
```json
{
  "clientId": "my-app-client-123",
  "clientName": "My Awesome Application",
  "description": "My application that integrates with the auth server",
  "redirectUris": [
    "http://localhost:3000/callback",
    "https://myapp.com/oauth/callback"
  ],
  "scopes": "read,write,profile",
  "accessTokenTtl": 900,
  "refreshTokenTtl": 2592000,
  "clientCredentialsEnabled": true,
  "authorizationCodeEnabled": true,
  "refreshTokenEnabled": true
}
```

**Response**:
```json
{
  "id": "uuid",
  "clientId": "my-app-client-123",
  "clientSecret": "super-secret-key-123456",
  "clientName": "My Awesome Application",
  "redirectUris": "http://localhost:3000/callback,https://myapp.com/oauth/callback",
  "scopes": "read,write,profile",
  "accessTokenTtl": 900,
  "refreshTokenTtl": 2592000,
  "clientCredentialsEnabled": true,
  "authorizationCodeEnabled": true,
  "refreshTokenEnabled": true,
  "createdAt": "2024-01-15T10:30:00Z"
}
```

**Important**: The `clientSecret` is only returned once during creation. Store it securely and never expose it to the client-side code.

---

## OAuth2 Flows

### 1. Authorization Code Flow (Web Applications)

Recommended for server-side applications. The user is redirected to log in on the authentication server, and the application receives an authorization code to exchange for tokens.

#### Step 1: Redirect User to Authorization Endpoint

```
GET /oauth2/authorize?client_id=my-app-client-123&response_type=code&redirect_uri=http://localhost:3000/callback&scope=read+write&state=random-state-value
```

**Parameters**:
- `client_id`: Your registered client ID
- `response_type`: Must be `code`
- `redirect_uri`: One of your registered redirect URIs
- `scope`: Requested scopes (space-separated)
- `state`: CSRF protection token (recommended)

#### Step 2: User Logs In

The user is presented with a login form. After successful authentication and email verification, the user is asked to authorize your application.

#### Step 3: Authorization Code Returned

The authentication server redirects the user to your redirect URI:

```
http://localhost:3000/callback?code=auth-code-xyz&state=random-state-value
```

#### Step 4: Exchange Code for Tokens

Make a server-to-server request to exchange the authorization code for tokens:

```bash
curl -X POST \
  https://auth-server.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=auth-code-xyz" \
  -d "client_id=my-app-client-123" \
  -d "client_secret=super-secret-key-123456" \
  -d "redirect_uri=http://localhost:3000/callback"
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "refresh-token-value",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read write"
}
```

---

### 2. Client Credentials Flow (Machine-to-Machine)

Recommended for server-to-server communication where there's no user involved. Your application authenticates directly using credentials.

#### Request Access Token

```bash
curl -X POST \
  https://auth-server.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=my-app-client-123" \
  -d "client_secret=super-secret-key-123456" \
  -d "scope=read+write"
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "read write"
}
```

---

### 3. Refresh Token Flow

Get a new access token using your refresh token (valid for 30 days by default).

```bash
curl -X POST \
  https://auth-server.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=refresh-token-value" \
  -d "client_id=my-app-client-123" \
  -d "client_secret=super-secret-key-123456"
```

**Response**:
```json
{
  "access_token": "new-access-token...",
  "refresh_token": "new-refresh-token-value",
  "token_type": "Bearer",
  "expires_in": 900
}
```

---

## API Endpoints

### User Registration

**Endpoint**: `POST /api/auth/register`

**Request**:
```json
{
  "username": "newuser",
  "email": "newuser@example.com",
  "password": "SecurePassword@123",
  "passwordConfirm": "SecurePassword@123"
}
```

**Response**:
```json
{
  "user": {
    "id": "uuid",
    "username": "newuser",
    "email": "newuser@example.com",
    "emailVerified": false,
    "twoFactorEnabled": false,
    "roles": ["ROLE_USER"]
  },
  "tokens": null,
  "requiresEmailVerification": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### Email Verification

**Endpoint**: `POST /api/auth/verify-email`

**Request**:
```json
{
  "token": "email-verification-token"
}
```

**Response**: Returns user data with `emailVerified: true`

---

### User Login

**Endpoint**: `POST /api/auth/login`

**Request**:
```json
{
  "usernameOrEmail": "newuser@example.com",
  "password": "SecurePassword@123"
}
```

**Response**:
```json
{
  "user": {
    "id": "uuid",
    "username": "newuser",
    "email": "newuser@example.com",
    "emailVerified": true,
    "twoFactorEnabled": false,
    "roles": ["ROLE_USER"]
  },
  "tokens": {
    "accessToken": "jwt-token...",
    "refreshToken": "refresh-token-value",
    "tokenType": "Bearer",
    "expiresIn": 900
  },
  "requiresEmailVerification": false,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### Get Current User Profile

**Endpoint**: `GET /api/users/me`

**Authentication**: Bearer JWT token required

**Response**:
```json
{
  "id": "uuid",
  "username": "newuser",
  "email": "newuser@example.com",
  "emailVerified": true,
  "twoFactorEnabled": false,
  "roles": ["ROLE_USER"]
}
```

---

### Setup Two-Factor Authentication

**Endpoint**: `POST /api/users/me/2fa/setup`

**Authentication**: Bearer JWT token required

**Response**:
```json
{
  "secret": "base32-encoded-secret",
  "qrCode": "data:image/png;base64,...",
  "backupCodes": ["code1", "code2", ...]
}
```

**Steps**:
1. Display QR code to user
2. User scans with authenticator app (Google Authenticator, Authy, etc.)
3. User enters 6-digit code to verify setup

---

### Verify 2FA Code

**Endpoint**: `POST /api/users/me/2fa/verify`

**Authentication**: Bearer JWT token required

**Request**:
```json
{
  "code": "123456"
}
```

---

### Password Reset

**Endpoint**: `POST /api/auth/forgot-password`

**Request**:
```json
{
  "email": "user@example.com"
}
```

**Response**:
```json
{
  "message": "Password reset email sent"
}
```

Then user receives email with reset link.

---

### Reset Password with Token

**Endpoint**: `POST /api/auth/reset-password`

**Request**:
```json
{
  "token": "password-reset-token",
  "newPassword": "NewPassword@123"
}
```

---

### Logout

**Endpoint**: `POST /api/auth/logout`

**Authentication**: Bearer JWT token required

**Response**:
```json
{
  "message": "Logout successful"
}
```

---

### Token Introspection

**Endpoint**: `POST /oauth2/introspect`

**Request**:
```
POST /oauth2/introspect
Content-Type: application/x-www-form-urlencoded

token=access-token-value
```

**Response**:
```json
{
  "active": true,
  "scope": "read write",
  "client_id": "my-app-client-123",
  "username": "user@example.com",
  "token_type": "Bearer",
  "exp": 1234567890,
  "iat": 1234567000,
  "sub": "user-id"
}
```

---

### Token Revocation

**Endpoint**: `POST /oauth2/revoke`

**Request**:
```
POST /oauth2/revoke
Content-Type: application/x-www-form-urlencoded

token=refresh-token-value
```

**Response**: HTTP 200 OK (no body)

---

### OAuth2 Discovery

**Endpoint**: `GET /.well-known/oauth-authorization-server`

**Response**:
```json
{
  "issuer": "https://auth-server.com",
  "authorization_endpoint": "https://auth-server.com/oauth2/authorize",
  "token_endpoint": "https://auth-server.com/oauth2/token",
  "introspection_endpoint": "https://auth-server.com/oauth2/introspect",
  "revocation_endpoint": "https://auth-server.com/oauth2/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "scopes_supported": ["read", "write", "profile"]
}
```

---

## Security Considerations

### 1. Never Expose Client Secret

- Store `client_secret` securely on your server
- Never include it in client-side code or version control
- Regenerate if compromised

### 2. Use HTTPS

- Always use HTTPS in production
- Never send credentials over unencrypted connections

### 3. Validate State Parameter

In Authorization Code Flow:
```javascript
// Store state in session
const state = generateRandomString();
session.state = state;

// Later, verify state matches
if (request.query.state !== session.state) {
  throw new Error('Invalid state parameter - CSRF attack detected');
}
```

### 4. Secure Token Storage

- Store tokens in memory or secure HTTP-only cookies
- For SPAs: Consider using Authorization Code Flow with PKCE
- Never store in localStorage if possible

### 5. Token Validation

Validate JWT tokens:
```javascript
// Token structure: HEADER.PAYLOAD.SIGNATURE
const token = request.headers.authorization.split(' ')[1];

// Verify signature using public key from /.well-known/oauth-authorization-server
// Verify expiration (exp claim)
// Verify issuer (iss claim)
```

### 6. Implement Rate Limiting

The server implements rate limiting:
- Login: 5 attempts per 15 minutes
- Account locks after 5 failed attempts for 30 minutes

### 7. Certificate Pinning (Mobile Apps)

For mobile applications, implement SSL pinning to prevent MITM attacks:
```java
// Example for OkHttp
CertificatePinner certificatePinner = new CertificatePinner.Builder()
  .add("auth-server.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
  .build();
```

---

## Code Examples

### JavaScript/Node.js

```javascript
// Using axios
const axios = require('axios');

// 1. Authorization Code Flow
const authUrl = new URL('https://auth-server.com/oauth2/authorize');
authUrl.searchParams.append('client_id', 'my-app-client-123');
authUrl.searchParams.append('response_type', 'code');
authUrl.searchParams.append('redirect_uri', 'http://localhost:3000/callback');
authUrl.searchParams.append('scope', 'read write');
authUrl.searchParams.append('state', generateRandomState());

window.location.href = authUrl.toString();

// 2. Exchange code for token
const response = await axios.post('https://auth-server.com/oauth2/token',
  new URLSearchParams({
    grant_type: 'authorization_code',
    code: authCode,
    client_id: 'my-app-client-123',
    client_secret: 'super-secret-key-123456',
    redirect_uri: 'http://localhost:3000/callback'
  })
);

const { access_token, refresh_token } = response.data;

// 3. Use access token
const userResponse = await axios.get('https://auth-server.com/api/users/me', {
  headers: { Authorization: `Bearer ${access_token}` }
});

// 4. Refresh token
const refreshResponse = await axios.post('https://auth-server.com/oauth2/token',
  new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refresh_token,
    client_id: 'my-app-client-123',
    client_secret: 'super-secret-key-123456'
  })
);
```

### Python

```python
import requests
from requests.auth import HTTPBasicAuth

# Client Credentials Flow
response = requests.post(
    'https://auth-server.com/oauth2/token',
    data={
        'grant_type': 'client_credentials',
        'scope': 'read write'
    },
    auth=HTTPBasicAuth('my-app-client-123', 'super-secret-key-123456')
)

access_token = response.json()['access_token']

# Use access token
headers = {'Authorization': f'Bearer {access_token}'}
user_response = requests.get(
    'https://auth-server.com/api/users/me',
    headers=headers
)
```

### Java

```java
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

// Spring WebClient with OAuth2 support
WebClient webClient = WebClient.builder()
    .filter(new ServerOAuth2AuthorizedClientExchangeFilterFunction())
    .baseUrl("https://auth-server.com")
    .build();

// Automatically handles token refresh
var response = webClient.get()
    .uri("/api/users/me")
    .retrieve()
    .bodyToMono(UserProfile.class)
    .block();
```

---

## Troubleshooting

### Invalid Client ID

**Error**: `invalid_client` or `Client not found`

**Solution**:
- Verify client_id is correct
- Check that client is not deleted (soft delete)
- Ensure client is active

### Redirect URI Mismatch

**Error**: `redirect_uri_mismatch`

**Solution**:
- Ensure redirect_uri in request matches exactly one registered URI
- Check for trailing slashes, protocols, ports
- Register additional URIs if needed

### Invalid Grant

**Error**: `invalid_grant`

**Solution**:
- For auth code: Code may have expired (5 minute limit)
- Verify code hasn't been used before
- Check client_secret is correct

### Token Expired

**Error**: `invalid_token` or `token_expired`

**Solution**:
- Use refresh_token to get new access_token
- Access tokens expire in 15 minutes by default
- Check token expiration: `exp` claim in JWT

### 2FA Required

**Error**: `2fa_required`

**Solution**:
- User needs to complete 2FA during login
- Follow 2FA setup guide provided in login response

### Account Locked

**Error**: `account_locked`

**Solution**:
- Account locked after 5 failed login attempts
- Auto-unlocks after 30 minutes
- Admin can manually unlock via `/api/admin/users/{id}/unlock`

---

## Support

For additional support or questions:
- Email: support@auth-server.com
- API Documentation: https://auth-server.com/swagger-ui.html
- Issues: https://github.com/yourusername/auth-server/issues
