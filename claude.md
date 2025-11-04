# Central Authentication Server Implementation Plan

## Technology Stack & Requirements

### Core Technologies
- **Java**: 21 (LTS)
- **Build Tool**: Maven
- **Framework**: Spring Boot 3.x
- **Security**: Spring Authorization Server (OAuth 2.1 + OpenID Connect)
- **Database**: PostgreSQL with Hibernate/JPA
- **Password Hashing**: BCrypt (Spring Security default)
- **Token Format**: JWT with RSA signing

### Key Dependencies
- spring-boot-starter-oauth2-authorization-server
- spring-boot-starter-security
- spring-boot-starter-data-jpa
- spring-boot-starter-validation
- spring-boot-starter-mail
- postgresql driver

### Security Features (All Included)
- ✅ Email Verification
- ✅ Password Reset
- ✅ Two-Factor Authentication (TOTP)
- ✅ Account Lockout (after failed attempts)
- ✅ Rate Limiting
- ✅ CSRF Protection
- ✅ CORS Configuration

## Database Schema Design

### Core Tables
1. **users** - User credentials & status (username, email, password_hash, enabled, locked)
2. **roles** - Role definitions (ROLE_USER, ROLE_ADMIN)
3. **user_roles** - Many-to-many relationship
4. **oauth2_registered_client** - OAuth2 client applications
5. **oauth2_authorization** - Active authorizations & tokens
6. **oauth2_authorization_consent** - User consent records
7. **refresh_tokens** - Refresh token management with rotation
8. **verification_tokens** - Email verification & password reset tokens
9. **login_attempts** - Failed login tracking for account lockout
10. **two_factor_auth** - TOTP secrets & backup codes

## Project Structure
```
com.auth.server
├── config          # Security, OAuth2, database configs
├── entity          # JPA entities
├── repository      # Spring Data repositories
├── service         # Business logic
├── controller      # REST API endpoints
├── dto             # Data Transfer Objects
├── security        # Custom security components
├── exception       # Custom exceptions & handlers
└── util            # Helper utilities
```

## Implementation Phases

### Phase 1: Project Setup & Core Configuration
- Generate Maven project structure
- Configure application.properties (database, server, JWT settings)
- Set up PostgreSQL connection
- Create database schema (Liquibase/Flyway migrations)
- Configure RSA key pair for JWT signing

### Phase 2: User Management Foundation
- Create User, Role entities
- Implement UserRepository with Spring Data JPA
- Configure BCrypt password encoder
- Create UserDetailsService implementation
- Build user registration endpoint with validation

### Phase 3: OAuth2 Authorization Server Setup
- Configure Spring Authorization Server
- Set up registered clients (for testing)
- Implement authorization endpoints (/oauth2/authorize, /oauth2/token)
- Configure JWT token customization (add custom claims)
- Set up token introspection and revocation

### Phase 4: Email Verification
- Create verification token entity & repository
- Implement email sending service (SMTP configuration)
- Build verification email template
- Create verification endpoints (verify, resend)
- Add verification check to login flow

### Phase 5: Password Reset
- Create password reset token system
- Implement forgot password endpoint
- Build password reset email template
- Create reset password endpoint with token validation
- Add password strength validation

### Phase 6: Two-Factor Authentication (2FA)
- Add TOTP library dependency (google-authenticator)
- Create 2FA entity for storing secrets
- Implement 2FA setup endpoint (QR code generation)
- Add 2FA verification to login flow
- Create backup codes system

### Phase 7: Account Lockout & Rate Limiting
- Create login attempts tracking entity
- Implement failed login counter
- Add automatic account locking logic
- Build unlock account endpoint (admin)
- Add rate limiting interceptor for auth endpoints

### Phase 8: Client Management API
- Create client registration endpoints (admin)
- Implement client CRUD operations
- Add client secret regeneration
- Build client listing & search
- Add scope management per client

### Phase 9: Security Hardening
- Configure CORS for allowed origins
- Enable CSRF protection (where needed)
- Add comprehensive input validation
- Implement request/response logging
- Add security headers (HSTS, X-Frame-Options, etc.)

### Phase 10: Testing & Documentation
- Write unit tests for services
- Integration tests for auth flows
- Test OAuth2 flows (authorization code, client credentials)
- Create API documentation (Swagger/OpenAPI)
- Document OAuth2 integration guide for clients

## API Endpoints Overview

### Public Endpoints
- `POST /api/auth/register` - User registration
- `POST /api/auth/verify-email` - Email verification
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token

### OAuth2 Endpoints (Standard)
- `GET /oauth2/authorize` - Authorization flow start
- `POST /oauth2/token` - Token issuance & refresh
- `POST /oauth2/revoke` - Revoke tokens
- `POST /oauth2/introspect` - Token introspection
- `GET /.well-known/oauth-authorization-server` - Discovery

### Protected Endpoints
- `GET /api/users/me` - Current user profile
- `PUT /api/users/me` - Update profile
- `POST /api/users/me/2fa/setup` - Enable 2FA
- `POST /api/users/me/2fa/verify` - Verify 2FA code
- `POST /api/users/me/change-password` - Change password

### Admin Endpoints
- `POST /api/admin/clients` - Register OAuth2 client
- `GET /api/admin/clients` - List clients
- `PUT /api/admin/users/{id}/unlock` - Unlock user account
- `GET /api/admin/users` - List all users

## Key Configuration Values
- **Access Token TTL**: 15 minutes
- **Refresh Token TTL**: 30 days (with rotation)
- **Authorization Code TTL**: 5 minutes
- **Email Verification Token TTL**: 24 hours
- **Password Reset Token TTL**: 1 hour
- **Failed Login Threshold**: 5 attempts
- **Account Lock Duration**: 30 minutes
- **JWT Algorithm**: RS256 (RSA with SHA-256)
