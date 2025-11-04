# Remaining Phases Implementation Guide

## Phase 6: Two-Factor Authentication (2FA)

### Files to Create

1. **TotpService.java** (com.auth.server.service)
```java
// Use: dev.samstevens.totp library (already in pom.xml)
// Functions:
// - generateSecret() - Generate TOTP secret
// - getQrCodeUrl(secret, email) - Generate QR code URL
// - verifyCode(secret, code) - Verify TOTP code
// - generateBackupCodes(count) - Generate backup codes
```

2. **2FA DTOs** (com.auth.server.dto)
- `Setup2FARequest` - Initiate 2FA setup
- `Setup2FAResponse` - Returns secret and QR code URL
- `Verify2FARequest` - Verify code and enable 2FA
- `Backup2FACodesResponse` - Returns backup codes

3. **Controller Methods** in UserController
```java
@PostMapping("/me/2fa/setup")
@PostMapping("/me/2fa/verify")
@PostMapping("/me/2fa/backup-codes")
@DeleteMapping("/me/2fa")
```

### Implementation Steps

1. Create TotpService using dev.samstevels.totp library
2. Add 2FA setup endpoint that generates secret + QR code
3. Add 2FA verification endpoint that enables 2FA
4. Update login flow to check for 2FA requirement
5. Create 2FA token for users with 2FA enabled
6. Implement backup code generation and validation

### Database

- Use existing `two_factor_auth` table
- Fields: secret, enabled, backup_codes, enabled_at

---

## Phase 7: Account Lockout & Rate Limiting

### Files to Create

1. **LoginAttemptService.java** (com.auth.server.service)
```java
// Functions:
// - recordLoginAttempt(user, ip, success)
// - isAccountLocked(user)
// - getFailedAttemptCount(user)
// - unlockAccount(user)
// - getRecentAttempts(username, minutes)
```

2. **RateLimitingInterceptor.java** (com.auth.server.config)
- Intercept requests to /api/auth endpoints
- Track request count per IP
- Return 429 Too Many Requests if exceeded
- Use local cache (Caffeine) for counters

3. **AccountLockoutService.java** (com.auth.server.service)
- Check account lockout status
- Handle automatic unlock after duration
- Admin unlock endpoint

4. **AdminController.java** (com.auth.server.controller)
```java
@PutMapping("/users/{id}/unlock") - Admin unlock
@GetMapping("/users/{id}/attempts") - View login attempts
```

### Implementation Steps

1. Create LoginAttemptService to track failed attempts
2. Integrate service into authentication provider
3. Create RateLimitingInterceptor for IP-based rate limiting
4. Register interceptor in WebSecurityConfig
5. Create admin unlock endpoint
6. Add lockout duration configuration

### Configuration

```properties
account.lockout.threshold=5
account.lockout.duration.minutes=30
rate.limit.login.requests=5
rate.limit.login.duration.minutes=15
```

---

## Phase 8: Client Management API

### Files to Create

1. **RegisteredClientEntity.java** (com.auth.server.entity)
- Store OAuth2 clients in database
- Separate from Spring's in-memory clients

2. **RegisteredClientRepository.java**
3. **RegisteredClientService.java**

4. **ClientManagementController.java**
```java
@PostMapping("/admin/clients") - Create client
@GetMapping("/admin/clients") - List clients
@GetMapping("/admin/clients/{id}") - Get client
@PutMapping("/admin/clients/{id}") - Update client
@DeleteMapping("/admin/clients/{id}") - Delete client
@PostMapping("/admin/clients/{id}/secret") - Regenerate secret
```

5. **ClientRequest/ClientResponse DTOs**

### Implementation Steps

1. Create database-backed registered client repository
2. Replace in-memory clients with database lookups
3. Implement CRUD operations
4. Add scope management per client
5. Implement client secret rotation (hash before storing)
6. Add client validation

### Security

- Store client secrets hashed (use BCrypt)
- Only return secrets on creation/regeneration
- Require admin role for all operations
- Audit all client modifications

---

## Phase 9: Security Hardening

### Files to Create

1. **SecurityHeadersFilter.java**
- Add security headers to all responses
- HSTS, X-Frame-Options, CSP, etc.

2. **AuditService.java** (com.auth.server.service)
- Log authentication attempts
- Log admin actions
- Log sensitive operations

3. **InputValidationUtil.java** (com.auth.server.util)
- Validate and sanitize inputs
- Prevent XSS attacks
- Check for SQL injection patterns

### Implementation Steps

1. Create SecurityHeadersFilter and register as bean
2. Add security headers configuration:
   ```
   Strict-Transport-Security: max-age=31536000
   X-Content-Type-Options: nosniff
   X-Frame-Options: DENY
   X-XSS-Protection: 1; mode=block
   Referrer-Policy: no-referrer
   ```
3. Implement request/response logging
4. Add input validation annotations
5. Create audit log entity and service
6. Log all authentication, authorization, and admin events

### Additional Security Measures

- Implement request signing for API calls
- Add API key authentication for service clients
- Implement webhook verification (HMAC-SHA256)
- Add DDoS protection (rate limiting per endpoint)
- Implement CORS preflight validation

---

## Phase 10: Testing & Documentation

### Test Files to Create

1. **UserServiceTest.java** (src/test/java)
- Test registration, password update, locking
- Test validation and error handling

2. **AuthControllerTest.java**
- Test registration endpoint
- Test email verification
- Test password reset

3. **OAuth2IntegrationTest.java**
- Test authorization code flow
- Test client credentials flow
- Test token refresh

4. **SecurityTest.java**
- Test authentication
- Test authorization
- Test CORS headers
- Test rate limiting

### Test Framework
- JUnit 5
- Mockito for mocking
- Spring Test for integration tests
- TestRestTemplate for API testing
- H2 in-memory database for tests

### Documentation

1. **API Documentation (Swagger)**
- Configure springdoc-openapi
- Add @Operation, @ApiResponse annotations
- Document all endpoints with examples

2. **Integration Guide**
- How to register an OAuth2 client
- Authorization Code flow example
- Client Credentials flow example
- Token refresh example
- Error handling examples

3. **Developer Guide**
- Architecture overview
- Database schema documentation
- Security considerations
- Configuration options
- Deployment guide

### Testing Checklist

- [ ] Unit tests for all services (80%+ coverage)
- [ ] Integration tests for all controllers
- [ ] OAuth2 flow tests (auth code, client creds, refresh)
- [ ] Security tests (CORS, CSRF, headers)
- [ ] Rate limiting tests
- [ ] Email sending tests (mock SMTP)
- [ ] Token expiration tests
- [ ] Password hashing verification tests
- [ ] 2FA code validation tests

---

## Quick Implementation Order

1. **Phase 6 (2FA)** - ~4-6 hours
   - Most self-contained feature
   - Uses existing token infrastructure

2. **Phase 7 (Lockout & Rate Limiting)** - ~3-4 hours
   - Uses existing LoginAttempt entity
   - Interceptor-based approach

3. **Phase 8 (Client Management)** - ~3-4 hours
   - Database-backed client repository
   - Standard CRUD endpoints

4. **Phase 9 (Security Hardening)** - ~2-3 hours
   - Headers filter
   - Audit logging

5. **Phase 10 (Testing & Docs)** - ~6-8 hours
   - Comprehensive test suite
   - API documentation

---

## Maven Commands for Testing

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=UserServiceTest

# Run with coverage
mvn test jacoco:report

# Run integration tests only
mvn verify -Dgroups=integration

# Skip tests
mvn clean install -DskipTests
```

---

## Common Implementation Patterns

### Creating a New Endpoint

1. Create DTO for request/response
2. Create Service method for business logic
3. Create Controller method with @PostMapping/@GetMapping
4. Add @Operation and @ApiResponse annotations
5. Add validation with @Valid
6. Handle exceptions with GlobalExceptionHandler
7. Write tests for the endpoint

### Adding a New Service

1. Create Service class with @Service annotation
2. Inject dependencies via constructor
3. Add @Transactional annotation if needed
4. Use logging with @Slf4j
5. Throw appropriate custom exceptions
6. Write unit tests with Mockito

### Database Changes

1. Create new Liquibase YAML file
2. Add changeset with table/column definitions
3. Add indexes for frequently queried columns
4. Create corresponding entity and repository
5. Update master changelog YAML
6. Test migration locally

---

## Deployment Considerations

1. Use environment variables for sensitive config
2. Set up HTTPS/TLS certificates
3. Configure SMTP for production emails
4. Set up PostgreSQL backups
5. Enable audit logging
6. Set up monitoring and alerting
7. Configure log rotation
8. Use secrets management (HashiCorp Vault)
9. Set up CI/CD pipeline (GitHub Actions, Jenkins)
10. Load testing before production

---

## Resources

- **Spring Authorization Server**: https://spring.io/projects/spring-authorization-server
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **OAuth 2.0 Security Best Practices**: https://tools.ietf.org/html/draft-ietf-oauth-security-topics
- **TOTP Implementation**: https://tools.ietf.org/html/rfc6238
- **Spring Security Documentation**: https://spring.io/projects/spring-security

