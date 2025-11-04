# Central Authentication Server

> Enterprise-grade authentication and authorization server built with Spring Boot 3.3, Java 21, and PostgreSQL

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Tests](https://img.shields.io/badge/tests-91%2F91%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-87%25-green)
![Java Version](https://img.shields.io/badge/java-21%20LTS-blue)
![Spring Boot](https://img.shields.io/badge/spring%20boot-3.3.0-green)

---

## Quick Start

### Prerequisites
- **Java 21 LTS**
- **Maven 3.8+**
- **PostgreSQL 14+** (or use Docker)
- **Git**

### Automated Installation (Recommended)

The easiest way to get started is using the automated install script:

```bash
# Clone repository
git clone https://github.com/yourusername/AuthenticationServer.git
cd AuthenticationServer

# Run the installer (sets up PostgreSQL and builds the application)
./install.sh
```

The install script will:
- ✅ Check all prerequisites (Java, Maven, PostgreSQL)
- ✅ Install PostgreSQL if not present
- ✅ Create and configure the database
- ✅ Build the project
- ✅ Optionally start the application

### Manual Installation

```bash
# Clone repository
git clone https://github.com/yourusername/AuthenticationServer.git
cd AuthenticationServer

# Setup PostgreSQL database (see SETUP.md for details)
sudo -u postgres psql -c "CREATE DATABASE auth_server;"

# Build and test
mvn clean verify

# Run application
mvn spring-boot:run
```

### Management Scripts

```bash
# Start the application
./start.sh

# Stop the application
./stop.sh

# Uninstall (removes database and build artifacts)
./uninstall.sh
```

### Access Application
- **API:** http://localhost:8080
- **Swagger UI:** http://localhost:8080/swagger-ui.html
- **Health Check:** http://localhost:8080/actuator/health

---

## Documentation

| Document | Purpose |
|----------|---------|
| **[status.md](status.md)** | Current project status, architecture, API endpoints |
| **[teach.md](teach.md)** | Theory, concepts, security principles (educational) |
| **[ci-cd-setup.md](ci-cd-setup.md)** | CI/CD pipeline setup (GitHub Actions, Docker, Kubernetes) |
| **[SETUP.md](SETUP.md)** | Detailed setup and configuration instructions |
| **[TESTING_GUIDE.md](TESTING_GUIDE.md)** | How to run tests, test categories, best practices |
| **[TEST_SUMMARY.md](TEST_SUMMARY.md)** | Test results, coverage statistics, achievements |
| **[PROGRESS.md](PROGRESS.md)** | Implementation progress, completed features |
| **[REMAINING_PHASES.md](REMAINING_PHASES.md)** | Next phases: 2FA, rate limiting, client management |

---

## What's Included

### ✅ Implemented Features (Phases 1-5)

- **User Management** - Registration, profile management, role-based access control
- **Authentication** - JWT tokens, password hashing (BCrypt), stateless API
- **Authorization** - Role-based access control (RBAC) with 3 pre-built roles
- **Email Verification** - Token-based email verification (24-hour expiration)
- **Password Reset** - Secure password reset with email verification
- **API Documentation** - Swagger/OpenAPI 3.0 auto-generated docs
- **Security** - CORS, CSRF protection, SQL injection prevention
- **Testing** - 91 comprehensive tests (repository, service, controller layers)
- **Database Migrations** - Liquibase-based schema management
- **Configuration Management** - Environment-specific profiles (dev, test, prod)

### 🔄 Coming Soon (Phases 6-10)

- **Two-Factor Authentication (2FA)** - TOTP with Google Authenticator
- **Account Lockout & Rate Limiting** - Protection against brute force attacks
- **Client Management API** - OAuth2 client registration and management
- **Advanced Security** - HTTPS enforcement, security headers, audit logging
- **Additional Testing** - End-to-end flows, performance testing

---

## Architecture

```
┌─────────────────────────────────────┐
│     REST API (Controller Layer)      │
│   /api/auth/*, /api/users/*         │
└──────────────────┬──────────────────┘
                   │
┌──────────────────▼──────────────────┐
│   Business Logic (Service Layer)     │
│  UserService, EmailService, etc.    │
└──────────────────┬──────────────────┘
                   │
┌──────────────────▼──────────────────┐
│   Data Access (Repository Layer)     │
│   Spring Data JPA Repositories       │
└──────────────────┬──────────────────┘
                   │
┌──────────────────▼──────────────────┐
│  Database (PostgreSQL with JPA)      │
│   7 tables, Liquibase migrations     │
└─────────────────────────────────────┘
```

### API Endpoints

```
Authentication:
  POST   /api/auth/register              Register new user
  POST   /api/auth/login                 Login (form-based)
  POST   /api/auth/logout                Logout
  POST   /api/auth/verify-email          Verify email with token
  POST   /api/auth/resend-verification   Resend verification email
  POST   /api/auth/forgot-password       Request password reset
  POST   /api/auth/reset-password        Reset password with token

User Profile:
  GET    /api/users/me                   Get authenticated user's profile

Admin (Protected):
  GET    /api/admin/users                List all users
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| **Runtime** | Java 21 LTS |
| **Framework** | Spring Boot 3.3.0 |
| **Web** | Spring Web MVC |
| **Security** | Spring Security 6.x + JWT |
| **Database** | PostgreSQL 14+ (H2 for tests) |
| **ORM** | Hibernate JPA 6.x |
| **Migrations** | Liquibase 4.29 |
| **Passwords** | BCrypt (strength 13) |
| **Tokens** | JWT / RSA-2048 |
| **Email** | JavaMailSender |
| **2FA** | TOTP (Dev.samstevens) |
| **Testing** | JUnit 5, Mockito, AssertJ |
| **Build** | Maven 3.9 |
| **Documentation** | Swagger/OpenAPI 3.0 |
| **Monitoring** | Spring Actuator, JaCoCo |

---

## Testing

All **91 tests** pass with **87% coverage**:

```bash
# Run all tests
mvn clean test

# Run specific category
mvn test -Dtest="*RepositoryTest"
mvn test -Dtest="*ServiceTest"
mvn test -Dtest="*ControllerTest"

# Generate coverage report
mvn clean test jacoco:report
# View: target/site/jacoco/index.html

# Run with verbose output
mvn test -X
```

**Test Breakdown:**
- **30 Repository Tests** - Data access layer, H2 in-memory database
- **33 Service Tests** - Business logic, Mockito mocks
- **28 Controller Tests** - REST API integration tests

---

## Security Features

✅ **Password Security**
- BCrypt hashing with strength 13 (~1 second per hash)
- Prevents rainbow table and brute force attacks

✅ **Token Security**
- JWT with RSA-2048 asymmetric signing
- Short-lived access tokens (15 minutes)
- Long-lived refresh tokens with rotation (30 days)

✅ **Email Verification**
- Token-based verification (24-hour expiration)
- Single-use tokens (prevented replay attacks)
- Email ownership proof

✅ **Password Reset**
- Token-based reset (1-hour expiration)
- Requires email access (proof of ownership)
- No user enumeration

✅ **Authorization**
- Role-based access control (RBAC)
- Three pre-built roles (USER, ADMIN, SERVICE)
- Permission checking on every request

✅ **API Security**
- CORS configured (whitelist origins)
- CSRF protection (stateless API)
- SQL injection prevention (JPA parameterized queries)
- Input validation (JSR-380 annotations)

---

## Project Status

**Completion:** 50% (5 of 10 phases complete)

| Phase | Feature | Status |
|-------|---------|--------|
| 1 | Project Setup & Configuration | ✅ Complete |
| 2 | User Management Foundation | ✅ Complete |
| 3 | OAuth2 Authorization Server | ✅ Complete (foundation) |
| 4 | Email Verification | ✅ Complete |
| 5 | Password Reset | ✅ Complete |
| 6 | Two-Factor Authentication | 🔄 Coming Soon |
| 7 | Rate Limiting & Account Lockout | 🔄 Coming Soon |
| 8 | Client Management API | 🔄 Coming Soon |
| 9 | Advanced Security Features | 🔄 Coming Soon |
| 10 | Testing & Documentation | ⏳ In Progress |

---

## CI/CD Setup

The project is **fully CI/CD ready**. See [ci-cd-setup.md](ci-cd-setup.md) for complete instructions.

### GitHub Actions (Recommended)

```yaml
# Automatically runs on every push/PR
- Build and compile
- Run 91 tests
- Generate code coverage
- Build Docker image (optional)
- Deploy to production (optional)
```

### Quick CI/CD Setup

```bash
# Copy workflow files
mkdir -p .github/workflows
cp ci-cd-setup.md .github/workflows/ci.yml

# Push to GitHub
git add .github/
git commit -m "feat: add CI/CD pipeline"
git push

# Watch it run!
# GitHub → Actions tab → See workflow running
```

---

## Deployment

### Docker

```bash
# Build image
docker build -t auth-server:latest .

# Run container
docker run -p 8080:8080 \
  -e DATABASE_URL=jdbc:postgresql://postgres:5432/auth_server \
  -e DATABASE_USER=postgres \
  -e DATABASE_PASSWORD=postgres \
  auth-server:latest

# Test
curl http://localhost:8080/actuator/health
```

### Kubernetes

See [ci-cd-setup.md](ci-cd-setup.md) for complete Kubernetes deployment guide with YAML examples.

---

## Development Workflow

### 1. Create Feature Branch
```bash
git checkout -b feature/my-feature
```

### 2. Make Changes
```bash
# Edit files, add features
```

### 3. Run Tests Locally
```bash
mvn clean verify
```

### 4. Commit Changes
```bash
git add .
git commit -m "feat: add new feature"
```

### 5. Push and Open PR
```bash
git push origin feature/my-feature
# GitHub will automatically run CI tests
```

### 6. Merge After Tests Pass
```bash
# CI/CD pipeline automatically deploys to production
```

---

## Database Schema

**7 Tables with Relationships:**

```
users              ←→  roles  (many-to-many via user_roles)
    ↓
    ├─ verification_tokens
    ├─ login_attempts
    ├─ refresh_tokens
    └─ two_factor_auth
```

**Automatic Liquibase Migrations:**
- `001-initial-schema.yaml` - Users, roles, relationships
- `002-oauth2-tables.yaml` - OAuth2 client support
- `003-security-tables.yaml` - Verification tokens, 2FA, etc.

---

## Monitoring & Observability

### Health Checks
```bash
# Basic health
curl http://localhost:8080/actuator/health

# Detailed health
curl http://localhost:8080/actuator/health/details
```

### Metrics
```bash
# Prometheus metrics
curl http://localhost:8080/actuator/prometheus
```

### Logging
```
All authentication operations logged to console and files
Configure in application.properties:
  logging.level.com.auth.server=INFO
  logging.file.name=logs/application.log
```

---

## License

This project is licensed under the MIT License - see LICENSE file for details.

---

## Support

### Documentation
- **[status.md](status.md)** - Project overview and current state
- **[teach.md](teach.md)** - Educational guide on concepts and principles
- **[ci-cd-setup.md](ci-cd-setup.md)** - CI/CD implementation guide
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - How to run and write tests

### Questions?
1. Check the relevant documentation file above
2. Review code comments and JavaDoc
3. Check test examples for usage patterns
4. Open an issue on GitHub

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `mvn clean test`
5. Submit a pull request

All pull requests must:
- ✅ Pass all 91 tests
- ✅ Maintain or improve code coverage (87%+)
- ✅ Include documentation updates
- ✅ Follow code style conventions

---

## Roadmap

**Next Month (Phase 6):**
- Two-Factor Authentication (TOTP)
- Google Authenticator support
- Backup codes

**Following Month (Phase 7):**
- Account lockout after failed attempts
- Rate limiting (per IP, per username)
- Distributed rate limiting with Redis

**Long Term (Phases 8-10):**
- OAuth2 client management
- Advanced security features
- Performance optimization

---

## Authors

Development Team

---

## Acknowledgments

- **Spring Security Team** - For excellent authentication framework
- **OWASP** - For security best practices
- **JWT.io** - For JWT specification
- The open-source community

---

**Happy coding! 🚀**

For latest updates, see [PROGRESS.md](PROGRESS.md)
