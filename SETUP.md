# Authentication Server - Setup Guide

## Prerequisites

- Java 21 (LTS)
- Maven 3.9+
- PostgreSQL 14+ (running and accessible)
- Git

## Database Setup

### 1. Create PostgreSQL Database

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE auth_server;

# Create user (if needed)
CREATE USER auth_user WITH PASSWORD 'secure_password';
ALTER ROLE auth_user SET client_encoding TO 'utf8';
ALTER ROLE auth_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE auth_user SET default_transaction_deferrable TO on;
ALTER ROLE auth_user SET timezone TO 'UTC';

# Grant privileges
GRANT ALL PRIVILEGES ON DATABASE auth_server TO auth_user;
```

### 2. Update Database Configuration

Edit `src/main/resources/application.properties`:

```properties
spring.datasource.url=jdbc:postgresql://localhost:5432/auth_server
spring.datasource.username=auth_user
spring.datasource.password=secure_password
```

## JWT Keys Setup

### Generate RSA Keys

The application will automatically generate RSA keys on first run. You can also manually generate them:

```bash
cd AuthenticationServer
mvn exec:java@generate-keys
```

Or run the key generator:

```bash
java -cp "target/classes" com.auth.server.util.RsaKeyGenerator
```

Keys will be stored in: `src/main/resources/keys/`
- `private.key` - Private key for signing JWTs
- `public.key` - Public key for validating JWTs

## Email Configuration

The application is configured to use an SMTP server for sending emails. Update `src/main/resources/application.properties`:

```properties
spring.mail.host=your-smtp-host
spring.mail.port=587
spring.mail.username=your-email
spring.mail.password=your-password
spring.mail.from=noreply@yourdomain.com
spring.mail.properties.mail.smtp.auth=true
spring.mail.properties.mail.smtp.starttls.enable=true
```

For development, you can use MailHog:

```bash
# Install MailHog
brew install mailhog  # macOS
# or download from https://github.com/mailhog/MailHog

# Run MailHog
mailhog

# Access web UI at http://localhost:1025
```

## Building the Project

```bash
# Navigate to project directory
cd AuthenticationServer

# Clean and build
mvn clean install

# Or skip tests if needed
mvn clean install -DskipTests
```

## Running the Application

### Using Maven
```bash
mvn spring-boot:run
```

### Using Java
```bash
java -jar target/authentication-server-1.0.0.jar
```

### Using IDE
1. Open the project in your IDE
2. Right-click on `AuthenticationServerApplication` class
3. Select "Run" or "Debug"

## Accessing the Application

Once the application is running:

- **API Base URL**: http://localhost:8080
- **Swagger UI**: http://localhost:8080/swagger-ui.html
- **OpenAPI Docs**: http://localhost:8080/v3/api-docs
- **Health Check**: http://localhost:8080/actuator/health
- **Metrics**: http://localhost:8080/actuator/metrics

## Database Migrations

Liquibase migrations are automatically applied on startup. The migrations will:

1. Create all necessary tables (users, roles, OAuth2 tables, etc.)
2. Create indexes for optimal query performance
3. Insert default roles (ROLE_USER, ROLE_ADMIN, ROLE_SERVICE)

If you need to manually run migrations:

```bash
mvn liquibase:update
```

## Troubleshooting

### Database Connection Issues

1. Verify PostgreSQL is running
2. Check database credentials in `application.properties`
3. Ensure the database exists

```bash
psql -U postgres -l | grep auth_server
```

### Port Already in Use

If port 8080 is already in use, change it in `application.properties`:

```properties
server.port=8081
```

### Key Generation Issues

If key generation fails, ensure the `src/main/resources/keys/` directory exists and is writable:

```bash
mkdir -p src/main/resources/keys
chmod 755 src/main/resources/keys
```

### Migration Issues

To reset the database and re-run migrations:

```bash
# Drop and recreate database
psql -U postgres -c "DROP DATABASE auth_server;"
psql -U postgres -c "CREATE DATABASE auth_server;"

# Re-run migrations
mvn liquibase:update
```

## Next Steps

1. Review `claude.md` for the complete implementation plan
2. Begin Phase 2: User Management Foundation
3. Create User entity and repositories
4. Implement user registration endpoint

## Configuration Reference

See `application.properties` for all available configuration options:

- JWT expiration times
- Rate limiting thresholds
- 2FA settings
- Email settings
- CORS allowed origins
- Logging levels

## Development Notes

- The application uses BCrypt with strength 13 for password encoding
- JWT tokens are signed using RS256 (RSA with SHA-256)
- Email verification is required before users can fully use the system
- All passwords are hashed and never stored in plaintext
- Refresh tokens are rotated on each refresh request
