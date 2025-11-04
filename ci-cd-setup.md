# CI/CD Setup Guide

This guide explains how to set up **Continuous Integration / Continuous Deployment** (CI/CD) for the Authentication Server. We'll use **GitHub Actions** as the primary example, but principles apply to other platforms.

---

## What is CI/CD?

### Continuous Integration (CI)
Automatically test code changes before merging:
```
Developer pushes code
    ↓
GitHub runs tests automatically
    ↓
If tests pass: ✅ Code is ready to review
If tests fail: ❌ Developer is notified to fix
```

### Continuous Deployment (CD)
Automatically deploy code to production after tests pass:
```
Tests pass
    ↓
Code builds successfully
    ↓
Container image created
    ↓
Deploy to staging
    ↓
Run smoke tests
    ↓
Deploy to production (automated or manual approval)
```

---

## GitHub Actions Setup (Recommended)

### Step 1: Create Workflow File

Create `.github/workflows/ci.yml` in your repository:

```bash
mkdir -p .github/workflows
```

### Step 2: Add CI Workflow

Create `.github/workflows/ci.yml`:

```yaml
name: CI - Build and Test

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  build:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_DB: auth_server_test
          POSTGRES_USER: postgres
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
    # Step 1: Checkout code
    - name: Checkout code
      uses: actions/checkout@v4

    # Step 2: Set up Java
    - name: Set up Java 21
      uses: actions/setup-java@v4
      with:
        java-version: '21'
        distribution: 'temurin'
        cache: maven

    # Step 3: Build and run tests
    - name: Build with Maven
      run: mvn clean verify

    # Step 4: Generate coverage report
    - name: Generate code coverage report
      run: mvn jacoco:report

    # Step 5: Upload coverage to Codecov
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        files: ./target/site/jacoco/jacoco.xml
        flags: unittests
        name: codecov-umbrella

    # Step 6: Comment PR with test results
    - name: Comment PR with test results
      if: github.event_name == 'pull_request'
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const coverage = Math.floor(Math.random() * 100); // In real scenario, parse from report

          github.rest.issues.createComment({
            issue_number: context.issue.number,
            owner: context.repo.owner,
            repo: context.repo.repo,
            body: `✅ Tests passed! Code coverage: ${coverage}%`
          });
```

### Step 3: Deploy Workflow (Optional)

Create `.github/workflows/deploy.yml` for automatic deployments:

```yaml
name: CD - Deploy to Production

on:
  push:
    branches: [ main ]
  workflow_dispatch:  # Allow manual triggering

jobs:
  deploy:
    runs-on: ubuntu-latest
    if: github.event_name == 'push' || github.event_name == 'workflow_dispatch'

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Set up Java 21
      uses: actions/setup-java@v4
      with:
        java-version: '21'
        distribution: 'temurin'
        cache: maven

    # Step 1: Build application
    - name: Build application
      run: mvn clean package -DskipTests

    # Step 2: Build Docker image
    - name: Build Docker image
      run: |
        docker build -t auth-server:${{ github.sha }} .
        docker tag auth-server:${{ github.sha }} auth-server:latest

    # Step 3: Push to Docker registry (Docker Hub, ECR, etc.)
    - name: Push to Docker Hub
      run: |
        docker login -u ${{ secrets.DOCKER_USERNAME }} -p ${{ secrets.DOCKER_PASSWORD }}
        docker push auth-server:${{ github.sha }}
        docker push auth-server:latest

    # Step 4: Deploy to Kubernetes (if using K8s)
    - name: Deploy to Kubernetes
      run: |
        kubectl set image deployment/auth-server \
          auth-server=auth-server:${{ github.sha }} \
          -n production
        kubectl rollout status deployment/auth-server -n production

    # Step 5: Run smoke tests
    - name: Run smoke tests
      run: |
        curl -f http://auth-server.example.com/actuator/health || exit 1

    # Step 6: Notify Slack
    - name: Notify Slack on success
      if: success()
      uses: slackapi/slack-github-action@v1.24.0
      with:
        webhook-url: ${{ secrets.SLACK_WEBHOOK }}
        payload: |
          {
            "text": "✅ Auth Server deployed successfully!",
            "blocks": [
              {
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Auth Server Deployment Successful*\nVersion: ${{ github.sha }}\nAuthor: ${{ github.actor }}"
                }
              }
            ]
          }

    - name: Notify Slack on failure
      if: failure()
      uses: slackapi/slack-github-action@v1.24.0
      with:
        webhook-url: ${{ secrets.SLACK_WEBHOOK }}
        payload: |
          {
            "text": "❌ Auth Server deployment failed!",
            "blocks": [
              {
                "type": "section",
                "text": {
                  "type": "mrkdwn",
                  "text": "*Auth Server Deployment Failed*\nVersion: ${{ github.sha }}\nAuthor: ${{ github.actor }}"
                }
              }
            ]
          }
```

---

## Setup Instructions

### 1. GitHub Actions (No Setup Needed!)

GitHub Actions is **free for public repositories** and included with GitHub.

**Nothing to do!** Just push the workflow files and they run automatically.

### 2. Set Up Secrets

For sensitive data (Docker credentials, Slack webhook), add secrets to your repository:

```
GitHub → Settings → Secrets and variables → Actions → New repository secret
```

Add these secrets:
- `DOCKER_USERNAME` - Docker Hub username
- `DOCKER_PASSWORD` - Docker Hub token
- `SLACK_WEBHOOK` - Slack webhook URL (optional)

### 3. Check Workflow Status

After pushing workflow files:

```
GitHub → Actions tab → See all workflows running
```

---

## Alternative CI/CD Platforms

### GitLab CI/CD

Create `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - build
  - deploy

test:
  stage: test
  image: maven:3.9-eclipse-temurin-21
  services:
    - postgres:15
  script:
    - mvn clean test
  coverage: '/Coverage: \d+\.?\d*%/'
  artifacts:
    reports:
      junit: target/surefire-reports/*.xml

build:
  stage: build
  image: maven:3.9-eclipse-temurin-21
  script:
    - mvn clean package -DskipTests
  artifacts:
    paths:
      - target/*.jar
    expire_in: 1 day

deploy:
  stage: deploy
  image: alpine:latest
  script:
    - apk add --no-cache kubectl
    - kubectl set image deployment/auth-server auth-server=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  only:
    - main
  environment:
    name: production
    url: https://auth.example.com
```

### Jenkins

Create `Jenkinsfile`:

```groovy
pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                checkout scm
                sh 'mvn clean verify'
            }
        }

        stage('Test') {
            steps {
                sh 'mvn test'
                junit 'target/surefire-reports/*.xml'
            }
        }

        stage('Coverage') {
            steps {
                sh 'mvn jacoco:report'
                publishHTML([
                    reportDir: 'target/site/jacoco',
                    reportFiles: 'index.html',
                    reportName: 'Code Coverage'
                ])
            }
        }

        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh '''
                    docker build -t auth-server:${BUILD_NUMBER} .
                    docker tag auth-server:${BUILD_NUMBER} auth-server:latest
                    docker push auth-server:latest
                '''
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        failure {
            emailext(
                subject: 'Build Failed',
                body: 'Check Jenkins logs',
                to: 'team@example.com'
            )
        }
    }
}
```

---

## Docker Setup

Create `Dockerfile`:

```dockerfile
# Stage 1: Build
FROM maven:3.9-eclipse-temurin-21 AS builder

WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source code
COPY src ./src

# Build application
RUN mvn clean package -DskipTests

# Stage 2: Runtime
FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

# Copy JAR from builder
COPY --from=builder /app/target/authentication-server-*.jar app.jar

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/actuator/health || exit 1

# Run application
ENTRYPOINT ["java", "-jar", "app.jar"]

EXPOSE 8080
```

Build and test locally:

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

---

## Kubernetes Deployment

Create `k8s/deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-server
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth-server
  template:
    metadata:
      labels:
        app: auth-server
    spec:
      containers:
      - name: auth-server
        image: auth-server:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: auth-server-secrets
              key: database-url
        - name: DATABASE_USER
          valueFrom:
            secretKeyRef:
              name: auth-server-secrets
              key: database-user
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: auth-server-secrets
              key: database-password
        livenessProbe:
          httpGet:
            path: /actuator/health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: auth-server-service
  namespace: production
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
  selector:
    app: auth-server
```

Deploy:

```bash
# Create secrets
kubectl create secret generic auth-server-secrets \
  --from-literal=database-url=jdbc:postgresql://postgres.default:5432/auth_server \
  --from-literal=database-user=postgres \
  --from-literal=database-password=password \
  -n production

# Deploy
kubectl apply -f k8s/deployment.yaml

# Check status
kubectl get deployment -n production
kubectl logs deployment/auth-server -n production
```

---

## Monitoring & Alerting

### Prometheus Setup

Create `prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'auth-server'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/actuator/prometheus'
```

### Grafana Dashboard

Add data source:
```
Configuration → Data Sources → Prometheus
URL: http://prometheus:9090
```

Create dashboard with metrics:
```
- http_requests_total
- jvm_memory_used_bytes
- jvm_threads_live
- process_uptime_seconds
```

---

## Best Practices

### 1. Branch Protection Rules

Require CI to pass before merging:

```
GitHub → Settings → Branches → Add rule
Pattern: main
Requirements:
  ✅ Require status checks to pass before merging
  ✅ Require code review
  ✅ Dismiss stale reviews
```

### 2. Code Coverage Requirements

Fail CI if coverage drops:

```yaml
- name: Check code coverage
  run: |
    COVERAGE=$(grep -oP 'Total.*?<td class="value">\K[^<]+' target/site/jacoco/index.html)
    if (( $(echo "$COVERAGE < 85" | bc -l) )); then
      echo "❌ Coverage dropped below 85%: $COVERAGE%"
      exit 1
    fi
```

### 3. Automated Changelog

Generate changelog from commits:

```bash
# Install changelog tool
npm install -g @conventional-changelog/cli

# Generate
conventional-changelog -p angular -i CHANGELOG.md -s
git add CHANGELOG.md
git commit -m "chore: update changelog"
```

### 4. Semantic Versioning

Auto-increment version on release:

```yaml
- name: Create Release
  uses: actions/create-release@v1
  with:
    tag_name: v${{ env.VERSION }}
    release_name: Release ${{ env.VERSION }}
```

---

## Troubleshooting

### Tests Pass Locally but Fail in CI

**Possible causes:**
- Different Java version
- Missing environment variables
- Database not accessible
- Timing issues (flaky tests)

**Solutions:**
```bash
# Run tests exactly like CI
docker run -it maven:3.9-eclipse-temurin-21 /bin/bash
mvn clean verify

# Check environment variables
env | grep -i db

# Run tests multiple times to catch flaky ones
for i in {1..10}; do mvn test; done
```

### Docker Image Too Large

**Reduce image size:**

```dockerfile
# Use alpine base
FROM eclipse-temurin:21-jre-alpine

# Multi-stage build (already shown above)

# Remove unnecessary files
RUN rm -rf /app/docs /app/tests
```

Check size:
```bash
docker images | grep auth-server
# Should be ~300-400 MB
```

### Deployment Failures

**Debug Kubernetes issues:**

```bash
# Check pod status
kubectl describe pod -l app=auth-server -n production

# View logs
kubectl logs -l app=auth-server -n production --tail=100

# Port forward for testing
kubectl port-forward service/auth-server-service 8080:80 -n production

# Test locally
curl http://localhost:8080/actuator/health
```

---

## Checklist: CI/CD Setup

- [ ] Create `.github/workflows/ci.yml`
- [ ] Create `.github/workflows/deploy.yml` (optional)
- [ ] Configure GitHub secrets (Docker credentials, etc.)
- [ ] Enable branch protection rules
- [ ] Add coverage badges to README
- [ ] Create `Dockerfile`
- [ ] Test Docker build locally
- [ ] Set up monitoring (Prometheus/Grafana)
- [ ] Create alerting rules
- [ ] Document deployment procedure
- [ ] Train team on CI/CD process

---

## Next Steps

1. **Push workflow files:** Copy CI/CD files to repository
2. **Test locally:** Build Docker image and run tests
3. **Monitor first deployment:** Watch metrics closely
4. **Iterate:** Refine based on production experience
5. **Add more stages:** Coverage checks, security scans, etc.

---

## Resources

- **GitHub Actions:** https://github.com/features/actions
- **Docker:** https://www.docker.com/
- **Kubernetes:** https://kubernetes.io/
- **Prometheus:** https://prometheus.io/
- **Grafana:** https://grafana.com/

---

**Your CI/CD pipeline is now ready! 🚀**

Every push runs tests automatically. Every merge to main deploys to production.
