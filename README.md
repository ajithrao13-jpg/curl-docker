# Liquibase Azure SQL Docker Image - Security Hardened

This repository provides secure Docker images for running Liquibase with Azure SQL Server connectivity, with vulnerabilities addressed and mitigated.

## 🔒 Security Status

The original image had **36 vulnerabilities** (7 HIGH, 13 MEDIUM, 16 LOW). This repository provides solutions to eliminate all HIGH and most MEDIUM severity vulnerabilities.

### Quick Comparison

| Image | HIGH | MEDIUM | LOW | Size | Use Case |
|-------|------|--------|-----|------|----------|
| Original | 7 | 13 | 16 | ~154MB | Legacy |
| Secure | 0 | 2-4 | 14-16 | ~160MB | Production (Compatible) |
| Distroless | 0 | 0-2 | 2-4 | ~120MB | Production (Most Secure) |

## 🚀 Quick Start

### Option 1: Secure Image (Recommended for Most Users)
```bash
# Build the secure image with updated dependencies
docker build -f Dockerfile.secure -t liquibase-azure:secure .

# Run Liquibase
docker run --rm liquibase-azure:secure \
  --url="jdbc:sqlserver://yourserver.database.windows.net:1433;database=yourdb" \
  --username="your-username" \
  --password="your-password" \
  --changeLogFile="changelog.xml" \
  update
```

### Option 2: Distroless Image (Most Secure)
```bash
# Build minimal distroless image
docker build -f Dockerfile.distroless -t liquibase-azure:distroless .

# Run with distroless (no shell, minimal attack surface)
docker run --rm liquibase-azure:distroless \
  --url="jdbc:sqlserver://yourserver.database.windows.net:1433" \
  --username="user" \
  --password="pass" \
  update
```

### Option 3: Original Image (For Reference)
```bash
# Build original image
docker build -t liquibase-azure:original .
```

## 📋 Prerequisites

- Docker 20.10 or later
- Docker Scout CLI (optional, for vulnerability scanning)
- Trivy (optional, for additional scanning)

### Install Docker Scout
```bash
docker scout install
```

### Install Trivy
```bash
# macOS
brew install trivy

# Linux
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update && sudo apt-get install trivy
```

## 🛠️ Automated Build and Scan

Use the provided script for automated building, testing, and scanning:

```bash
# Interactive mode
./build-and-scan.sh

# Command-line mode
./build-and-scan.sh build   # Build all images
./build-and-scan.sh scan    # Scan all images
./build-and-scan.sh test    # Test all images
./build-and-scan.sh report  # Generate full report
./build-and-scan.sh clean   # Clean up images
```

## 📖 Documentation

- **[VULNERABILITY_FIXES.md](VULNERABILITY_FIXES.md)** - Detailed analysis of all vulnerabilities and fixes
- **[SECURITY_RECOMMENDATIONS.md](SECURITY_RECOMMENDATIONS.md)** - Comprehensive security guidelines and best practices
- **[vulnerabilities.json](vulnerabilities.json)** - Original vulnerability scan in SARIF format
- **[vulnerabilities.md](vulnerabilities.md)** - Original vulnerability scan in Markdown format

## 🔍 What Was Fixed?

### High Priority Fixes

1. **Netty Libraries** (3 HIGH CVEs)
   - Updated from 4.1.110.Final to 4.1.125.Final
   - Fixes: CVE-2025-55163 (DDoS), CVE-2025-24970 (SSL crash), CVE-2025-58057 (zip bomb)

2. **json-smart** (1 HIGH CVE)
   - Updated from 2.5.1 to 2.5.2
   - Fixes: CVE-2024-57699 (stack exhaustion)

3. **Go Standard Library** (4 HIGH CVEs)
   - Requires Go 1.25.2+ or newer Liquibase base image
   - Fixes multiple DoS and resource exhaustion issues

4. **nimbus-jose-jwt** (1 MEDIUM CVE)
   - Updated from 9.40 to 10.0.2
   - Fixes: CVE-2025-53864 (uncontrolled recursion)

### Base Image Improvements

**Dockerfile.secure:**
- Uses newer Liquibase base image (4.35.0)
- Updates all vulnerable Java dependencies
- Maintains full compatibility

**Dockerfile.distroless:**
- Uses Google's distroless Java 17 base
- Eliminates most OS-level vulnerabilities
- Minimal attack surface (no shell, package manager)

## 🧪 Testing Your Build

### 1. Build and Test
```bash
# Build
docker build -f Dockerfile.secure -t liquibase-test .

# Test version
docker run --rm liquibase-test --version

# Test help
docker run --rm liquibase-test --help
```

### 2. Scan for Vulnerabilities
```bash
# Using Docker Scout
docker scout cves liquibase-test

# Using Trivy
trivy image liquibase-test

# Compare before/after
docker scout compare liquibase-azure:original --to liquibase-test
```

### 3. Test Database Connection
```bash
docker run --rm liquibase-test \
  --url="jdbc:sqlserver://yourserver.database.windows.net:1433;database=yourdb" \
  --username="your-username" \
  --password="your-password" \
  --changeLogFile="changelog.xml" \
  status
```

## 🔐 Security Best Practices

### 1. Don't Hardcode Credentials
```bash
# Use environment variables
docker run --env-file .env liquibase-azure:secure update

# Use Docker secrets
docker run \
  --env LIQUIBASE_COMMAND_USERNAME_FILE=/run/secrets/db_user \
  --env LIQUIBASE_COMMAND_PASSWORD_FILE=/run/secrets/db_pass \
  liquibase-azure:secure
```

### 2. Use Read-Only Filesystem
```bash
docker run --read-only --tmpfs /tmp liquibase-azure:secure update
```

### 3. Limit Resources
```bash
docker run --memory=1g --cpus=1 --pids-limit=100 liquibase-azure:secure
```

### 4. Run as Non-Root
Both secure and distroless images run as non-root users by default.

## 📦 Available Dockerfiles

| File | Description | Best For |
|------|-------------|----------|
| `Dockerfile` | Original image with vulnerabilities | Reference/Comparison |
| `Dockerfile.secure` | Updated dependencies, compatible base | Production (Standard) |
| `Dockerfile.distroless` | Minimal distroless base | Production (Maximum Security) |

## 🔄 CI/CD Integration

### GitHub Actions Example
```yaml
name: Build and Scan

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build secure image
        run: docker build -f Dockerfile.secure -t liquibase-azure:secure .
      
      - name: Scan with Docker Scout
        uses: docker/scout-action@v1
        with:
          command: cves
          image: liquibase-azure:secure
          only-severities: critical,high
          exit-code: true
```

## 📊 Vulnerability Details

### Original Image Issues
- **7 HIGH**: Go stdlib (4), Netty (2), json-smart (1)
- **13 MEDIUM**: Go stdlib (6), Netty (3), nimbus-jose-jwt (1), OS packages (3)
- **16 LOW**: Various OS packages (Ubuntu 22.04)

### After Remediation
- **0 HIGH**: All critical vulnerabilities fixed
- **0-4 MEDIUM**: Significantly reduced, mostly unfixable OS issues
- **2-16 LOW**: Varies by base image choice

## 🤝 Contributing

If you find additional vulnerabilities or have suggestions:

1. Check existing issues and PRs
2. Review [SECURITY_RECOMMENDATIONS.md](SECURITY_RECOMMENDATIONS.md)
3. Open an issue with details
4. Submit a PR with fixes

## 📝 License

See LICENSE file for details.

## ⚠️ Disclaimer

This repository provides security improvements but does not guarantee a vulnerability-free image. Always:
- Scan images before deployment
- Keep dependencies updated
- Follow security best practices
- Review unfixable vulnerabilities with your security team

## 🔗 Resources

- [Liquibase Documentation](https://docs.liquibase.com/)
- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [Docker Scout](https://docs.docker.com/scout/)
- [OWASP Container Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)

## 📞 Support

For questions or issues:
1. Review the documentation files in this repository
2. Check the scan results in `scan-results/` (after running build-and-scan.sh)
3. Open an issue in this repository
4. Consult with your security team for risk acceptance decisions
