# Security Recommendations for Liquibase Docker Image

## Quick Start - Immediate Actions

### Option 1: Use Pre-Built Secure Dockerfile (Fastest)
```bash
# Build using the secure Dockerfile
docker build -f Dockerfile.secure -t liquibase-azure:secure .

# Scan to verify improvements
docker scout cves liquibase-azure:secure
```

### Option 2: Use Distroless Base (Most Secure)
```bash
# Build using distroless base (minimal attack surface)
docker build -f Dockerfile.distroless -t liquibase-azure:distroless .

# Scan to verify
docker scout cves liquibase-azure:distroless
```

### Option 3: Manual Dependency Update (Custom Requirements)
Follow the detailed steps in VULNERABILITY_FIXES.md

## Comparison of Approaches

| Approach | HIGH CVEs | MEDIUM CVEs | LOW CVEs | Effort | Maintenance |
|----------|-----------|-------------|----------|--------|-------------|
| Original | 7 | 13 | 16 | - | - |
| Dockerfile.secure | 0 | 2-4 | 14-16 | Low | Medium |
| Dockerfile.distroless | 0 | 0-2 | 2-4 | Medium | Low |
| Manual Update | 0 | 0-3 | 15-16 | High | High |

## Detailed Recommendations

### 1. Immediate Fixes (Critical Priority)

#### Update Netty Dependencies
**Impact**: Fixes 3 HIGH severity CVEs
```xml
<!-- Update these in your Maven dependencies or JAR -->
<dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-codec-http2</artifactId>
    <version>4.1.125.Final</version>
</dependency>
<dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-handler</artifactId>
    <version>4.1.118.Final</version>
</dependency>
<dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-common</artifactId>
    <version>4.1.118.Final</version>
</dependency>
<dependency>
    <groupId>io.netty</groupId>
    <artifactId>netty-codec</artifactId>
    <version>4.1.125.Final</version>
</dependency>
```

#### Update json-smart
**Impact**: Fixes 1 HIGH severity CVE
```xml
<dependency>
    <groupId>net.minidev</groupId>
    <artifactId>json-smart</artifactId>
    <version>2.5.2</version>
</dependency>
```

#### Update Go Binary (lpm)
**Impact**: Fixes 4 HIGH + 6 MEDIUM CVEs
- Upgrade Liquibase base image to version with Go 1.25.2+
- Or rebuild lpm binary with Go 1.25.3

### 2. High Priority Fixes

#### Update nimbus-jose-jwt
**Impact**: Fixes 1 MEDIUM severity CVE
```xml
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>10.0.2</version>
</dependency>
```

#### Use Newer Base Image
```dockerfile
# Instead of liquibase/liquibase:latest
FROM liquibase/liquibase:5.0.1  # Uses newer Go version
```

### 3. Long-Term Strategies

#### Strategy A: Distroless Base (Recommended)
**Advantages**:
- Minimal attack surface (no shell, package manager, or extra binaries)
- Fewer OS-level vulnerabilities
- Smaller image size
- Better security posture

**Disadvantages**:
- Harder to debug (no shell access)
- Requires multi-stage builds
- May need custom tooling for troubleshooting

**Use Case**: Production environments prioritizing security

#### Strategy B: Alpine Base
**Advantages**:
- Smaller than Ubuntu/Debian
- Fewer packages = fewer vulnerabilities
- Active security updates
- Still has shell for debugging

**Disadvantages**:
- musl libc compatibility issues possible
- Some Java applications may have issues

**Use Case**: Balance between security and maintainability

#### Strategy C: Regular Ubuntu LTS with Hardening
**Advantages**:
- Most compatible
- Easiest to debug
- Familiar tooling

**Disadvantages**:
- Larger attack surface
- More unfixable LOW severity CVEs
- Larger image size

**Use Case**: Development/testing environments

### 4. CI/CD Integration

#### Add Vulnerability Scanning to Pipeline
```yaml
# GitHub Actions example
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build image
        run: docker build -f Dockerfile.secure -t liquibase-test .
      
      - name: Run Docker Scout
        uses: docker/scout-action@v1
        with:
          command: cves
          image: liquibase-test
          only-severities: critical,high
          exit-code: true
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: liquibase-test
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
```

#### Set Vulnerability Thresholds
```yaml
# Example policy
security_policy:
  max_critical: 0
  max_high: 0
  max_medium: 5
  max_low: 20
  fail_build: true
```

### 5. Runtime Security

#### Use Read-Only Filesystem
```bash
docker run --read-only \
  --tmpfs /tmp \
  liquibase-azure:secure \
  --changeLogFile=changelog.xml \
  update
```

#### Limit Resources
```bash
docker run \
  --memory=1g \
  --cpus=1 \
  --pids-limit=100 \
  liquibase-azure:secure
```

#### Use Security Profiles
```bash
# AppArmor
docker run --security-opt apparmor=docker-default \
  liquibase-azure:secure

# Seccomp
docker run --security-opt seccomp=default.json \
  liquibase-azure:secure
```

### 6. Network Security

#### Use Docker Networks
```bash
# Create isolated network
docker network create --driver bridge liquibase-net

# Run in isolated network
docker run --network liquibase-net \
  liquibase-azure:secure
```

#### Restrict Network Access
```bash
# No internet access (if not needed)
docker run --network none \
  liquibase-azure:secure
```

### 7. Secrets Management

#### Don't Hardcode Credentials
```bash
# BAD - hardcoded
docker run liquibase-azure \
  --username=admin \
  --password=secret123

# GOOD - use Docker secrets
docker run \
  --env-file .env \
  liquibase-azure

# BETTER - use secrets management
docker run \
  --env LIQUIBASE_COMMAND_USERNAME_FILE=/run/secrets/db_user \
  --env LIQUIBASE_COMMAND_PASSWORD_FILE=/run/secrets/db_pass \
  liquibase-azure
```

#### Use Azure Key Vault
```bash
# Fetch credentials at runtime
docker run \
  -e AZURE_KEYVAULT_URL=https://myvault.vault.azure.net/ \
  -e LIQUIBASE_COMMAND_USERNAME=$(az keyvault secret show --name db-user --query value -o tsv) \
  liquibase-azure
```

### 8. Monitoring and Logging

#### Enable Security Logging
```bash
docker run \
  --log-driver=json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  --log-opt labels=security,version \
  liquibase-azure:secure
```

#### Integrate with SIEM
- Forward Docker logs to Azure Monitor
- Use Azure Security Center for container insights
- Enable Azure Defender for Containers

### 9. Regular Maintenance

#### Schedule Vulnerability Scans
```bash
# Weekly automated scans
0 0 * * 0 docker scout cves liquibase-azure:latest --format sarif > scan-results.sarif
```

#### Update Dependencies Quarterly
- Review new CVEs monthly
- Update dependencies quarterly
- Rebuild images with security patches

#### Subscribe to Security Advisories
- Liquibase: https://github.com/liquibase/liquibase/security/advisories
- Netty: https://github.com/netty/netty/security/advisories
- MSSQL JDBC: https://github.com/microsoft/mssql-jdbc/security/advisories
- Base Image: https://ubuntu.com/security/notices

### 10. Documentation and Compliance

#### Maintain SBOM (Software Bill of Materials)
```bash
# Generate SBOM
docker sbom liquibase-azure:secure --format spdx > sbom.json

# Or use Syft
syft liquibase-azure:secure -o spdx-json > sbom.json
```

#### Document Accepted Risks
For unfixable vulnerabilities:
1. Document why they're accepted
2. Note mitigation strategies
3. Set review dates
4. Get stakeholder approval

Example:
```
CVE-2016-2781 (coreutils): ACCEPTED
- Requires local access with specific configuration
- Mitigation: Container runs as non-root
- Alternative: Use distroless image
- Review Date: Q2 2025
```

## Summary Checklist

- [ ] Update Netty to 4.1.125.Final or later
- [ ] Update json-smart to 2.5.2 or later  
- [ ] Update nimbus-jose-jwt to 10.0.2 or later
- [ ] Update Go binary (lpm) to use Go 1.25.2+
- [ ] Consider distroless or Alpine base
- [ ] Add vulnerability scanning to CI/CD
- [ ] Implement runtime security controls
- [ ] Use proper secrets management
- [ ] Enable security logging and monitoring
- [ ] Document accepted risks
- [ ] Schedule regular security reviews

## Testing Your Fixes

### 1. Functional Testing
```bash
# Build image
docker build -f Dockerfile.secure -t liquibase-azure:test .

# Test version
docker run liquibase-azure:test --version

# Test help
docker run liquibase-azure:test --help

# Test database connection (replace with your details)
docker run liquibase-azure:test \
  --url="jdbc:sqlserver://yourserver.database.windows.net:1433;database=yourdb" \
  --username="user@yourserver" \
  --password="yourpassword" \
  --changeLogFile="changelog.xml" \
  status
```

### 2. Security Testing
```bash
# Scan with Docker Scout
docker scout cves liquibase-azure:test

# Scan with Trivy
trivy image liquibase-azure:test

# Check for secrets
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image --scanners secret liquibase-azure:test

# Compare before/after
docker scout compare liquibase-azure:old --to liquibase-azure:test
```

### 3. Performance Testing
```bash
# Measure image size
docker images liquibase-azure:test --format "{{.Size}}"

# Measure startup time
time docker run liquibase-azure:test --version

# Check resource usage
docker stats liquibase-azure:test
```

## Support and Resources

- **This Repository**: See VULNERABILITY_FIXES.md for detailed analysis
- **Dockerfile.secure**: Production-ready with updated dependencies
- **Dockerfile.distroless**: Minimal security-focused image
- **Docker Scout**: https://docs.docker.com/scout/
- **Trivy**: https://github.com/aquasecurity/trivy
- **Azure Security**: https://docs.microsoft.com/azure/security/

## Questions?

For questions or issues:
1. Review the detailed VULNERABILITY_FIXES.md document
2. Check the vulnerability scan outputs (vulnerabilities.json, vulnerabilities.md)
3. Test with provided Dockerfiles
4. Consult with your security team for risk acceptance
