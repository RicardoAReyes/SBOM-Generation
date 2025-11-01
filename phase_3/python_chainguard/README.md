# Phase 3 - Python Chainguard with Nexus/Libraries Registry

This phase demonstrates **SBOM enrichment workflow** using Chainguard's secure Python base images combined with Chainguard Python packages from a Nexus registry or Chainguard Libraries.

## Overview

This implementation showcases advanced SBOM lifecycle management focusing on:

1. **Vendor SBOM Reuse** - Extracting pre-existing SBOMs from Chainguard image attestations
2. **Private Registry Integration** - Using Nexus/Chainguard Libraries for Python packages
3. **Multi-stage Builds** - Optimized Docker builds with tool caching
4. **SBOM Enrichment** - Adding NTIA minimum elements using Parlay
5. **Quality Verification** - Scoring SBOMs with sbomqs
6. **Package Verification** - Using chainver for Chainguard package validation

## Architecture

```
┌──────────────────────────────────────────────┐
│   Chainguard Python Base Image               │
│   (cgr.dev/chainguard-private/python:3.11)   │
│   - Pre-signed with cosign                   │
│   - SBOM attached as attestation             │
│   - Minimal attack surface                   │
└───────────────────┬──────────────────────────┘
                    │
                    │ Extract SBOM
                    ▼
┌──────────────────────────────────────────────┐
│   Chainguard Base SBOM                       │
│   (from attestation or Trivy scan)           │
└───────────────────┬──────────────────────────┘
                    │
                    │ Augment with metadata
                    ▼
┌──────────────────────────────────────────────┐
│   Augmented Base SBOM                        │
│   + Author, Supplier, License, Repository    │
└───────────────────┬──────────────────────────┘
                    │
                    │ Enrich ⭐ (Main Focus)
                    ▼
┌──────────────────────────────────────────────┐
│   Enriched Base SBOM                         │
│   + NTIA minimum elements                    │
│   + Component metadata (CPE, PURL)           │
│   + Vulnerability context                    │
└──────────────────────────────────────────────┘

┌──────────────────────────────────────────────┐
│   Application Layer                          │
│   - aiohttp web server                       │
│   - requirements.txt from Nexus/Libraries    │
└───────────────────┬──────────────────────────┘
                    │
                    │ Trivy scan
                    ▼
┌──────────────────────────────────────────────┐
│   Application SBOM                           │
└───────────────────┬──────────────────────────┘
                    │
                    │ Augment + Enrich ⭐
                    ▼
┌──────────────────────────────────────────────┐
│   Enriched Application SBOM                  │
│   + PyPI metadata                            │
│   + License information                      │
│   + Dependency relationships                 │
└───────────────────┬──────────────────────────┘
                    │
                    │ Verify Quality
                    ▼
┌──────────────────────────────────────────────┐
│   Quality Score Report (sbomqs)              │
│   - Before: ~65% completeness                │
│   - After:  ~90% completeness                │
└──────────────────────────────────────────────┘
```

## Project Structure

```
phase_3/python_chainguard/
├── Dockerfile              # Multi-stage build with Chainguard base
├── app.py                  # aiohttp web application
├── requirements.txt        # Python dependencies (aiohttp, requests, etc.)
├── pip.conf               # Nexus/Libraries registry configuration
├── .netrc                 # Authentication credentials
├── .netrc.template        # Template for credentials
├── secrets.txt            # Demo secrets file (for CVE demo)
├── static/
│   └── style.css          # Web application styles
└── README.md              # This file
```

## Application Stack

### Base Image
- **Chainguard Python 3.11** (`cgr.dev/chainguard-private/python:3.11-dev`)
- Includes: curl, jq, unzip, git, cosign
- Tools: chainver, chainctl (for Chainguard package verification)

### Python Dependencies
```
aiohttp==3.9.1           # Async HTTP server
requests==2.32.5         # HTTP client library
aiosignal==1.4.0         # Async signals
attrs==25.4.0            # Classes without boilerplate
charset-normalizer==3.4.4 # Character encoding detection
propcache==0.4.1         # Property caching
urllib3==2.5.0           # HTTP library
certifi==2025.8.3        # Root certificates
frozenlist==1.8.0        # Immutable lists
idna==3.11               # Internationalized domain names
multidict==6.7.0         # Multi-value dictionaries
typing-extensions==4.15.0 # Backported typing features
```

### Application Features
- **Root endpoint** (`/`) - Application information and links
- **Health check** (`/health`) - Service health status
- **Version info** (`/version`) - Application and Python versions
- **Dependencies** (`/dependencies`) - List installed packages
- **Secrets** (`/secrets`) - Demo secrets exposure (CVE demonstration)

## Dockerfile Architecture

### Base Stage
```dockerfile
FROM cgr.dev/chainguard-private/python:3.11-dev AS base
```
- Installs system tools: curl, jq, unzip, git, cosign
- Downloads chainver for Chainguard package verification
- Downloads chainctl for Chainguard CLI operations
- This layer is cached and rarely changes

### Final Stage
```dockerfile
FROM base AS final
```
- Installs application dependencies from Nexus/Libraries
- Copies application code (app.py, static/)
- Runs as non-root user (nonroot:nonroot)
- Exposes port 5000

## Workflow Pipeline

The GitHub Actions workflow (`.github/workflows/phase_3_python_chainguard.yml`) demonstrates the complete enrichment lifecycle:

### Job 1: Build_and_Extract_SBOMs
1. **Install tools**: Trivy, cosign, crane
2. **Configure pip**: Use public PyPI for CI/CD (or Nexus/Libraries in production)
3. **Authenticate**: Chainguard registry (optional, uses public for demo)
4. **Build container**: Multi-stage Docker build with Chainguard base
5. **Extract Chainguard SBOM**: From image attestations using cosign
6. **Generate Application SBOM**: Scan requirements.txt with Trivy
7. **Generate Container SBOM**: Full image scan with Trivy
8. **Vulnerability Scan**: Security assessment of final image
9. **Upload artifacts**: All generated SBOMs

### Job 2: Augment
1. **Download SBOMs**: From previous job
2. **Install sbomasm**: Metadata augmentation tool
3. **Augment Base SBOM**: Add Chainguard supplier information
4. **Augment Application SBOM**: Add CISA author, repository, license
5. **Augment Container SBOM**: Add complete metadata
6. **Process both formats**: CycloneDX and SPDX
7. **Upload augmented SBOMs**

### Job 3: Enrich ⭐ (Main Focus)
1. **Download augmented SBOMs**: From Augment job
2. **Install Parlay**: SBOM enrichment tool
3. **Enrich Base SBOM**: Add NTIA elements for Chainguard components
4. **Enrich Application SBOM**: Add PyPI metadata, licenses, CPEs
5. **Enrich Container SBOM**: Add comprehensive component data
6. **Process both formats**: CycloneDX and SPDX
7. **Upload enriched SBOMs**

### Job 4: Verify
1. **Download all SBOMs**: Generated, augmented, enriched
2. **Install sbomqs**: Quality scoring tool
3. **Score all SBOMs**: Calculate completeness metrics
4. **Compare scores**: Before/after enrichment
5. **Generate report**: GitHub Actions summary with detailed metrics
6. **Compare sizes**: Show file size differences

## Configuration

### Local Development with Nexus

1. **Start Nexus Registry**:
   ```bash
   # Run Nexus on localhost:8081
   docker run -d -p 8081:8081 sonatype/nexus3
   ```

2. **Update `.netrc`**:
   ```
   machine localhost
     login admin
     password admin

   machine host.docker.internal
     login admin
     password admin
   ```

3. **Build and Run**:
   ```bash
   cd phase_3/python_chainguard
   docker build -t chainguard-python-demo .
   docker run -p 5000:5000 chainguard-python-demo
   ```

4. **Access Application**:
   ```
   http://localhost:5000
   ```

### Production with Chainguard Libraries

1. **Get Chainguard Libraries Access**:
   - Sign up at https://console.chainguard.dev
   - Create API token for Libraries access

2. **Update `.netrc`**:
   ```
   machine libraries.cgr.dev
     login your-email@company.com
     password YOUR_TOKEN_HERE
   ```

3. **Update `pip.conf`**:
   ```ini
   [global]
   index-url = https://libraries.cgr.dev/python/simple/
   timeout = 60
   ```

4. **Build with Authentication**:
   ```bash
   docker build \
     --build-arg NEXUS_HOST=libraries.cgr.dev \
     --build-arg PIP_INDEX_URL=https://libraries.cgr.dev/python/simple/ \
     -t chainguard-python-demo .
   ```

### CI/CD with GitHub Actions

1. **Add GitHub Secrets**:
   - `CHAINGUARD_REGISTRY_USER` - Your cgr.dev username
   - `CHAINGUARD_REGISTRY_TOKEN` - Your cgr.dev token
   - `CHAINGUARD_LIBRARIES_USER` - Your Libraries email
   - `CHAINGUARD_LIBRARIES_TOKEN` - Your Libraries API token

2. **Update Workflow** (uncomment lines in workflow file):
   ```yaml
   - name: Configure Chainguard Libraries
     run: |
       echo "machine libraries.cgr.dev login ${{ secrets.CHAINGUARD_LIBRARIES_USER }} password ${{ secrets.CHAINGUARD_LIBRARIES_TOKEN }}" > .netrc
   ```

3. **Trigger Workflow**:
   ```bash
   git add .
   git commit -m "feat: add Chainguard Python SBOM enrichment demo"
   git push
   ```

## Expected Results

### SBOM Quality Scores

**Before Enrichment (Augmented)**:
- Overall Score: ~65-70%
- NTIA Minimum Elements: ~70%
- Component metadata: Limited
- License info: Partial
- CPE/PURL: Minimal

**After Enrichment (Enriched)**:
- Overall Score: ~85-95%
- NTIA Minimum Elements: 90%+
- Component metadata: Comprehensive
- License info: Complete
- CPE/PURL: Full coverage

### Artifacts Generated

1. **generated-sboms** (from Build job)
   - `chainguard-base-sbom.cdx.json` - Base image SBOM
   - `application-sbom.cdx.json` - Application dependencies (CycloneDX)
   - `application-sbom.spdx.json` - Application dependencies (SPDX)
   - `container-sbom.cdx.json` - Full container (CycloneDX)
   - `container-sbom.spdx.json` - Full container (SPDX)
   - `vulnerability-report.txt` - Security scan results

2. **augmented-sboms** (from Augment job)
   - All SBOMs with added metadata (author, supplier, license, etc.)

3. **enriched-sboms** (from Enrich job)
   - All SBOMs with NTIA elements and component enrichment

## Package Verification with chainver

The Dockerfile includes `chainver` for verifying Chainguard package authenticity:

```bash
# Inside container
chainver verify /app/wheels/*.whl
```

This validates:
- Package signatures
- Provenance attestations
- Supply chain security

## Security Considerations

### Chainguard Images Benefits
1. **Minimal attack surface** - Only essential packages
2. **No CVEs** - Continuously rebuilt with latest patches
3. **Non-root by default** - Runs as nonroot user
4. **Signed attestations** - Cryptographic verification
5. **SBOM included** - Supply chain transparency

### Private Registry Benefits
1. **Package control** - Approved packages only
2. **Vulnerability scanning** - Before deployment
3. **License compliance** - Track all licenses
4. **Air-gapped deployments** - No internet dependency

### Best Practices
1. Always verify Chainguard signatures with cosign
2. Use specific image digests in production
3. Scan for vulnerabilities in CI/CD
4. Rotate registry credentials regularly
5. Use GitHub Secrets for sensitive data

## Troubleshooting

### Issue: Cannot pull Chainguard private image
**Solution**:
```bash
# Authenticate with Chainguard registry
echo "$CHAINGUARD_TOKEN" | docker login cgr.dev -u "$CHAINGUARD_USER" --password-stdin
```

### Issue: pip cannot find packages in Nexus
**Solution**:
1. Check .netrc permissions: `chmod 600 .netrc`
2. Verify Nexus is running: `curl http://localhost:8081`
3. Check pip.conf index-url is correct

### Issue: chainver verification fails
**Solution**:
```bash
# Ensure packages are from Chainguard Libraries
pip download --index-url "https://USER:TOKEN@libraries.cgr.dev/python/simple/" \
  -d /app/wheels -r requirements.txt
```

### Issue: Workflow uses wrong Docker image
**Solution**: The workflow temporarily modifies the Dockerfile for CI/CD. In production, use:
```dockerfile
FROM cgr.dev/chainguard-private/python:3.11-dev
```

### Issue: Low enrichment scores
**Solution**:
1. Check internet connectivity for Parlay lookups
2. Verify SBOM format is valid CycloneDX/SPDX
3. Some components may lack public metadata

## NTIA Minimum Elements Compliance

After enrichment, SBOMs include all NTIA required fields:

**Data Fields:**
- ✅ Supplier Name
- ✅ Component Name
- ✅ Version of Component
- ✅ Other Unique Identifiers (PURL, CPE)
- ✅ Dependency Relationship
- ✅ Author of SBOM Data
- ✅ Timestamp

**Automation Support:**
- ✅ Machine-readable format (CycloneDX, SPDX)
- ✅ Automatic generation (Trivy)
- ✅ Automatic enrichment (Parlay)

## Comparison: Standard vs Chainguard Approach

| Aspect | Standard Python | Chainguard Python |
|--------|----------------|-------------------|
| Base Image | python:3.11-slim (140MB) | cgr.dev/chainguard/python:3.11 (60MB) |
| CVEs | 5-20 per month | 0-1 per month |
| SBOM | Manual generation | Included as attestation |
| Updates | Weekly/Monthly | Daily automated |
| User | root by default | nonroot by default |
| Tools | Full OS packages | Minimal essentials only |
| Verification | None | Cosign signatures |

## References

- [Chainguard Images](https://github.com/chainguard-images/images)
- [Chainguard Console](https://console.chainguard.dev/)
- [Chainguard Libraries](https://www.chainguard.dev/chainguard-libraries)
- [Parlay SBOM Enrichment](https://github.com/snyk/parlay)
- [NTIA SBOM Minimum Elements](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)
- [CycloneDX Specification](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.dev/)
- [Trivy Scanner](https://github.com/aquasecurity/trivy)
- [sbomasm Tool](https://github.com/interlynk-io/sbomasm)
- [sbomqs Tool](https://github.com/interlynk-io/sbomqs)

## License

Apache 2.0 - See LICENSE file in repository root.

## Contributing

See CONTRIBUTING.md in the repository root for guidelines.

## Maintainers

See MAINTAINERS.md in the repository root.
