# Container Security Assessment

## 1. Assessment Overview

| Property | Value |
|---|---|
| Project | Azure AI Cybersecurity Lab |
| Image | azure-ai-cybersecurity-lab:1.4 |
| Base image | python:3.14-slim |
| Operating system | Debian 13.7 |
| Scanner | Trivy 0.76.0 |
| Scan date | November 17, 2026 |
| Scan type | Vulnerability scanning |

The container image was assessed using Trivy. The assessment covers
operating-system packages and Python dependencies.

## 2. Container Hardening

The following security measures are implemented:

- Uses the official Python 3.14 slim base image.
- Updates available Debian packages during the image build.
- Installs only production dependencies from requirements.txt.
- Keeps pytest and Bandit in requirements-dev.txt.
- Removes pip and its installed executables from the final runtime image
  after installing application dependencies.
- Runs the application as a dedicated non-root user.
- Uses UID 10001 (appuser).
- Uses a .dockerignore file to exclude development files, Git metadata,
  reports, and other unnecessary content from the build context.
- Exposes application port 8000.

## 3. Runtime Verification

The deployed container was tested after startup.

| Verification | Result |
|---|---|
| Container startup | Passed |
| Health endpoint | HTTP 200 OK |
| Health response | {"status":"healthy"} |
| Runtime user | appuser |
| Runtime UID | 10001 |
| FastAPI installed | Yes |
| Pydantic installed | Yes |
| Uvicorn installed | Yes |
| HTTPX installed | Yes |
| Pytest installed | No |
| Bandit installed | No |

The application runs as a non-root user, and development-only packages
are excluded from the production image.

## 4. Trivy Vulnerability Results

Image: azure-ai-cybersecurity-lab:1.4

| Severity | Findings |
|---|---:|
| CRITICAL | 0 |
| HIGH | 47 |
| MEDIUM | 92 |
| LOW | 65 |
| UNKNOWN | 5 |
| **Total** | **209** |

### Findings by scanner

| Scanner | Findings |
|---|---:|
| Debian OS packages | 209 |
| Python dependencies | 0 |
| **Total** | **209** |

Trivy identified Debian 13.7 and scanned 87 operating-system packages.
The Python package scanner reported zero vulnerabilities.

Trivy also reported that vendor severity ratings were used for some
vulnerabilities. Severity classifications should therefore be
interpreted in the context of the relevant vendor advisories.

## 5. Risk Assessment and Limitations

The remaining findings are associated with Debian operating-system
packages rather than the application's Python dependencies.

A vulnerability finding does not by itself establish that the
application is exploitable. Each finding requires review of its
affected package, vulnerability conditions, available fixes, and
whether the affected component is reachable or used.

The findings have not been suppressed or silently excluded.

The image build includes an operating-system package upgrade step.
However, that step did not eliminate all reported findings.

Some vulnerabilities may not have a fixed package version available
in the configured Debian repositories at scan time. These findings
require continued monitoring.

The scan is a point-in-time assessment. Results can change when the
base image, package repositories, or Trivy vulnerability database
changes.

## 6. Remediation and Follow-up

Recommended maintenance activities:

1. Rebuild the image periodically using an updated base image.
2. Refresh package repositories before each build.
3. Re-run Trivy after image updates.
4. Review HIGH findings against Debian security advisories.
5. Apply package updates when fixes become available.
6. Re-test application health and runtime permissions after updates.
7. Track changes in vulnerability counts between image versions.

## 7. Scan Artifact

The raw Trivy JSON report is retained locally at:

reports/trivy-docker-scan-1.4.json

Generated scan reports are excluded from Git through .gitignore.

## 8. Conclusion

The version 1.4 container implements several practical hardening
measures, including non-root execution, production-only Python
dependencies, and reduced runtime tooling.

The Python dependency scan returned zero findings. The remaining
209 findings are associated with Debian operating-system packages
and require ongoing assessment and remediation as fixes become
available.

This assessment documents the current state of the image; it is not
a certification that the container is vulnerability-free.
