# Azure AI Cybersecurity Lab

Local-first AI-assisted cybersecurity and threat detection project.

## Features

- FastAPI security event ingestion
- Deterministic threat detection
- MITRE ATT&CK mapping
- Local Ollama AI analysis
- Docker container hardening
- Trivy vulnerability scanning
- GitHub Actions CI

## Architecture

1. Security events are submitted through the FastAPI REST API.
2. Pydantic validates incoming event data.
3. The detection engine evaluates events against deterministic rules.
4. Alerts are mapped to applicable MITRE ATT&CK tactics and techniques.
5. Optional Ollama analysis provides additional incident context.
6. Results are returned as JSON.

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.14 | Application and detection logic |
| FastAPI | REST API |
| Pydantic | Input validation |
| Ollama | Local AI-assisted analysis |
| Qwen 2.5 3B | Local language model |
| MITRE ATT&CK | Threat classification |
| Docker | Containerization |
| Trivy | Container vulnerability scanning |
| pytest | Automated testing |
| Bandit | Python security scanning |
| GitHub Actions | Continuous integration |

## Detection Capabilities

The detection engine evaluates events within a five-minute UTC window.

| Detection Rule | Trigger | Severity |
|---|---|---|
| BRUTE_FORCE | Five or more failed login events from one source IP | HIGH |
| PRIVILEGE_ESCALATION | A privilege escalation event | CRITICAL |
| UNAUTHORIZED_API_ACCESS | Five or more unauthorized API events from one source IP | HIGH |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | / | Application status |
| GET | /health | Health check |
| GET | /rules | Detection rules |
| POST | /analyze | Analyze security events |

Interactive API documentation is available at http://localhost:8000/docs.


## Getting Started

### Requirements

- Python 3.14
- Git
- Ollama (optional, for AI-assisted analysis)
- Docker (optional, for container deployment)

### 1. Clone the repository

    git clone https://github.com/decorpintor/azure-ai-cybersecurity-lab.git
    cd azure-ai-cybersecurity-lab

### 2. Create a virtual environment

    python3.14 -m venv .venv
    source .venv/bin/activate

### 3. Install dependencies

    python -m pip install --upgrade pip
    python -m pip install -r requirements-dev.txt

### 4. Start the API

    uvicorn app.main:app --host 0.0.0.0 --port 8000

The API will be available at:

- API root: http://localhost:8000/
- Health check: http://localhost:8000/health
- Detection rules: http://localhost:8000/rules
- Interactive API documentation: http://localhost:8000/docs

## Example API Requests

### Health check

    curl http://localhost:8000/health

Expected response:

    {"status":"healthy"}

### List detection rules

    curl http://localhost:8000/rules

### Analyze security events

Create a file named payload.json containing security events. Each event must include:

- timestamp: ISO 8601 timestamp with timezone
- event_type: login, privilege_escalation, or api_access
- status: failed, success, or unauthorized
- source_ip: source IP address
- username: associated username

Example event:

    {
      "timestamp": "2026-11-17T12:00:00Z",
      "event_type": "login",
      "status": "failed",
      "source_ip": "192.168.1.100",
      "username": "analyst"
    }

Submit the payload:

    curl -X POST http://localhost:8000/analyze -H "Content-Type: application/json" -d @payload.json

Events must fall within the five-minute UTC detection window to trigger the time-based rules. The API accepts between 1 and 1,000 events per request.


## Local AI Analysis with Ollama

The project supports optional AI-assisted incident analysis using a locally hosted Ollama model.

The default configuration is:

| Setting | Default |
|---|---|
| OLLAMA_URL | http://localhost:11434 |
| OLLAMA_MODEL | qwen2.5:3b |
| OLLAMA_TIMEOUT_SECONDS | 60 |

### Install and prepare the model

Install Ollama from https://ollama.com/.

Download the model:

    ollama pull qwen2.5:3b

Start the Ollama service:

    ollama serve

Verify the installed model:

    ollama list

### Enable AI analysis

The API uses deterministic analysis by default. To request additional Ollama analysis, submit:

    curl -X POST "http://localhost:8000/analyze?use_ai=true" -H "Content-Type: application/json" -d @payload.json

AI-generated analysis is advisory. It does not change the deterministic detection rules or alert severity. If Ollama is unavailable, the application retains its deterministic analysis and reports the AI analysis as unavailable.

## Docker Deployment

The application includes a hardened Docker image.

### Build the image

    docker build -t azure-ai-cybersecurity-lab:1.4 .

### Run the container

    docker run -d --name azure-ai-cybersecurity-lab -p 8001:8000 azure-ai-cybersecurity-lab:1.4

### Verify container health

    curl http://localhost:8001/health

Expected response:

    {"status":"healthy"}

### Inspect and stop the container

    docker logs azure-ai-cybersecurity-lab
    docker stop azure-ai-cybersecurity-lab
    docker rm azure-ai-cybersecurity-lab

The container runs as a non-root application user (UID 10001). The runtime image installs production dependencies rather than development testing and scanning tools.

Note: The default Ollama URL uses localhost. If the API runs inside Docker, configure OLLAMA_URL to point to an Ollama service reachable from the container.


## CI/CD and Security Validation

GitHub Actions automatically validates changes pushed to the main branch and pull requests targeting main.

The CI workflow performs:

- Python dependency installation
- Automated pytest test execution
- Python compile-time checks using compileall
- Static security analysis using Bandit

### Local validation

Run the automated tests:

    python -m pytest -v

Compile the application:

    python -m compileall -q ai app detection scripts

Run Bandit:

    python -m bandit -r ai app detection scripts

## Container Security Assessment

The Docker image was scanned with Trivy 0.76.0.

### Recorded scan results

| Severity | Findings |
|---|---:|
| CRITICAL | 0 |
| HIGH | 47 |
| MEDIUM | 92 |
| LOW | 65 |
| UNKNOWN | 5 |
| Total | 209 |

The recorded findings were associated with Debian operating system packages. Trivy reported no Python package vulnerabilities in this scan.

These are point-in-time scan results, not a claim that the image is vulnerability-free. OS package findings should be reviewed against available fixes and the current image build.

See [Container Security Assessment](docs/container-security-assessment.md) for the detailed assessment.

## Security Considerations and Limitations

- The API does not currently implement authentication or authorization.
- Do not expose the service to untrusted networks or use it as a production security monitoring platform.
- Do not submit sensitive production security data to this demonstration environment.
- AI-generated analysis is advisory and does not automatically remediate incidents or change alert severity.
- The application currently returns analysis through its API; it is not a persistent SIEM or incident-management platform.
- Ollama is optional. Deterministic detection works independently of the AI service.

## Future Improvements

Potential areas for future development include:

- Persistent security event storage and incident history
- Authentication and role-based access control
- Security monitoring dashboard
- Azure Monitor and Microsoft Sentinel integration
- Infrastructure provisioning and deployment automation
- Additional detection rules and automated security testing

## Author

Cordice Saunders

GitHub: https://github.com/decorpintor

Project repository: https://github.com/decorpintor/azure-ai-cybersecurity-lab

