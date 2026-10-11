# PromptShield Integration Checklist & Module Interface Contracts
**VORTEXA 3.0 | Problem Statement C-03 (Cybersecurity & Digital Trust Track)**
**Branch:** `feature/testing-deployment` | **Version:** 1.0.0

---

## 1. Executive Summary & Integration Architecture

PromptShield is engineered as a decoupled four-role defensive architecture:
1. **Laptop 1 (Frontend UI)**: Interactive security workbench, pipeline visualizer, policy management studio, human review queue, audit trail viewer, and live benchmarking interface.
2. **Laptop 2 (Detection Engine)**: Multi-stage real-time content analysis engine performing Unicode normalization, multi-signal prompt injection detection, canary secret scanning, risk scoring, surgical sanitization, and screening gatekeeper before LLM invocation.
3. **Laptop 3 (Policy & Database Service)**: Authoritative stateful policy management layer with deterministic precedence (`BLOCK` $\succ$ `ESCALATE` $\succ$ `SANITIZE` $\succ$ `ALLOW`), PostgreSQL persistence, Alembic migrations, RBAC/JWT authentication, review queue, and append-only audit trail.
4. **Laptop 4 (Testing, Evaluation & DevSecOps)**: Labelled evaluation dataset, automated unit/integration suites, security regression test invariants, Docker Compose containerization, and evaluation report generation.

---

## 2. Module Specifications & Inter-Service Contracts

### Module 1: Laptop 2 — Detection Engine (`backend/`)
- **Owner / Directory**: Detection Logic Team (`backend/`)
- **Primary Entry Point**: `backend.main:app` (FastAPI)
- **Runtime Port**: `8000`
- **Dependencies**: `fastapi`, `uvicorn`, `pydantic`, `httpx`
- **Environment Variables**:
  - `POLICY_SERVICE_URL`: URL to Laptop 3 policy service (e.g. `http://localhost:8001`)
  - `POLICY_TIMEOUT_SECONDS`: Maximum latency for remote policy handshake (default: `2.0s`)
  - `MAX_CONTENT_LENGTH`: Maximum characters per scan request (default: `1,048,576` = 1MB)
  - `MAX_SCAN_PAYLOAD_BYTES`: Maximum raw HTTP payload size (default: `2,097,152` = 2MB)
  - `CANARY_TOKENS`: JSON array of synthetic canary tokens monitored for exfiltration
- **Key API Schemas**:
  - `POST /api/v1/scan`:
    - **Request**: `ScanRequest(content: str, source_type: str, trusted_metadata: dict, application_context: dict)`
    - **Response**: `ScanResponse(scan_id: str, final_decision: str, risk_score: float, risk_classification: str, decision_reason: str, findings: list, sanitized_content: str, processing_duration_ms: float)`
  - `POST /api/v1/llm/generate`:
    - **Request**: `ScreenedLLMRequest(content: str, source_type: str, system_instruction: str)`
    - **Response**: `ScreenedLLMResponse(llm_response: dict, security_scan: dict, screening_proof_token: str)`
  - `GET /health`: Health and telemetry endpoint
- **Startup Command**:
  ```powershell
  python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
  ```
- **Known Limitations**:
  - Bounded recursive decoding limited to depth 3 to avoid decompression bombs.
  - Large payloads (>1MB) rejected at Stage A for denial-of-service prevention.

---

### Module 2: Laptop 3 — Policy & Database Layer (`promptshield/`)
- **Owner / Directory**: Policy & Database Team (`promptshield/`, `alembic/`)
- **Primary Entry Point**: `promptshield.main:app` (FastAPI)
- **Runtime Port**: `8001`
- **Dependencies**: `fastapi`, `uvicorn`, `sqlalchemy`, `alembic`, `pydantic`, `pydantic-settings`, `python-jose`, `passlib`
- **Environment Variables**:
  - `DATABASE_URL`: PostgreSQL connection string (fallback: `sqlite:///./promptshield.db`)
  - `JWT_SECRET_KEY`: Minimum 32-byte secret for access token signing
  - `FAIL_SECURE_MODE`: When `true`, missing policies or service errors default to `BLOCK`
  - `CORS_ORIGINS`: Allowed client origins (e.g. `["*"]` or `["http://localhost:3000"]`)
- **Key API Schemas**:
  - `POST /api/v1/enforce`:
    - **Request**: `EnforceRequest(source_type: str, detection_findings: list, content_to_sanitize: str, policy_id: str)`
    - **Response**: `EnforceResponse(final_action: str, risk_classification: str, reason_codes: list, policy_version: int, processing_duration_ms: float)`
  - `GET /api/v1/policies`: List all authoritative policies
  - `PUT /api/v1/policies/{id}`: Update policy severity thresholds & create version snapshot
  - `GET /api/v1/review-queue`: Retrieve pending human escalation review cases
  - `POST /api/v1/review-queue/{case_id}/decide`: Authoritative human reviewer disposition
  - `GET /api/v1/audit-events`: Append-only audit trail
  - `GET /api/v1/health`: Policy engine and DB connectivity health check
- **Startup Command**:
  ```powershell
  alembic upgrade head
  python -m uvicorn promptshield.main:app --host 0.0.0.0 --port 8001
  ```
- **Known Limitations**:
  - Database schema changes require Alembic migration scripts.
  - Unauthenticated policy mutation is blocked (requires JWT token with `admin` role).

---

### Module 3: Laptop 1 — Frontend UI (`frontend/`)
- **Owner / Directory**: UI / UX Engineering (`frontend/`)
- **Primary Entry Point**: `frontend/index.html` (Vanilla JS, CSS, Semantic HTML)
- **Runtime Access**:
  - Direct reverse proxy or static server on port `3000` / `8080`, or embedded mount on backend port `8000`
- **Key Interconnections**:
  - Calls `http://localhost:8000/api/v1/scan` for live detection and visualization.
  - Calls `http://localhost:8000/api/v1/benchmark/run` for on-demand evaluation.
  - Calls `http://localhost:8001/api/v1/policies` for policy studio and version inspection.
  - Calls `http://localhost:8001/api/v1/review-queue` for human-in-the-loop escalation review.
  - Calls `http://localhost:8001/api/v1/audit-events` for tamper-evident audit logs.
- **Startup Command**:
  - Served directly by FastAPI on `http://localhost:8000/` or via Nginx container.

---

### Module 4: Laptop 4 — Testing, Evaluation & DevSecOps (`tests/`, `data/`, `scripts/`)
- **Owner**: Senior QA Automation, Cybersecurity & Integration Lead
- **Artifacts**:
  - Version-controlled labelled evaluation dataset (`data/labelled_benchmark_dataset_v1.json`)
  - Dataset documentation (`data/DATASET_DOCUMENTATION.md`)
  - Automated unit and integration test suites (`tests/`)
  - Security regression invariants test suite (`tests/test_security_regression.py`)
  - Benchmark evaluation reporter (`scripts/evaluate_promptshield.py`)
  - Multi-container Docker deployment (`docker-compose.yml`, `Dockerfile.*`)
  - Live 5-minute demonstration script (`DEMO_SCRIPT.md`)
  - Known issues registry (`KNOWN_ISSUES.md`)

---

## 3. Integration Verification Matrix

| Checklist Item | Description | Target Subsystems | Status |
| :--- | :--- | :--- | :--- |
| **INT-01** | API schema compatibility between Detection Client and Policy Engine | Backend & Policy DB | **VERIFIED** |
| **INT-02** | Fail-Secure fallback when Laptop 3 policy service is offline | Detection Service | **VERIFIED** |
| **INT-03** | Sanitized content revalidation before LLM forwarding | Detection Engine & LLM | **VERIFIED** |
| **INT-04** | Blocked / Escalated content never forwarded to LLM adapter | LLM Adapter & Gates | **VERIFIED** |
| **INT-05** | Human Review Queue creation on `ESCALATE` decision | Policy DB & Review Queue | **VERIFIED** |
| **INT-06** | Append-only Audit Event creation on all operational scans | Policy DB & Audit Trail | **VERIFIED** |
| **INT-07** | Zero raw secret exposure in logs, responses, and records | Secret Scanner & DB | **VERIFIED** |
| **INT-08** | Policy immutability against untrusted input and prompt injection | Policy Service & DB | **VERIFIED** |
| **INT-09** | Role-based access control protecting policy and review actions | Security & JWT | **VERIFIED** |
| **INT-10** | End-to-end multi-container deployment via Docker Compose | DevSecOps & Infra | **VERIFIED** |
