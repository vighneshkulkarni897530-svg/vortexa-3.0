# PromptShield — Enterprise LLM Defense & Policy Enforcement System
**VORTEXA 3.0 (Problem Statement C-03) Cybersecurity & Digital Trust Track**

PromptShield is an enterprise-grade, high-assurance defensive middleware platform designed to protect Large Language Model (LLM) applications against prompt injection (direct and indirect), canary token leakage, and unauthorized data exfiltration.

Branch: `feature/testing-deployment`

---

## 1. System Overview & Integrated Multi-Laptop Architecture

PromptShield is engineered as a unified, decoupled defense ecosystem integrating all four team modules:

| Role / Module | Directory / Service | Port | Responsibilities & Integration Contracts |
| :--- | :--- | :--- | :--- |
| **Laptop 1: Frontend Dashboard** | `frontend/`, `Froentend/` | `3000` / `8000` | Real-time Operations Center: Interactive Screening Workbench, Pipeline Visualizer, Policy Studio, Human Review Queue, Audit Trail, and Live Benchmark Evaluation. |
| **Laptop 2: Detection Engine** | `backend/` | `8000` | 7-stage deterministic security pipeline: Input validation (>1MB rejection), NFKC normalization, multi-signal rule matching, canary scanner, calibrated risk scoring (0.00–1.00), surgical sanitization, and fail-secure handoff to Policy service. |
| **Laptop 3: Policy & Database** | `promptshield/`, `alembic/` | `8001` | Authoritative persistence layer: PostgreSQL 16 schema, Alembic migrations, JWT/RBAC auth (`admin`, `reviewer`, `auditor`), deterministic policy hierarchy (`BLOCK` $\succ$ `ESCALATE` $\succ$ `SANITIZE` $\succ$ `ALLOW`), Review Queue, and tamper-evident audit log. |
| **Laptop 4: Testing & DevSecOps** | `tests/`, `scripts/`, `data/` | N/A | 122 automated tests (Unit, Backend Integration, Security Regression Invariants, Frontend Integration), 60-sample labelled benchmark dataset, and confusion matrix generator. |

---

## 2. Measured Evaluation Benchmark Results

Evaluated directly against the active PromptShield pipeline using 60 curated, version-controlled samples (`data/labelled_benchmark_dataset_v1.json`):

| Metric | Measured Value | Standard Formula & Notes |
| :--- | :--- | :--- |
| **Dataset Size** | **60 Samples** | 40 Malicious, 12 Legitimate, 8 Ambiguous |
| **True Positives (TP)** | **39** | Malicious attacks correctly intercepted (`BLOCK` or `SANITIZE`) |
| **False Positives (FP)** | **0** | Legitimate queries mistakenly intercepted (**0% FPR**) |
| **True Negatives (TN)** | **12** | Legitimate queries correctly permitted (`ALLOW`) |
| **False Negatives (FN)** | **1** | Malicious attack missed (Disclosed: `OBF-008` Unicode BiDi) |
| **Precision** | **100.00%** | $\text{TP} / (\text{TP} + \text{FP}) = 39 / (39 + 0)$ |
| **Recall** | **97.50%** | $\text{TP} / (\text{TP} + \text{FN}) = 39 / (39 + 1)$ |
| **False Positive Rate** | **0.00%** | $\text{FP} / (\text{FP} + \text{TN}) = 0 / (0 + 12)$ |
| **False Negative Rate** | **2.50%** | $\text{FN} / (\text{FN} + \text{TP}) = 1 / (1 + 39)$ |
| **Binary Classification Accuracy** | **98.08%** | $(\text{TP} + \text{TN}) / (\text{TP} + \text{TN} + \text{FP} + \text{FN}) = 51 / 52$ |
| **Average Scan Latency** | **1.09 ms** | Min: 0.16 ms, Median: 0.81 ms, Max: 7.74 ms |

### 4-Action Disposition Distribution
- **`BLOCK`**: 28 samples (46.7%) — Direct injections, destructive commands, active canary exfiltration.
- **`SANITIZE`**: 11 samples (18.3%) — Indirect injections in passive documents/webpages where benign text was preserved.
- **`ESCALATE`**: 6 samples (10.0%) — Ambiguous technical directives routed to human review queue.
- **`ALLOW`**: 15 samples (25.0%) — Benign user requests, technical discussions, and 1 missed attack.

*Full details and per-category breakdowns available in [EVALUATION_REPORT.md](file:///d:/Vortexa%203.0/EVALUATION_REPORT.md).*

---

## 3. Quick Start & Setup (Windows PowerShell)

### Step 1: Clone Repository & Switch Branch
```powershell
git checkout feature/testing-deployment
```

### Step 2: Create & Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3: Install Required Dependencies
```powershell
pip install -r requirements.txt
```

### Step 4: Configure Environment File
```powershell
Copy-Item .env.example .env
```
*(Verify `.env` has placeholder test tokens only; never commit credentials).*

### Step 5: Initialize Database & Apply Migrations
```powershell
# Applies all Alembic database schema migrations
alembic upgrade head
```

---

## 4. Running Application Services (Windows PowerShell)

PromptShield can be launched locally in two terminal windows:

### Terminal 1: Detection Engine & Integrated Web UI (Laptop 2 & 1)
```powershell
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
- **Web Dashboard**: [http://localhost:8000/](http://localhost:8000/)
- **Swagger API Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Health Check**: [http://localhost:8000/health](http://localhost:8000/health)

### Terminal 2: Policy & Database Engine (Laptop 3)
```powershell
python -m uvicorn promptshield.main:app --host 0.0.0.0 --port 8001 --reload
```
- **Swagger API Docs**: [http://localhost:8001/docs](http://localhost:8001/docs)
- **Health Check**: [http://localhost:8001/api/v1/health](http://localhost:8001/api/v1/health)

---

## 5. Automated Verification & Testing Commands

Execute all 122 automated tests via `pytest`:

```powershell
# 1. Run all 122 automated unit, integration, and regression tests
pytest -v

# 2. Run Backend Integration Test Suite (16 tests)
pytest tests/test_backend_integration.py -v

# 3. Run Security Regression Invariant Suite (10 tests)
pytest tests/test_security_regression.py -v

# 4. Run Frontend Integration Test Suite (10 tests)
pytest tests/test_frontend_integration.py -v

# 5. Run Live 60-Sample Evaluation Benchmark Script
python scripts/evaluate_promptshield.py
```

### Verified Security Invariants (10 Passed)
1. **Invariant 1**: Blocked content never reaches the LLM adapter.
2. **Invariant 2**: Escalated content never reaches the LLM before authorized resolution.
3. **Invariant 3**: Sanitized content is revalidated before forwarding.
4. **Invariant 4**: Untrusted documents and tool outputs cannot modify policies.
5. **Invariant 5**: Tool calls require explicit server authorization.
6. **Invariant 6**: Unauthorized destinations and SSRF attempts are rejected.
7. **Invariant 7**: Secrets and canary tokens are redacted from logs and responses.
8. **Invariant 8**: Unauthorized users cannot access protected review or policy functions.
9. **Invariant 9**: Malformed and encoded inputs cannot bypass validation.
10. **Invariant 10**: Policy service network failure fails secure (`BLOCK`).

---

## 6. Docker Compose Deployment

To deploy the entire multi-container stack (Frontend Nginx, FastAPI Detection, FastAPI Policy, PostgreSQL 16, and Alembic migrations):

```powershell
# 1. Start all containers in detached mode
docker compose up -d --build

# 2. Check running container health status
docker compose ps

# 3. View logs
docker compose logs -f

# 4. Run automated test runner inside container network
docker compose --profile test run --rm test-runner

# 5. Graceful shutdown
docker compose down
```

See [DEPLOYMENT.md](file:///d:/Vortexa%203.0/DEPLOYMENT.md) for full container topology and multi-server instructions.

---

## 7. Deliverables & Documentation Index

- [ARCHITECTURE.md](file:///d:/Vortexa%203.0/ARCHITECTURE.md) — Complete multi-layer architecture specification with Mermaid system and ERD diagrams.
- [DEMO_SCRIPT.md](file:///d:/Vortexa%203.0/DEMO_SCRIPT.md) — 5-minute live demonstration script for SIH judges covering all 8 core scenarios.
- [EVALUATION_REPORT.md](file:///d:/Vortexa%203.0/EVALUATION_REPORT.md) — Verified benchmark evaluation report with 4-action confusion matrix and latency statistics.
- [LIMITATIONS_AND_FUTURE_SCOPE.md](file:///d:/Vortexa%203.0/LIMITATIONS_AND_FUTURE_SCOPE.md) — Technical boundaries, defense-in-depth principles, and multi-phase roadmap.
- [INTEGRATION_CHECKLIST.md](file:///d:/Vortexa%203.0/INTEGRATION_CHECKLIST.md) — 10-step integration protocol and cross-service schema contracts.
- [DEPLOYMENT.md](file:///d:/Vortexa%203.0/DEPLOYMENT.md) — Docker Compose, standalone microservice setup, CORS, and TLS configurations.
- [KNOWN_ISSUES.md](file:///d:/Vortexa%203.0/KNOWN_ISSUES.md) — Technical RCA of edge cases and security resolution log.
- [data/DATASET_DOCUMENTATION.md](file:///d:/Vortexa%203.0/data/DATASET_DOCUMENTATION.md) — Benchmark dataset schema, labeling criteria, and category counts.
- [data/labelled_benchmark_dataset_v1.json](file:///d:/Vortexa%203.0/data/labelled_benchmark_dataset_v1.json) — 60 curated evaluation samples.
