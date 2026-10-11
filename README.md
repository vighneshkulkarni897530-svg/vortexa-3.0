# PromptShield — Policy Management & Data Persistence Layer
**VORTEXA 3.0 (C-03) Cybersecurity & Digital Trust Track**

PromptShield is a high-assurance defensive middleware layer designed to protect Large Language Model (LLM) applications against prompt injection (direct and indirect) and unauthorized data exfiltration.

This repository hosts the **authoritative policy management, persistence, and evaluation enforcement layer (Laptop 3)**.

---

## 1. System Overview & Division of Responsibilities

PromptShield is engineered as a decoupled, multi-laptop defense system:

| Role / Laptop | Domain | Contract with Policy & DB Layer |
| :--- | :--- | :--- |
| **Laptop 3 (This Service)** | **Policy & Database Layer** | Owns PostgreSQL schema, SQLAlchemy models, Alembic migrations, JWT/RBAC auth, the deterministic Policy Engine (`BLOCK` > `ESCALATE` > `SANITIZE` > `ALLOW`), Human Review Queue, and append-only audit persistence. |
| **Laptop 2** | **Detection Logic** | Submits detector findings and source metadata to `POST /api/v1/enforce`. Consumes the authoritative decision, policy version, and reason codes. |
| **Laptop 1** | **Frontend UI** | Interacts with Policy Administration (`/api/v1/policies`), Human Review Queue (`/api/v1/review-queue`), Audit Trail (`/api/v1/audit-events`), and Analytics Dashboards. |
| **Laptop 4** | **Testing & Evaluation** | Executes benchmarking suites and submits test dataset metrics to `POST /api/v1/evaluations` to track confusion matrices without metric fabrication. |

---

## 2. Technology Stack

- **Framework**: Python 3.14 / FastAPI
- **Database**: PostgreSQL (with SQLite compatibility for isolated test suites)
- **ORM & Migrations**: SQLAlchemy 2.0 (Mapped Columns) & Alembic
- **Validation**: Pydantic v2 & Pydantic-Settings
- **Security & Cryptography**: PBKDF2-HMAC-SHA256 (310,000 iterations), PyJWT (HS256), Regex Secret Redaction
- **Testing**: pytest, pytest-cov, pytest-asyncio, HTTPX

---

## 3. Database Architecture & Models

1. **`users`**: RBAC identities (`admin`, `reviewer`, `auditor`, `user`, `service`) with PBKDF2 hashed credentials.
2. **`security_policies`**: Master policy configuration including enabled status, source applicability, rule configurations, severity thresholds, default action, and current version.
3. **`policy_versions`**: Immutable audit history of configuration snapshots. Policy updates strictly append new versions rather than silently overwriting history.
4. **`scan_records`**: Operational scan records containing correlation ID, source type, detector findings, final action, risk classification, reason codes, processing duration, and redacted evidence. Raw secrets and complete prompts are never stored.
5. **`review_cases`**: Human-in-the-loop review queue for escalated findings. Stores assignment, review status, reviewer decision (`ALLOW`, `BLOCK`, `SANITIZE`), and mandatory justification.
6. **`audit_events`**: Append-only, tamper-evident audit trail capturing actors, resources, actions, outcomes, and redacted metadata. Ordinary users cannot modify or delete audit events.
7. **`evaluation_runs`**: Persists benchmark runs with sample counts and confusion matrix counts (TP, FP, TN, FN), deterministically computing precision, recall, false-positive rate, and false-negative rate.

---

## 4. Trusted Policy Engine

### Deterministic Precedence Hierarchy
When conflicting detection rules trigger on a single scan payload, deterministic precedence rules guarantee non-bypassable security:

$$\mathbf{BLOCK} \succ \mathbf{ESCALATE} \succ \mathbf{SANITIZE} \succ \mathbf{ALLOW}$$

1. **`BLOCK` (Highest Precedence - 40)**: Confirmed critical/high-severity threats (e.g., data exfiltration, direct instruction override). A generic allow rule will **never** override a high-severity block rule.
2. **`ESCALATE` (Precedence - 30)**: Medium-to-high uncertainty or indirect injection found in untrusted sources (`RETRIEVED_DOC`, `TOOL_OUTPUT`). Held in the human review queue.
3. **`SANITIZE` (Precedence - 20)**: Offending span surgical excision. If sanitization leaves empty or unsafe output, the engine automatically escalates to `BLOCK`.
4. **`ALLOW` (Lowest Precedence - 10)**: Baseline default applied only when no higher-priority security rule is triggered.

### Fail-Secure Guarantees
- If a security policy is disabled, missing, or unparseable, the engine defaults to **`BLOCK`** with `POLICY_MISSING_OR_DISABLED_FAIL_SECURE_TRIGGERED`.
- Untrusted content (user prompts, retrieved docs, tool outputs) is treated strictly as **data to inspect**, never instructions capable of altering policy rules.

---

## 5. API Endpoints

### Health & System
- `GET /api/v1/health`: Service status and database connectivity check.

### Authentication & RBAC
- `POST /api/v1/auth/register`: Register user with role (`admin`, `reviewer`, `auditor`, `user`, `service`).
- `POST /api/v1/auth/token`: Authenticate and receive JWT access token.
- `GET /api/v1/auth/me`: Inspect authenticated user claims.

### Security Policies (Laptop 1 UI $\leftrightarrow$ Laptop 3)
- `GET /api/v1/policies`: List policies (filters: `is_enabled`, `source_type`).
- `GET /api/v1/policies/{id}`: Detailed policy configuration.
- `POST /api/v1/policies`: Create policy and initialize Version 1 snapshot (*Admin only*).
- `PUT /api/v1/policies/{id}`: Update policy, creating new immutable Version snapshot (*Admin only*).
- `GET /api/v1/policies/{id}/versions`: View immutable version history (*Admin/Auditor*).

### Enforcement Contract (Laptop 2 Detection $\leftrightarrow$ Laptop 3)
- `POST /api/v1/enforce`: Evaluates detection findings against trusted policy, persists scan records, auto-escalates to review queue when warranted, and returns authoritative action (`ALLOW`, `BLOCK`, `SANITIZE`, `ESCALATE`).

### Human Review Queue (Laptop 1 Reviewer UI $\leftrightarrow$ Laptop 3)
- `GET /api/v1/review-queue`: List review cases (filters: `status`, `severity`).
- `GET /api/v1/review-queue/{id}`: Retrieve case details and redacted evidence.
- `POST /api/v1/review-queue/{id}/assign`: Assign reviewer to case.
- `POST /api/v1/review-queue/{id}/decision`: Record final human verdict (`ALLOW`, `BLOCK`, `SANITIZE`) with mandatory justification. Transactionally resolves case and updates scan record.

### Audit Events & Compliance
- `GET /api/v1/audit-events`: Query append-only audit trail (filters: `actor_id`, `event_type`, `outcome`, `correlation_id`).

### Evaluation Benchmarking (Laptop 4 $\leftrightarrow$ Laptop 3)
- `POST /api/v1/evaluations`: Submit benchmark dataset confusion matrix and record calculated metrics.
- `GET /api/v1/evaluations`: List historical evaluation runs.
- `GET /api/v1/evaluations/{id}`: View run details.

---

## 6. Setup and Running

### 1. Environment Setup
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
To configure PostgreSQL:
```ini
DATABASE_URL="postgresql+psycopg://promptshield_user:password@localhost:5432/promptshield_db"
```
Or for local development / SQLite fallback:
```ini
DATABASE_URL="sqlite:///./promptshield.db"
```

### 3. Database Migrations
Run Alembic migrations:
```bash
alembic upgrade head
```

To rollback a migration:
```bash
alembic downgrade -1
```

### 4. Running the API Server
```bash
uvicorn promptshield.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive OpenAPI documentation is available at:
`http://localhost:8000/docs`

---

## 7. Automated Testing Results

The automated test suite covers all required security boundaries, migrations, RBAC rules, fail-secure fallbacks, and transactional integrity guarantees:

```bash
pytest -v --cov=promptshield --cov-report=term-missing
```

### Test Results Summary:
- **Total Tests**: 29 passed, 0 failed (100% pass rate)
- **Code Coverage**: 91%
- **Tested Capabilities**:
  - Alembic forward and backward migrations
  - Policy creation and immutable versioning snapshots
  - Conflicting rule resolution (`BLOCK` $\succ$ `ESCALATE` $\succ$ `SANITIZE` $\succ$ `ALLOW`)
  - Untrusted source escalation for retrieved documents and tool outputs
  - Surgical span excision and verification
  - Fail-secure defaults on missing/inactive policy
  - Role-based access control (Admin, Reviewer, Auditor, Ordinary User)
  - Review case assignment, decision justification, and transactional updates
  - Append-only audit logging and secret redaction
  - Deterministic evaluation metric calculations and validation against fabrication
  - SQL injection and adversarial prompt injection resilience
