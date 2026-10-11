# PromptShield — Enterprise LLM Defense & Policy Enforcement System
**VORTEXA 3.0 (C-03) Cybersecurity & Digital Trust Track**

PromptShield is an enterprise-grade high-assurance defensive middleware platform designed to protect Large Language Model (LLM) applications against prompt injection (direct and indirect), canary token leakage, and unauthorized data exfiltration.

---

## 1. System Overview & Multi-Laptop Architecture

PromptShield is engineered as a decoupled, multi-laptop defense ecosystem:

| Role / Component | Domain / Directory | Responsibilities & Integration Contracts |
| :--- | :--- | :--- |
| **Laptop 2: Detection Logic** | `backend/` | Inspects untrusted inputs (`POST /api/v1/scan`), performs normalization, multi-signal injection detection, secret scanning, calibrated risk assessment (0.00–1.00), and guarded LLM execution. Submits detector findings to Laptop 3 at `POST /api/v1/enforce`. |
| **Laptop 3: Policy & Database** | `promptshield/` & `alembic/` | Authoritative persistence layer owning PostgreSQL schema, SQLAlchemy models, Alembic migrations, JWT/RBAC auth, deterministic Policy Engine (`BLOCK` $\succ$ `ESCALATE` $\succ$ `SANITIZE` $\succ$ `ALLOW`), Human Review Queue, and append-only audit persistence. |
| **Laptop 1: Frontend UI** | Frontend Clients | Interacts with Policy Administration (`/api/v1/policies`), Human Review Queue (`/api/v1/review-queue`), Audit Trail (`/api/v1/audit-events`), and Real-Time Inspection Dashboards. |
| **Laptop 4: Testing & Evaluation** | `tests/` | Executes benchmarking suites and submits test dataset metrics to `POST /api/v1/evaluations` to track confusion matrices without metric fabrication. |

---

## 2. Detection Engine Architecture (`backend/`)

The detection engine implements a 7-stage deterministic security pipeline:

```
[Untrusted Input]
       │
       ▼
[Stage A: Validation] ──▶ Reject malformed/oversized payloads (>1MB), enforce UTF-8
       │
       ▼
[Stage B: Normalization] ──▶ Unicode NFKC, homoglyph folding, zero-width strip, bounded URL & Base64 decoding
       │
       ▼
[Stage C: Injection Detection] ──▶ Multi-signal detection (System overrides, jailbreaks, exfil, tool manipulation)
       │
       ▼
[Stage D: Secret Protection] ──▶ Canary token & sensitive pattern matching (redacted from outputs & logs)
       │
       ▼
[Stage E: Risk Assessment] ──▶ Calibrated risk index (0.00 - 1.00) & recommendation (ALLOW, SANITIZE, BLOCK, ESCALATE)
       │
       ▼
[Stage F: Sanitization] ──▶ Surgical excision of isolated malicious spans (preserves legitimate content)
       │
       ▼
[Stage G: Policy Handoff] ──▶ Handoff to trusted Policy Authority (Laptop 3) with fail-secure local fallback
       │
       ▼
[Authorized LLM Invocation] ──▶ LLM Adapter (screening proof required) + Output Guard (canary leakage check)
```

### Module Responsibilities:
- `backend/detection/normalization.py` — Bounded decoding, homoglyph confusable normalization, zero-width strip.
- `backend/detection/source_context.py` — Evaluates origin (`user_prompt`, `uploaded_document`, `retrieved_webpage`, `tool_output`) and assigns strict server-side authority levels.
- `backend/detection/rules.py` — Explainable multi-signal injection detection rules with benign discussion filters.
- `backend/detection/secret_scanner.py` — Canary token and credential detection with automatic non-disclosure masking.
- `backend/detection/risk_assessment.py` — Multi-signal risk aggregation and score computation.
- `backend/detection/sanitizer.py` — Precise span-based sanitization for passive documents and webpages.
- `backend/policy/client.py` — Coordination client for Laptop 3's persistent policy service.
- `backend/llm/adapter.py` — Provider-neutral execution gate preventing direct screening bypass.
- `backend/llm/output_guard.py` — Post-generation inspection blocking canary leaks in generated text.
- `backend/tools/security.py` — Server-side tool allowlists, argument validation, and SSRF prevention.

### Documented Risk Score Interpretation
$$\text{Risk Score} = \min\left(1.0, \max_{i}(\text{weight}_i \times \text{confidence}_i) + \sum_{i} 0.05 \times (\text{weight}_i \times \text{confidence}_i)\right)$$

| Score Range | Classification | Action | Documented Interpretation |
| :--- | :--- | :--- | :--- |
| **0.00 – 0.19** | `SAFE` | `ALLOW` | Content contains no detected threats or only benign, quoted educational references. |
| **0.20 – 0.44** | `LOW` | `ALLOW` | Low-severity anomalies or benign discussions mentioning security concepts. |
| **0.45 – 0.69** | `MEDIUM` | `SANITIZE` / `ESCALATE` | Suspected indirect injection or ambiguous directives in untrusted data. |
| **0.70 – 0.89** | `HIGH` | `BLOCK` / `SANITIZE` | Direct prompt injection attempt, jailbreak payload, or unauthorized tool request. |
| **0.90 – 1.00** | `CRITICAL` | `BLOCK` | Active canary secret extraction, exfiltration payload, or destructive tool execution. |

---

## 3. Policy Management & Database Layer (`promptshield/`)

### Database Models & Schema
1. **`users`**: RBAC identities (`admin`, `reviewer`, `auditor`, `user`, `service`) with PBKDF2-HMAC-SHA256 credentials.
2. **`security_policies`**: Master policy configuration including enabled status, source applicability, rule configurations, severity thresholds, default action, and current version.
3. **`policy_versions`**: Immutable audit history of configuration snapshots. Updates append new versions rather than overwriting history.
4. **`scan_records`**: Operational scan records containing correlation ID, source type, detector findings, final action, risk classification, reason codes, and redacted evidence.
5. **`review_cases`**: Human-in-the-loop review queue for escalated findings with mandatory reviewer justifications.
6. **`audit_events`**: Append-only, tamper-evident audit trail capturing actors, resources, actions, outcomes, and redacted metadata.
7. **`evaluation_runs`**: Persists benchmark runs with sample counts and confusion matrices (TP, FP, TN, FN), computing precision, recall, FPR, and FNR.

### Deterministic Precedence Hierarchy
When conflicting detection rules trigger on a single scan payload:
$$\mathbf{BLOCK} \succ \mathbf{ESCALATE} \succ \mathbf{SANITIZE} \succ \mathbf{ALLOW}$$

- **`BLOCK` (Precedence 40)**: Confirmed critical/high-severity threats. Never overridden by allow rules.
- **`ESCALATE` (Precedence 30)**: High uncertainty or indirect injection found in untrusted sources (`RETRIEVED_DOC`, `TOOL_OUTPUT`).
- **`SANITIZE` (Precedence 20)**: Surgical span excision. Escalates to `BLOCK` if empty/unsafe.
- **`ALLOW` (Precedence 10)**: Baseline default applied only when no higher-priority security rule is triggered.

---

## 4. Environment Setup & Installation

### 1. Create and Activate Virtual Environment
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 3. Configure Environment
Copy `.env.example` to `.env`:
```powershell
cp .env.example .env
```

---

## 5. Running the Application Services

### Running the Detection Engine (Laptop 2 Service)
```powershell
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
- Swagger UI: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

### Running the Policy & Database Engine (Laptop 3 Service)
```powershell
# Run database migrations
alembic upgrade head

# Run Policy & DB API server
python -m uvicorn promptshield.main:app --host 0.0.0.0 --port 8001 --reload
```
- Interactive API Docs: `http://localhost:8001/docs`
- Health check: `http://localhost:8001/api/v1/health`

---

## 6. Automated Testing

Run the full unified test suite across both subsystems:
```powershell
python -m pytest -v
```
