# PromptShield Detection Engine (VORTEXA 3.0 — Problem C-03)

The **PromptShield Detection Engine** is an enterprise-grade LLM security subsystem designed to inspect untrusted content, detect prompt injection attacks, intercept sensitive data/canary token leakage, produce explainable structured findings, and enforce policy boundaries before content reaches language models.

---

## 1. System Architecture & Pipeline Stages

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

---

## 2. API Contract Specification

### `POST /api/v1/scan`
Inspects untrusted content and returns explainable security findings.

#### Request Schema:
```json
{
  "scan_id": "optional-custom-uuid-or-none",
  "content": "Can you summarize this quarterly financial review?",
  "source_type": "user_prompt",
  "trusted_metadata": null,
  "application_context": "finance-copilot",
  "tenant_context": "tenant-corp-01"
}
```

#### Response Schema:
```json
{
  "scan_id": "786a0767-17b1-4bb2-b5e8-11204ec10f03",
  "source_type": "user_prompt",
  "normalized_content_metadata": {
    "original_length": 51,
    "normalized_length": 51,
    "transformations_applied": [],
    "encodings_detected": [],
    "has_unicode_normalization": false,
    "has_homoglyphs": false,
    "has_collapsed_whitespace": false
  },
  "findings": [],
  "risk_classification": "SAFE",
  "risk_score": 0.0,
  "recommended_action": "ALLOW",
  "final_decision": "ALLOW",
  "decision_reason": "Policy rule POL-005: Content verified safe; within acceptable operational risk bounds.",
  "policy_version": "v1.2.0-local",
  "sanitized_content": "Can you summarize this quarterly financial review?",
  "processing_duration_ms": 0.42
}
```

---

## 3. Team Integration Guide

- **Laptop 3 (Persistent Policy Management & Database):**
  - Set `POLICY_SERVICE_URL=http://<laptop-3-ip>:<port>` in `.env`.
  - The Detection Engine dispatches evaluated findings and risk metrics to Laptop 3 at `/api/v1/policy/evaluate`.
  - If Laptop 3's service is unavailable or times out (>2s), the Detection Engine automatically falls back to its local trusted policy matrix (fail-secure; blocks CRITICAL/HIGH threats).
- **Laptop 1 (Frontend):**
  - Call `POST /api/v1/scan` before sending prompts or retrieved web content.
  - Display explainable findings (`rule_id`, `category`, `severity`, `safe_evidence_summary`) in the UI.
  - For full-stack execution demos, call `POST /api/v1/llm/generate` to trigger the combined detection and guarded response pipeline.
- **Laptop 4 (Evaluation & Integration):**
  - Use `tests/` and the evaluation dataset against `POST /api/v1/scan`.
  - Evaluate accuracy against benign security discussions, direct injections, indirect document injections, and canary token leakage attempts.

---

## 4. Documented Risk Score Interpretation

The numerical `risk_score` (ranging from `0.00` to `1.00`) is calculated deterministically:

$$\text{Risk Score} = \min\left(1.0, \max_{i}(\text{weight}_i \times \text{confidence}_i) + \sum_{i} 0.05 \times (\text{weight}_i \times \text{confidence}_i)\right)$$

| Score Range | Classification | Action | Documented Interpretation |
| :--- | :--- | :--- | :--- |
| **0.00 – 0.19** | `SAFE` | `ALLOW` | Content contains no detected threats or only benign, quoted educational references. |
| **0.20 – 0.44** | `LOW` | `ALLOW` | Low-severity anomalies or benign discussions mentioning security concepts. |
| **0.45 – 0.69** | `MEDIUM` | `SANITIZE` / `ESCALATE` | Suspected indirect injection or ambiguous directives in untrusted data. |
| **0.70 – 0.89** | `HIGH` | `BLOCK` / `SANITIZE` | Direct prompt injection attempt, jailbreak payload, or unauthorized tool request. |
| **0.90 – 1.00** | `CRITICAL` | `BLOCK` | Active canary secret extraction, exfiltration payload, or destructive tool execution. |

> **IMPORTANT:** The risk score is an explainable weighted threat severity index based on detector confidence and signal severity. It is **not** a statistical probability of attack.

---

## 5. Detection Limitations & Threat Model Boundaries

While PromptShield offers robust defense-in-depth, security practitioners and evaluators must recognize the following inherent limitations:

1. **Evolving Adversarial Obfuscation:**
   - Multi-stage mathematical, cryptographic, or cipher-based encodings (e.g., custom ciphers, uncommon steganography) outside standard Base64/Hex/URL decoding cannot be deterministically decoded without incurring computational Denial-of-Service risks.
2. **Novel Semantic Paraphrasing & Zero-Day Jailbreaks:**
   - Heuristic rules and pattern matchers detect known syntactic and structural indicators of injection. Heavily poetic, narrative-embedded, or multilingual multi-turn social engineering may bypass static syntactic rules if it avoids recognizable imperative override constructs.
3. **Multi-Turn Contextual Exploitation:**
   - PromptShield screens stateless individual interactions. Attacks that split an adversarial instruction across multiple conversational turns (token smuggling or incremental persona shifting) require conversational state tracking across sessions.
4. **Sanitization Constraints:**
   - Content sanitization is only performed when an isolated threat span can be identified with high confidence. When adversarial instructions are deeply interwoven with legitimate text, sanitization is deliberately aborted in favor of `BLOCK` or `ESCALATE` to prevent semantic alteration or incomplete excisions.
5. **No Universal Silver Bullet:**
   - A passing test suite confirms expected behavior for defined fixtures. It does not prove complete immunity against arbitrary, novel adversarial prompts.

---

## 6. Windows PowerShell Setup & Execution

### Prerequisites
- Python 3.11+ or 3.12 (installed at `C:\Users\BHAGYASHRI BHISE\AppData\Local\Programs\Python\Python312\python.exe`)

### Setup Virtual Environment
```powershell
# In d:\vortex 3.0:
& "C:\Users\BHAGYASHRI BHISE\AppData\Local\Programs\Python\Python312\python.exe" -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Run Automated Unit Test Suite
```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

### Start the PromptShield Detection Engine Service
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive API documentation will be available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- Health check: `http://localhost:8000/health`
