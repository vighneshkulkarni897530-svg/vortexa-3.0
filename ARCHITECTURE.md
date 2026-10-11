# PromptShield Architecture & Technical Specification
**Domain**: Cybersecurity & Digital Trust (SIH Track C-03)  
**System**: PromptShield Enterprise AI Defense Middleware  
**Version**: 1.3.0  

---

## 1. System Overview & Component Topology

PromptShield is architected as a high-assurance, decoupled defensive middleware layer positioned between untrusted external data sources and downstream Large Language Model (LLM) execution environments.

```mermaid
graph TD
    subgraph "Untrusted Content Ingestion Layer"
        UP["User Prompts (Direct)"]
        UD["Uploaded Documents (.pdf, .docx, .txt)"]
        RW["Retrieved Webpages (Passive Carrier)"]
        TO["Simulated Tool Outputs (Data Channel)"]
    end

    subgraph "PromptShield Gateway & Detection Engine (Port 8000)"
        Val["Stage 1: Input Validation & Size Enforcer (Max 1MB)"]
        Norm["Stage 2: Safe Normalizer (NFKC, Homoglyphs, BiDi Un-reversal, Base64/Hex)"]
        Src["Stage 3: Source Authority & Context Classifier"]
        Rules["Stage 4: Multi-Signal Injection Rules (Direct, Indirect, Delimiter)"]
        Canary["Stage 5: Canary Token & Data Exfiltration Scanner"]
        Risk["Stage 6: Calibrated Risk Composite Index (0.00 - 1.00)"]
        Sanit["Stage 7: Surgical Content Sanitizer (Revalidation Invariant)"]
    end

    subgraph "PromptShield Policy Authority & Persistence (Port 8001)"
        PolEng["Deterministic Policy Engine (BLOCK > ESCALATE > SANITIZE > ALLOW)"]
        DB[("Relational Database: SQLite / PostgreSQL")]
        Audit["Tamper-Evident Audit Event Logger"]
        ReviewQ["Human-in-the-Loop Review Queue"]
    end

    subgraph "Downstream Execution Layer"
        LLM["Guarded LLM Gateway (Simulated / Production)"]
        OutGuard["PromptShield Output Guard (Canary Leak Defense)"]
        Client["Safe AI Response Delivered"]
    end

    UP --> Val
    UD --> Val
    RW --> Val
    TO --> Val

    Val --> Norm
    Norm --> Src
    Src --> Rules
    Src --> Canary
    Rules --> Risk
    Canary --> Risk
    Risk --> Sanit

    Sanit -->|Screening Proof & Findings| PolEng
    PolEng <--> DB
    PolEng --> Audit
    PolEng -->|Action: ESCALATE| ReviewQ

    PolEng -->|Action: BLOCK| Drop["Immediate Discard (Zero LLM Tokens)"]
    PolEng -->|Action: SANITIZE / ALLOW| LLM
    LLM --> OutGuard
    OutGuard --> Client
```

---

## 2. Relational Database Entity-Relationship Diagram (ERD)

PromptShield models users, security policies, immutable version snapshots, scan telemetry, review cases, evaluation runs, and audit logs with strict foreign key integrity and performance indexes.

```mermaid
erDiagram
    users ||--o{ security_policies : "creates / updates"
    users ||--o{ audit_events : "acts as actor"
    users ||--o{ review_cases : "reviews / resolves"

    security_policies ||--|{ policy_versions : "versions"
    security_policies ||--o{ scan_records : "enforced on"

    scan_records ||--o| review_cases : "escalates to"
    scan_records ||--o{ audit_events : "generates"

    evaluation_runs ||--|{ evaluation_case_results : "evaluates"

    users {
        uuid id PK
        string username UK
        string email UK
        string password_hash
        string role "admin | reviewer | auditor"
        boolean is_active
        datetime created_at
    }

    security_policies {
        uuid id PK
        string name UK
        string description
        string default_action "ALLOW | BLOCK | SANITIZE | ESCALATE"
        int current_version
        boolean is_enabled
        uuid created_by FK
        datetime updated_at
    }

    policy_versions {
        uuid id PK
        uuid policy_id FK
        int version_number
        json configuration_snapshot
        string change_summary
        uuid changed_by FK
        datetime created_at
    }

    scan_records {
        uuid id PK
        string correlation_id
        string source_type "user_prompt | uploaded_document | retrieved_webpage | tool_output"
        float risk_score
        string risk_classification "SAFE | LOW | MEDIUM | HIGH | CRITICAL"
        string recommended_action
        string final_action "ALLOW | BLOCK | SANITIZE | ESCALATE"
        string decision_reason
        string policy_version
        int findings_count
        float processing_duration_ms
        datetime created_at
    }

    review_cases {
        uuid id PK
        uuid scan_id FK
        string status "PENDING | IN_REVIEW | RESOLVED | REJECTED"
        string severity "LOW | MEDIUM | HIGH | CRITICAL"
        string escalation_reason
        string resolution_action
        string analyst_notes
        uuid resolved_by FK
        datetime resolved_at
        datetime created_at
    }

    audit_events {
        uuid id PK
        string event_type "POLICY_CREATED | SCAN_EXECUTED | REVIEW_RESOLVED"
        string actor_username
        uuid actor_id FK
        string target_resource
        string action
        string outcome "SUCCESS | DENIED | ERROR"
        json safe_metadata
        datetime created_at
    }

    evaluation_runs {
        uuid id PK
        string dataset_name
        string dataset_version
        int sample_count
        int true_positives
        int false_positives
        int true_negatives
        int false_negatives
        float accuracy
        float precision
        float recall
        float duration_ms
        string execution_status
        datetime created_at
    }

    evaluation_case_results {
        uuid id PK
        uuid run_id FK
        string sample_id
        string expected_label "MALICIOUS | LEGITIMATE | AMBIGUOUS"
        string expected_action
        string actual_decision
        boolean is_correct
        float processing_ms
        datetime created_at
    }
```

---

## 3. The 6-Layer Security Detection Architecture

### Layer 1: Input Validation and Source Classification
- **Size Bounds**: Strict rejection of payloads $>1\,\text{MB}$ ($1,048,576$ bytes) before any parsing or memory allocation to mitigate DoS/memory exhaustion.
- **Source Classification**: Explicit classification into four distinct trust boundaries:
  1. `user_prompt` (Conversational prompt typed by user; direct threat vector).
  2. `uploaded_document` (Passive data carrier; sanitized when safe).
  3. `retrieved_webpage` (External web retrieval; high-vigilance indirect injection).
  4. `tool_output` (Simulated external tool or DB output; data only, never executive commands).
- **Untrusted Metadata Barrier**: Client-supplied metadata is sanitized. Provenance metadata is strictly stamped server-side.

### Layer 2: Safe Normalization Pipeline
- **Unicode NFKC**: Canonical compatibility decomposition and composition to defeat unicode evasion.
- **Homoglyph Folding**: Deterministic folding of Cyrillic, Greek, and fullwidth lookalikes into Latin ASCII equivalents.
- **BiDi Directional Override Defense**: Un-reversal of text spans enclosed by Unicode Right-to-Left Override (`\u202E` RLO) and Pop Directional Formatting (`\u202C` PDF).
- **Zero-Width Stripping**: Removal of zero-width spaces, joiners, and byte-order marks (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`).
- **Bounded Auxiliary Channels**: Safe decoding of Base64 and Hex payloads without code execution, capped at 3 recursion passes.

### Layer 3: Context-Aware Detection
- **Multi-Signal Rules**: High-precision regex engines with negative lookahead for academic/benign context (e.g. SQL injection tutorials, firewall rule updates).
- **Delimiter Injection**: Detection of forged model boundaries (ChatML `<|im_start|>system`, Llama `[INST]`, Alpaca `### Instruction:`).
- **Canary Scanner**: Flexible regex matching detecting synthetic test secrets (`CANARY_VORTEXA_SEC_7749`, `SYNTHETIC_API_KEY_123`, AWS/GitHub keys) across case variations, arbitrary spacing, leetspeak (`c4n4ry`), and ROT13.
- **Exfiltration Channels**: Detection of unauthorized external C2 addresses, SSRF link-local metadata endpoints (`169.254.169.254`), and markdown exfiltration channels (`![exfil](https://attacker.site/...)`).

### Layer 4: Deterministic Policy Engine
- **Precedence Hierarchy**:
  $$\mathbf{BLOCK} \succ \mathbf{ESCALATE} \succ \mathbf{SANITIZE} \succ \mathbf{ALLOW}$$
  An allow rule or benign signal can *never* override a confirmed critical threat.
- **Policy Immunity**: Untrusted content parsed from documents or prompts cannot modify server security policies. Policy edits require authenticated, role-authorized API calls.

### Layer 5: Surgical Sanitization & Revalidation Invariant
- **Span Excision**: Offending injection spans are cleanly removed from passive carriers, preserving unrelated business text.
- **Revalidation Invariant**: Sanitized output is passed back through Normalization and Rule matching before downstream delivery. If any threat signal persists, the action is automatically upgraded to `BLOCK`.

### Layer 6: Tamper-Evident Audit & Secret Redaction
- **Zero Raw Secrets**: Canary tokens, passwords, and API keys are redacted before persistence.
- **Append-Only Logging**: Every evaluation, policy snapshot, and analyst decision generates an immutable record in `audit_events`.
