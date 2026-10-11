# PromptShield Architecture & Security Specification
**VORTEXA 3.0 | Track C-03 (Cybersecurity & Digital Trust)**

---

## 1. System Architecture

```
                                      +--------------------------+
                                      | Laptop 1: Frontend UI    |
                                      +-------------+------------+
                                                    | (REST / JWT)
                                                    v
+-----------------------------+       +------------------------------------+
| Laptop 2: Detection Engine  | ----> | Laptop 3: Policy & DB Layer (This) |
| (Prompt & Exfil Detectors)  |       | - Deterministic Precedence Engine  |
+-----------------------------+       | - PostgreSQL / SQLAlchemy ORM      |
                                      | - Append-only Audit & Review Queue |
                                      +-----------------+------------------+
                                                        ^
                                                        | (Evaluation Runs)
                                      +-----------------+------------------+
                                      | Laptop 4: Testing & Evaluation     |
                                      +------------------------------------+
```

---

## 2. Relational Data Models & Constraints

### 2.1 Entity Relationship Diagram
```
  +------------------+       1:N       +---------------------+
  |      users       | <-------------- |  security_policies  |
  +------------------+                 +---------------------+
       |        |                               |        |
   1:N |    1:N |                           1:N |    1:N |
       |        |                               |        |
       v        v                               v        v
  +---------+ +-------------+            +----------+ +--------------+
  | reviews | | audit_events|            | versions | | scan_records |
  +---------+ +-------------+            +----------+ +--------------+
                                                              | 1:1
                                                              v
                                                         +---------+
                                                         | reviews |
                                                         +---------+
```

### 2.2 Table Specifications

| Table | Primary Key | Key Indexes & Constraints | Purpose |
| :--- | :--- | :--- | :--- |
| `users` | `id` (UUID) | Unique(`username`), Unique(`email`), Index(`role`) | Authentication and Role-Based Access Control |
| `security_policies` | `id` (UUID) | Unique(`name`), Index(`is_enabled`) | Authoritative security policies and rule configs |
| `policy_versions` | `id` (UUID) | Unique(`policy_id`, `version_number`), Index(`policy_id`) | Immutable historical snapshots of policy configs |
| `scan_records` | `id` (UUID) | Index(`correlation_id`), Index(`final_action`), Index(`source_type`), Index(`created_at`) | Persisted operational scan records and decisions |
| `review_cases` | `id` (UUID) | Unique(`scan_id`), Index(`status`), Index(`severity`), Index(`created_at`) | Human-in-the-loop escalation cases |
| `audit_events` | `id` (UUID) | Index(`created_at`, `actor_id`), Index(`event_type`), Index(`correlation_id`) | Append-only, tamper-evident audit records |
| `evaluation_runs` | `id` (UUID) | Index(`dataset_name`), Index(`execution_status`), Index(`created_at`) | Benchmark accuracy and confusion matrix records |

---

## 3. Transaction Boundaries & ACID Guarantees

PromptShield enforces strict transaction boundaries on critical state changes:

1. **Policy Creation & Version Snapshots**:
   - Creating or updating a policy is wrapped in a single database transaction.
   - Incrementing `current_version`, creating the `PolicyVersion` snapshot row, and writing the `POLICY_CREATED` / `POLICY_UPDATED` audit record all succeed together or fail together.

2. **Enforce & Review Queue Escalation**:
   - When `PolicyEngine.evaluate` returns `ESCALATE`, the creation of `ScanRecord`, `ReviewCase`, and `AuditEvent` occurs inside a single atomic commit.
   - If an error occurs during review queue generation, the entire scan is rolled back and no corrupted orphaned records are retained.

3. **Human Review Decision Resolution**:
   - Resolving a review case updates `ReviewCase.status = 'RESOLVED'`, sets `ReviewCase.resolved_at`, updates `ScanRecord.final_action`, appends to `ScanRecord.reason_codes`, and records `AuditEvent(event_type='REVIEW_DECIDED')`.
   - All 4 updates execute inside an ACID transaction.

---

## 4. Security & Data Protection Guarantees

1. **Untrusted Configuration Segregation**:
   - Content parsed from scanned prompts, tool outputs, or retrieved documents is strictly treated as passive evaluation data.
   - It is never parsed as policy configuration or SQL commands. Parameterized queries via SQLAlchemy ORM protect against SQL injection.

2. **Zero Raw Secret Persistence**:
   - Prompts may contain sensitive API tokens, AWS keys, passwords, or bearer tokens.
   - Before writing to `ScanRecord.redacted_content_ref` or `AuditEvent.safe_metadata`, all payloads undergo regex-based secret masking replacing secrets with `[REDACTED_AWS_KEY]`, `[REDACTED_SECRET]`, or `[REDACTED_SENSITIVE_FIELD]`.

3. **Fail-Secure Architecture**:
   - In the event of a missing policy, disabled policy, or unexpected exception in the evaluation pipeline, PromptShield defaults to `BLOCK` rather than silently allowing unverified traffic.
