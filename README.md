# Ghost Data Still Exists - Deletion-Audit Engine

[![HackerRank Orchestrate](https://img.shields.io/badge/HackerRank-Orchestrate_October_2026-00EA64?style=flat&logo=hackerrank&logoColor=black)](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero External LLM Cost](https://img.shields.io/badge/LLM_Calls-0_($0.00)-brightgreen)](#execution-and-resource-profile)

A deterministic privacy-compliance and deletion-audit engine developed for the **HackerRank Orchestrate (October 2026)** hackathon challenge: *Ghost Data Still Exists*.

In complex enterprise and commerce architectures, deletion workflows frequently claim `COMPLETE` while personal data persists across read replicas, log streams, support attachments, database exports, search indices, analytics profiles, and backup snapshots. Furthermore, active data synchronizations and backup restoration jobs can silently re-propagate previously deleted records. This engine audits platform evidence at a strict cutoff timestamp (`audit_at`), reconstructs temporal identities, evaluates retention policies, and synthesizes provable findings alongside safe, ordered remediation and post-remediation verification plans.

---

## Competition Results

Official results achieved in the **HackerRank Orchestrate October 2026** competition:

| Metric | Result |
|---|---|
| **Final Standing** | **#1,921 / 4,090** |
| **Total Score** | **46.2 / 100** |
| Chat Transcript | 8.4 / 10 |
| Output CSV | 18.6 / 30 |
| AI Judge Interview | 17.4 / 30 |
| Code ZIP | 1.8 / 30 |

---

## Key Capabilities

1. **Multilingual Intent & Request Authorization**
   - Distinguishes authentic Right-to-Erasure (GDPR Art. 17 / CCPA) requests from informational status queries, access/export requests, marketing opt-outs, profile updates, and negated or cancelled requests.
   - Evaluates multi-language text contexts deterministically without external translation API dependencies.

2. **Temporal & Historical Identity Reconstruction**
   - Links initial contact identifiers (email, phone, username) to stable user IDs.
   - Unwinds sequential identity changes recorded in the audit log backwards from current snapshots to the exact request cutoff timestamp (`audit_at`).
   - Normalizes phone numbers, canonicalizes case-insensitive emails, and resolves SHA-256 email hashes while rejecting ambiguous or ungrounded identity matches.

3. **Timestamp-Bounded Multi-Format Evidence Parsing**
   - Ingests structured manifests and filters out any evidence captured after `audit_at`.
   - Parses multi-modal evidence across SQLite-compatible SQL database snapshots (primary, regional, and reporting replicas), structured JSON documents, log files, plain-text audit trails, PDFs, and image metadata.
   - Preserves provenance (`file_id`, `activity_id`, `audit_id`) and distinguishes operational errors from missing records.

4. **Policy Enforcement & Remediation Planning**
   - Enforces granular policy actions (`DELETE`, `REDACT`, `ANONYMIZE`, `RETAIN`, and `ACCOUNT_TOMBSTONE`) defined in `deletion_rules.csv`.
   - Distinguishes legally required account tombstones (where internal identifiers remain while direct PII like email, name, and phone must be redacted) from prohibited PII exposures.
   - Identifies active synchronization flows and restore risks that could resurrect deleted records.
   - Emits strictly ordered steps: `FINDING` -> `REMEDIATION` -> `VERIFICATION`, ensuring prerequisite flows and restore paths are disabled prior to downstream data cleanup.

5. **Deterministic CSV Generation & Validation**
   - Processes all 518 evaluation requests in memory with guaranteed natural numeric sequence ordering (`case_33` through `case_550`).
   - Validates JSON step payloads, phase constraints, operation validity, and evidence citation integrity before committing to disk via atomic file replacement.

---

## Architecture & Pipeline

The system is organized into a four-phase modular pipeline:

```text
                          deletion_requests.csv
                                    |
                                    v
+------------------------------------------------------------------------+
| Phase 1: Authorization & Identity (code/authorization.py, identity.py) |
| - Classify request text intent (DELETE vs. ACCESS/STATUS/OPT-OUT)      |
| - Reconstruct temporal subject identity at audit_at cutoff             |
+-----------------------------------+------------------------------------+
                                    |
                                    v
+------------------------------------------------------------------------+
| Phase 2: Evidence Foundation (code/evidence/parser.py)                 |
| - Parse evidence manifest bounded by audit_at capture time             |
| - Ingest SQL replicas, JSON exports, logs, text, and PDF artifacts     |
+-----------------------------------+------------------------------------+
                                    |
                                    v
+------------------------------------------------------------------------+
| Phase 3: State & Policy Planning (code/state.py, policy.py)            |
| - Correlate evidence observations to subject identifiers               |
| - Detect ghost records, active data flows, and restore risks           |
| - Generate ordered FINDING, REMEDIATION, and VERIFICATION steps        |
+-----------------------------------+------------------------------------+
                                    |
                                    v
+------------------------------------------------------------------------+
| Phase 4: Execution & Delivery (code/main.py, io_loader.py)             |
| - Execute batch pipeline across all requests in memory                 |
| - Enforce strict output schema and natural case ordering               |
| - Perform atomic write to root output.csv                              |
+------------------------------------------------------------------------+
```

---

## Repository Structure

```text
.
|-- .gitignore                          # Git exclusions for dataset, cache, and submission files
|-- README.md                           # Project documentation and competition overview
|-- output.csv                          # Generated deletion audit results (518 cases)
`-- code/
    |-- authorization.py                # Request intent classification and authorization logic
    |-- identity.py                     # Historical identity reconstruction and cutoff rollback
    |-- io_loader.py                    # Input CSV loading, schema validation, and CSV output writer
    |-- main.py                         # CLI entry point and pipeline orchestrator
    |-- models.py                       # Dataclasses and type definitions (Request, Step, Subject, etc.)
    |-- policy.py                       # Deletion rule lookup and category mapping
    |-- state.py                        # Multi-system evidence correlation and plan synthesis
    |-- evaluation/
    |   |-- evaluation_report.md        # Comprehensive benchmark report, metrics, and error analysis
    |   `-- usage_report.md             # Execution environment, runtime, and resource usage profile
    |-- evidence/
    |   |-- __init__.py
    |   `-- parser.py                   # Multi-format evidence parser (SQL, JSON, logs, text, PDFs)
    `-- tests/
        |-- test_phase1.py              # Unit tests for Phase 1 (Authorization & Identity)
        |-- test_phase2.py              # Unit tests for Phase 2 (Evidence & Cutoff Parsing)
        |-- test_phase3.py              # Unit tests for Phase 3 (State, Policy & Planning)
        `-- test_phase4.py              # Unit tests for Phase 4 (Pipeline Runner & Output Validation)
```

---

## Output Contract

The pipeline produces `output.csv` with the following schema:

```csv
case_id,deletion_status,steps_json
```

- **`case_id`**: Request identifier matching the input dataset.
- **`deletion_status`**: One of `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- **`steps_json`**: Serialized JSON array of audit step objects. Non-applicable cases contain `[]`.

### Step Object Schema

```json
{
  "step_no": 1,
  "phase": "FINDING",
  "system_id": "account_service",
  "resource_id": "account_005",
  "operation": "REPORT_REMAINING_RECORD",
  "state": "PRESENT",
  "evidence_id": "evidence_01"
}
```

### Supported Operations & Phases

| Phase | Operation | State | Description |
|---|---|---|---|
| **FINDING** | `REPORT_REMAINING_RECORD` | `PRESENT` | Prohibited record still exists in system |
| | `REPORT_EXPOSED_PII` | `PRESENT` | Record exists with unredacted PII fields |
| | `REPORT_ACTIVE_DATA_FLOW` | `ACTIVE` | Active sync job can recreate deleted data |
| | `REPORT_RESTORE_RISK` | `ACTIVE` | Unrestricted backup snapshot can restore data |
| **REMEDIATION** | `DISABLE_DATA_FLOW` | `DISABLED` | Halt active sync processes before cleanup |
| | `BLOCK_RESTORE` | `BLOCKED` | Prevent affected backup restoration |
| | `DELETE_RECORD` | `ABSENT` | Remove entire record |
| | `REDACT_RECORD` | `REDACTED` | Redact required PII while preserving record |
| | `ANONYMIZE_RECORD` | `ANONYMIZED` | Irreversibly unlink record from subject |
| **VERIFICATION** | `VERIFY_RECORD_ABSENT` | `ABSENT` | Confirm complete record absence |
| | `VERIFY_RECORD_PRESENT` | `PRESENT` | Confirm retention of policy-required records |
| | `VERIFY_RECORD_REDACTED` | `REDACTED` | Confirm required fields were redacted |
| | `VERIFY_RECORD_ANONYMIZED` | `ANONYMIZED` | Confirm record unlinking |
| | `VERIFY_DATA_FLOW_DISABLED` | `DISABLED` | Confirm data flow is halted |
| | `VERIFY_RESTORE_BLOCKED` | `BLOCKED` | Confirm restore path is blocked |

---

## Public Benchmark Results

As documented in [`code/evaluation/evaluation_report.md`](code/evaluation/evaluation_report.md), the engine was evaluated against the frozen 32-case public sample (`dataset/sample_deletion_requests.csv`):

| Metric | Result |
|---|---:|
| **Status Classification Agreement** | **32 / 32 (100.0%)** |
| **Semantic True Positive Steps** | **153** |
| Total Predicted Steps | 181 |
| Total Expected Reference Steps | 193 |
| **Semantic Step Precision** | **84.53%** (`153 / 181`) |
| **Semantic Step Recall** | **79.27%** (`153 / 193`) |
| Exact Step-Array Sequence Match | 4 / 32 (12.5%) |
| Aligned Attribute Mismatches | 1 (`case_14`, `backup_3870`, `evidence_id`) |
| Genuinely Missing Steps | 39 |
| Genuinely Extra Steps | 27 |

*Note: As detailed in the evaluation report, exact step-array sequence variance stems primarily from grounded policy interpretations (e.g., whether shared support tickets require redaction vs. full deletion) and differing service identifier provenance (e.g., citing concrete database replicas vs. gateway envelopes).*

---

## Execution and Resource Profile

As documented in [`code/evaluation/usage_report.md`](code/evaluation/usage_report.md):

- **Runtime:** Python 3.10+ (Standard Library only)
- **External Dependencies:** None (no third-party pip packages required)
- **Model Calls:** **0** (100% deterministic local rule and evidence engine)
- **Token Usage:** **0 input / 0 output tokens**
- **Execution API Cost:** **$0.00**
- **Design Invariants:** Zero LLM hallucinations, reproducible execution, atomic file writes, and memory-safe batch processing.

---

## Setup and Reproduction

### Prerequisites

- Python 3.10 or higher.
- Git.

### 1. Run Unit Tests

Execute the full 70-test suite across all four architectural phases:

```bash
python -m unittest discover -s code/tests -p "test_*.py" -v
```

### 2. Generate Output Predictions

To run the complete audit engine across all 518 evaluation requests and produce `output.csv`:

```bash
python code/main.py --output-csv output.csv
```

Optional arguments:
- `--requests-csv`: Path to deletion requests CSV (default: `dataset/deletion_requests.csv`).
- `--dataset-dir`: Path to dataset directory (default: `dataset`).
- `--output-csv`: Destination path for output CSV (default: `output.csv`).

---

## Official HackerRank Feedback & Improvement Areas

> [!NOTE]
> The items below represent diagnostic feedback and recommendations provided by HackerRank's post-submission review committee. They are documented here transparently as roadmap improvement areas for future iterations and should not be misconstrued as completed or currently implemented functionality.

### 1. Judge Interview
- Prepare stronger technical explanations for architectural decisions, including correlation windows and evidence verification.
- Demonstrate how deletion requests are traced through evidence, policy treatment, and verification.
- Explain implemented capabilities using actual code locations and behavior.
- Validate policy interpretations independently rather than relying on the same reasoning used to produce them.

### 2. Chat Transcript
- Define inputs, outputs, and policy decision rules before requesting implementation.
- Make architectural decisions and trade-offs explicit.
- Bring independently inspected failures and diagnoses into corrective prompts.
- Define how unreadable evidence and conflicting retention requirements affect final decisions.

### 3. Code ZIP
- Repair authorization expressions that prevent application startup in the evaluation harness.
- Run import checks and end-to-end tests against the exact submitted package.
- Introduce a bounded agentic evidence-investigation role while retaining deterministic validation.
- Require sufficient supporting evidence before declaring deletion complete, and ensure parser warnings block unsupported conclusions.
- Verify that records subject to retention requirements remain available, and add a runnable measurement routine for complete remediation plans.

### 4. Output CSV
- Build a complete, request-specific inventory before generating remediation plans, including account and retention checks.
- Identify ways deleted data could reappear through replicas, backups, or other systems.
- Prevent identifiers from one deletion request from leaking into another, and apply exact policy treatments (deletion vs. redaction).
- Require verification evidence for each remediation action before determining the final status.

---

## Challenge Reference

For more information regarding the competition specification and rules, visit:
[HackerRank Orchestrate - Ghost Data Still Exists](https://www.hackerrank.com/contests/hackerrank-orchestrate-october26/challenges/ghost-data-still-exists)
