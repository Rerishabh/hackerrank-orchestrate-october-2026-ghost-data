# Usage Report

## 1. Execution environment

- Runtime: Python 3.10 or newer.
- Dependencies: standard library only.
- Standard-library modules used by the solution include `csv`, `json`, `sys`,
  `os`, `pathlib`, `argparse`, `collections`, `typing`, and `unittest`.
- The pipeline is runnable from the repository root and resolves dataset and
  output paths relative to the configured repository/dataset locations.

## 2. Reproduction commands

Run the complete unit-test suite:

```text
python -m unittest discover -s code\tests -p "test_*.py" -v
```

Regenerate the root output file:

```text
python code\main.py --output-csv output.csv
```

The second command is the Phase 4.2 delivery command. Phase 4.3 only
documents the command and does not execute it.

## 3. Model calls, tokens, and API cost

The production execution pipeline is fully deterministic. It performs **0
external LLM/API calls**, consumes **0 input tokens and 0 output tokens**, and
has an estimated execution API cost of **$0.00**.

The pipeline uses local CSV, JSON, SQL, text, PDF, and image evidence parsing
and deterministic matching/planning logic. No model provider or API key is
required for a production run. The benchmark numbers in the evaluation report
are therefore algorithmic comparison results, not model-call results.

## 4. Runtime and memory characteristics

The runner loads and validates the supporting inputs once per run, builds the
identity index once, parses evidence once, and then processes requests in a
single deterministic process. Results are held in memory until validation is
complete; the CSV writer validates the full result set before opening the
destination and uses a temporary same-directory file followed by replacement.

Consequently:

- Runtime is dominated by CSV/evidence parsing and subject/resource matching.
- Processing is single-pass over the request set after shared indexes are
  built; no external service latency or model retry variability is present.
- Memory is proportional to the loaded participant-facing dataset, parsed
  evidence, indexes, and in-memory result records.
- Ordering is deterministic, including natural numeric ordering for IDs such
  as `case_2`, `case_10`, and `case_100`.

No new timing or peak-memory measurement was collected for this documentation
turn, so no unmeasured duration or byte figure is asserted.

## 5. Operational invariants and contracts

- Input data is read only from participant-facing files under `dataset/`.
- The full request run produces one result per request case ID; duplicate,
  dropped, or extraneous result IDs are rejected.
- Request filenames must remain within the dataset directory.
- Results are validated for exact field sets, field types, allowed statuses,
  valid plan phases/operations/states, consecutive numbering, deterministic
  ordering, and supported non-empty provenance IDs.
- `NOT_APPLICABLE` results contain an empty step array.
- Output columns are exactly `case_id`, `deletion_status`, and `steps_json`.
- Output is UTF-8 CSV with newline `\n`, minimal quoting, and compact JSON
  arrays.
- Evidence is constrained by manifest capture time and the case's `audit_at`.
- Findings cite participant-visible evidence; incomplete-case remediation and
  future verification steps use empty evidence IDs.
- Policy-required retention, redaction, anonymization, account tombstones,
  active flows, and restore risks are preserved as distinct concepts.
- The generated output contains exactly one row per case, sorted naturally by
  case ID.
- No organizer-only truth, golden labels, third-party evaluator, or hidden
  leaderboard result was used in this report.

## 6. Scope of reported results

The documented benchmark is a local comparison against the 32 public sample
requests. The full input contract contains 518 evaluation requests, but this
report does not claim an official hidden-dataset score. Official leaderboard
results would require the challenge's evaluator and are intentionally not
asserted here.
