# Evaluation Report

## 1. Challenge objective

“Ghost Data Still Exists” requires an audit agent to determine whether each
request actually authorizes deletion, reconstruct the subject's current and
historical identifiers, inspect participant-facing evidence at the request's
`audit_at` cutoff, apply the supplied deletion policy, and produce an
evidence-backed deletion status and ordered remediation plan.

The agent must not treat workflow status, operation results, or later evidence
as proof of the state at the audit cutoff. It must preserve policy-required
records, handle account tombstones correctly, and identify active data flows or
restore paths that can recreate prohibited data.

## 2. Four-phase pipeline architecture

1. **Phase 1 — Authorization and identity**
   - Classify multilingual request text using command context and intent.
   - Reject status questions, negated or cancelled requests, access/export
     requests, and unrelated profile updates.
   - Reconstruct current and historical identifiers with cutoff-aware rollback,
     normalized phone numbers, case-insensitive email/hash matching, and
     ambiguity rejection.

2. **Phase 2 — Evidence foundation**
   - Load the evidence manifest and parse JSON, SQL, logs, text, PDF, and image
     artifacts into typed evidence records.
   - Preserve file provenance, capture timestamps, event timestamps, identifiers,
     resource IDs, and parser warnings.
   - Exclude evidence whose manifest capture time is after `audit_at`.

3. **Phase 3 — State, policy, and planning**
   - Match evidence and activity to the resolved subject.
   - Reconstruct resource state at the cutoff, classify outcomes, apply
     `deletion_rules.csv`, and detect active flows and restore risks.
   - Generate ordered `FINDING`, `REMEDIATION`, and `VERIFICATION` steps and
     validate plan invariants.

4. **Phase 4 — Execution and delivery**
   - **4.1:** Load shared inputs once, process the full request set
     deterministically in memory, and validate every result.
   - **4.2:** Serialize validated results to UTF-8 `output.csv` using compact
     JSON and an atomic same-directory replacement.
   - **4.3:** Document evaluation results, limitations, synthetic cases, and
     execution usage without changing the frozen implementation.

## 3. Output contract

The output has exactly three columns:

```text
case_id,deletion_status,steps_json
```

`deletion_status` is one of `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
`steps_json` is a JSON array of step objects with consecutive `step_no` values.
Steps are ordered by phase (`FINDING`, `REMEDIATION`, `VERIFICATION`) and then
by the established operation and resource ordering. Non-applicable requests
must contain `steps_json=[]`; incomplete-case remediation and future
verification steps use an empty `evidence_id`.

## 4. Frozen public-sample benchmark

The following figures are transcribed from the frozen artifact
[`phase3_semantic_diff_verified_post_fix.json`](../../../../.copilot/session-state/e16a2ba3-b051-4e7d-9d88-f1043b047213/files/phase3_semantic_diff_verified_post_fix.json)
and were not recomputed or altered for Phase 4.3:

| Metric | Result |
|---|---:|
| Status agreement | 32/32 (100%) |
| Exact step-array agreement | 4/32 (12.5%) |
| Semantic true positives | 153 |
| Genuinely missing steps | 39 |
| Genuinely extra steps | 27 |
| Aligned attribute mismatches | 1 |
| Attribute mismatch detail | `case_14`, `backup_3870`, `evidence_id` |
| Total predicted steps | 181 |
| Total expected steps | 193 |
| Precision | 84.53% (`153 / 181`) |
| Recall | 79.27% (`153 / 193`) |

These are local comparisons against the **32-case public sample**. They are
not the hidden 518-case official leaderboard score and must not be presented
as official evaluator results.

## 5. How to interpret the metrics

- **Overall status accuracy** asks whether each case is classified as
  `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`. The implementation agrees on
  all 32 public cases, but status agreement alone does not prove that every
  affected record, risk, or verification check was found.
- **Semantic alignment** compares step meaning—phase, system, resource,
  operation, state, and evidence provenance—while accounting for independently
  ordered but equivalent steps. The 153 true positives measure this deeper
  agreement. Missing and extra steps expose completeness and over-reporting
  differences.
- **Exact sequence agreement** requires the complete serialized step array to
  match in content, fields, ordering, and sequence numbers. Only 4 of 32
  arrays match exactly, so this stricter measure is necessarily lower than
  status accuracy and semantic precision.

## 6. Mismatch taxonomy and impact

### Bucket 1 — Confirmed Implementation Defects

**None confirmed.**

The read-only forensic review found no remaining discrepancy that establishes
a definite implementation error in date handling, identity rollback,
subject matching, cutoff enforcement, or policy mapping. In particular, the
analytics outcome logic no longer treats an empty identifier-field set as
proof of anonymization, and account absence is not synthesized from unrelated
references.

### Bucket 2 — Grounded Policy Divergences

* **`case_10`: support redaction versus deletion.** The public reference
  expects deletion of `support_002`, while the participant-facing policy
  distinguishes shared support conversations (`SUPPORT_MESSAGE`, `rule_05`,
  `REDACT`) from subject-only attachments (`SUPPORT_ATTACHMENT`, `rule_06`,
  `DELETE`). The available support evidence does not establish that this
  shared conversation is a subject-only attachment.
* **`case_12`: analytics anonymization versus deletion.** The public
  reference expects deletion of `analytics_9914`, while `ANALYTICS_PROFILE`
  records that remain attributable to a user require anonymization under
  `rule_07`. The implementation follows the supplied policy rather than
  converting that treatment to deletion.

These divergences affect finding/remediation/verification operations and
therefore reduce exact-array agreement even when the case status remains
correct.

### Bucket 3 — Evidence limitations and ambiguities

* **Unreferenced account lookups:** `case_01`, `case_02`, `case_03`,
  `case_04`, `case_06`, `case_07`, `case_08`, `case_09`, and later cases
  contain reference account verifications such as `account_###` that are not
  consistently observed as direct account-service records at the cutoff.
  A search row, numeric suffix, or foreign key is insufficient provenance for
  `VERIFY_RECORD_ABSENT`.
* **Post-cutoff evidence in `case_09`:** the `audit_record_4902` observation
  is in `evidence_06`, whose manifest capture is after the case's `audit_at`.
  The embedded event time cannot override the manifest capture cutoff.
* **Unlinked null-identifier traces:** `case_03` (`analytics_9406`) and
  `case_04` (`analytics_901`) contain null identifier fields, but do not
  independently link those records to the subject. Inferring
  `VERIFY_RECORD_ANONYMIZED` from absence alone would be unsupported.
* **`case_14` provenance precedence:** both direct `evidence_03` and
  `activity_3690` support the restore risk for `backup_3870`; the benchmark
  prefers `evidence_03`, while the prediction cites `activity_3690`.
* **Gateway envelope versus resource owner:** the
  `records_assurance_gateway` export contains resources owned by account,
  search, support, analytics, security, backup, and integration services.
  The implementation reports the concrete resource-owning service; some
  reference steps use the gateway envelope name. The evidence does not make
  that naming convention unambiguous.

These limitations explain missing, extra, and field-level differences without
justifying fabricated identifiers or unsupported state claims.

## 7. Independently designed synthetic evaluation cases

These cases are test designs for edge behavior, not additions to the official
dataset and not hidden-label claims.

### Synthetic case A — Historical hash rollback with a later audit event

* Request email: `old.person@example.test`
* Identity history: the email was replaced before `audit_at`; its hash was
  replaced after `audit_at`.
* Evidence: a pre-cutoff search row contains the historical email hash; a
  post-cutoff export contains only the newer hash.
* Expected behavior: resolve the historical identifier and report the
  pre-cutoff search record, while excluding the post-cutoff hash and later
  evidence. This exercises sequential rollback and cutoff filtering together.

### Synthetic case B — Redacted tombstone versus active recreation flow

* Request: permanent deletion for `user_synthetic_b`.
* Evidence: an account tombstone retains only the stable internal reference,
  while an integration connector with `enabled=true` still delivers that
  reference to a downstream search system.
* Expected behavior: verify the permitted tombstone redaction, report the
  active flow, plan `DISABLE_DATA_FLOW` before downstream cleanup, and verify
  that the flow is disabled. The tombstone must not be deleted merely because
  the flow remains active.

### Synthetic case C — Cascading unlink across support, analytics, and backup

* Request: delete a subject with a historical email and phone.
* Evidence: a shared support conversation requires redaction, an attributable
  analytics profile requires anonymization, and a backup restore check reports
  `restore_allowed=true`.
* Expected behavior: emit separate policy-specific findings, plan the restore
  block before dependent cleanup, redact support data, anonymize analytics, and
  verify each final state. A single “delete everything” step is invalid.

## 8. Conclusion

The public sample shows perfect deletion-status agreement and substantial
semantic step agreement, while exact serialized plans remain stricter and
lower. The forensic review supports documenting the policy divergences and
evidence ambiguities rather than changing Phase 3 logic to match unsupported
reference assumptions. Phase 4.3 documentation is complete; no official
leaderboard or third-party evaluator was run.
