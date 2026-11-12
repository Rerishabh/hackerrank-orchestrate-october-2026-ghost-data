from __future__ import annotations

import csv
import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

CODE_DIR = Path(__file__).parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from evidence.parser import EvidenceParser
from identity import build_identity_index
from io_loader import load_all, load_requests
from models import (
    DeletionRequest,
    EvidenceItem,
    IdentityChange,
    PlanStep,
    SystemActivity,
    UserIdentity,
)
from state import _outcome, reconstruct_case, steps_as_dicts, validate_plan_steps


class Phase3Tests(unittest.TestCase):
    ROOT = Path(__file__).parents[2]

    def _index(self):
        identity = UserIdentity(
            "user_1", "Example", "person@example.com", "+1 202 555 0100",
            "hash1", datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        return build_identity_index([identity], [])

    def _request(self, text: str = "Please delete my account.") -> DeletionRequest:
        cutoff = datetime(2026, 9, 10, tzinfo=timezone.utc)
        return DeletionRequest(
            "case_test", "person@example.com", cutoff, "COMPLETE", cutoff, cutoff, text
        )

    def _item(self, payload, *, resource="account_1", operation="profile_read",
              outcome="PRESENT", source="account_service", target=None):
        return EvidenceItem(
            "evidence_test", "evidence/test.json", "fixture", 
            datetime(2026, 9, 9, tzinfo=timezone.utc), None, source, target,
            resource, operation, outcome, (), (), payload,
        )

    def test_sample_statuses_are_reconstructed_from_public_inputs(self) -> None:
        dataset = self.ROOT / "dataset"
        loaded = load_all(dataset)
        index = build_identity_index(loaded["identities"], loaded["identity_changes"])
        evidence = EvidenceParser(dataset).parse_all()
        with (dataset / "sample_output.csv").open(encoding="utf-8", newline="") as handle:
            expected = {
                row["case_id"]: row["deletion_status"]
                for row in csv.DictReader(handle)
            }
        requests = load_requests(dataset / "sample_deletion_requests.csv")
        results = {
            request.case_id: reconstruct_case(
                request, index, evidence, loaded["activity"], loaded["rules"]
            ).status
            for request in requests
        }
        self.assertEqual(set(results), set(expected))
        # One sample intentionally remains unresolved because its only supporting
        # artifact is an image/PDF whose contents are unavailable to stdlib parsing.
        self.assertEqual(
            sum(results[case_id] == expected[case_id] for case_id in expected),
            32,
        )

    def test_remaining_record_and_redacted_tombstone(self) -> None:
        request = self._request()
        remaining = reconstruct_case(
            request, self._index(),
            (self._item({"email": "person@example.com", "status": "ACTIVE"}),), (),
        )
        self.assertEqual(remaining.status, "INCOMPLETE")
        self.assertEqual(
            [(step.operation, step.evidence_id) for step in remaining.steps],
            [("REPORT_REMAINING_RECORD", "evidence_test"),
             ("DELETE_RECORD", ""), ("VERIFY_RECORD_ABSENT", "")],
        )
        tombstone = self._item(
            {"subject_reference": "user_1", "account_status": "DELETED"},
            resource="tombstone_1", operation="ACCOUNT_TOMBSTONE",
            outcome="REDACTED", source="identity_service",
        )
        result = reconstruct_case(request, self._index(), (tombstone,), ())
        self.assertEqual(result.status, "COMPLETE")
        self.assertEqual(result.steps[0].operation, "VERIFY_RECORD_REDACTED")

    def test_active_flow_and_restore_risk_generate_ordered_steps(self) -> None:
        request = self._request()
        activity = (
            SystemActivity(
                "activity_flow", datetime(2026, 9, 1, tzinfo=timezone.utc),
                "SYNC_RECORD", "integration_service", "search_service",
                "flow_1", "SUCCESS", "customer_reference=user_1 enabled=true",
            ),
            SystemActivity(
                "activity_backup", datetime(2026, 9, 1, tzinfo=timezone.utc),
                "CHECK_RESTORE_ACCESS", "backup_service", "backup_service",
                "backup_1", "SUCCESS", "customer_reference=user_1 restore_allowed=true",
            ),
        )
        result = reconstruct_case(request, self._index(), (), activity)
        self.assertEqual(result.status, "INCOMPLETE")
        operations = [step.operation for step in result.steps]
        self.assertEqual(
            operations,
            [
                "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
                "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
                "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
            ],
        )
        self.assertEqual([step.step_no for step in result.steps], list(range(1, 7)))
        self.assertEqual(result.steps[0].evidence_id, "activity_flow")

    def test_deterministic_sorting_and_numbering(self) -> None:
        request = self._request()
        items = (
            self._item({"email": "person@example.com", "status": "PRESENT"},
                       resource="search_2", source="search_service", target="search_service"),
            self._item({"email": "person@example.com", "status": "PRESENT"},
                       resource="account_2", source="account_service"),
        )
        first = reconstruct_case(request, self._index(), items, ())
        second = reconstruct_case(request, self._index(), tuple(reversed(items)), ())
        self.assertEqual(first.steps, second.steps)
        self.assertEqual(
            [(step.system_id, step.resource_id) for step in first.steps[:2]],
            [("account_service", "account_2"), ("search_service", "search_2")],
        )
        self.assertEqual(steps_as_dicts(first.steps)[0]["step_no"], 1)

    def test_non_deletion_request_is_not_applicable(self) -> None:
        result = reconstruct_case(
            self._request("Please export my data."), self._index(), (), ()
        )
        self.assertEqual(result.status, "NOT_APPLICABLE")
        self.assertEqual(result.steps, ())

    def test_analytics_explicit_identifiable_outcome_overrides_missing_fields(self) -> None:
        item = self._item(
            {},
            resource="analytics_2034",
            operation="ANALYTICS_PROFILE",
            outcome="IDENTIFIABLE",
            source="analytics_platform",
        )
        self.assertEqual(_outcome(item), "PRESENT")

    def test_analytics_missing_identifier_fields_do_not_prove_anonymization(self) -> None:
        item = self._item(
            {},
            resource="analytics_2034",
            operation="ANALYTICS_PROFILE",
            outcome=None,
            source="analytics_platform",
        )
        self.assertIsNone(_outcome(item))

    def test_analytics_null_identifier_fields_prove_anonymization(self) -> None:
        item = self._item(
            {
                "customer_reference": None,
                "email": None,
                "phone": None,
                "email_hash": None,
            },
            resource="analytics_2034",
            operation="analytics_profile_read_completed",
            outcome=None,
            source="analytics_platform",
        )
        self.assertEqual(_outcome(item), "ANONYMIZED")

    def test_analytics_identifying_values_do_not_prove_anonymization(self) -> None:
        item = self._item(
            {"customer_reference": "user_1"},
            resource="analytics_2034",
            operation="analytics_profile_read_completed",
            outcome=None,
            source="analytics_platform",
        )
        self.assertEqual(_outcome(item), "PRESENT")

    def test_identifiable_analytics_record_plans_anonymization(self) -> None:
        item = self._item(
            {"email": "person@example.com"},
            resource="analytics_2034",
            operation="ANALYTICS_PROFILE",
            outcome="IDENTIFIABLE",
            source="analytics_platform",
        )
        result = reconstruct_case(self._request(), self._index(), (item,), ())
        self.assertEqual(result.status, "INCOMPLETE")
        self.assertEqual(
            [(step.phase, step.operation, step.resource_id, step.evidence_id)
             for step in result.steps],
            [
                ("FINDING", "REPORT_EXPOSED_PII", "analytics_2034", "evidence_test"),
                ("REMEDIATION", "ANONYMIZE_RECORD", "analytics_2034", ""),
                ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED", "analytics_2034", ""),
            ],
        )

    def test_subject_key_anchors_flow_and_backup_risks(self) -> None:
        request = self._request()
        evidence = (
            self._item(
                {"subject_key": "user_1", "trace_id": "trace-1",
                 "enabled": "true"},
                resource="data_flow_1", operation="SYNC_RECORD",
                source="integration_service", target="search_service",
            ),
            self._item(
                {"subject_key": "user_1", "eligible": "true",
                 "deletion_block": "false"},
                resource="backup_1", operation="BACKUP_CHECK",
                source="backup_service",
            ),
        )
        result = reconstruct_case(request, self._index(), evidence, ())
        self.assertEqual(result.status, "INCOMPLETE")
        self.assertEqual(
            [step.operation for step in result.steps],
            [
                "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
                "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
                "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
            ],
        )

    def test_public_pdf_attachment_is_linked_without_external_tools(self) -> None:
        evidence = EvidenceParser(self.ROOT / "dataset").parse_all()
        attachment = [
            item for item in evidence
            if item.evidence_id == "evidence_58"
            and item.resource_id == "support_001"
        ]
        self.assertEqual(len(attachment), 1)
        self.assertIn("priya.raman@gmail.com", attachment[0].identifiers)
        self.assertEqual(
            attachment[0].payload.get("data_category"),
            "SUPPORT_ATTACHMENT",
        )

    def test_resource_ownership_overrides_authoring_replica(self) -> None:
        request = self._request()
        item = self._item(
            {"email": "person@example.com", "rows": "1"},
            resource="support_1",
            operation="contact_query_completed",
            source="support_replica",
        )
        result = reconstruct_case(request, self._index(), (item,), ())
        self.assertEqual(result.steps[0].system_id, "support_platform")

    def test_incomplete_future_verification_steps_have_no_evidence(self) -> None:
        request = self._request()
        item = self._item(
            {"email": "person@example.com", "status": "PRESENT"},
            resource="search_1",
            source="search_replica",
        )
        result = reconstruct_case(request, self._index(), (item,), ())
        self.assertEqual(result.status, "INCOMPLETE")
        self.assertTrue(
            all(
                step.evidence_id == ""
                for step in result.steps
                if step.phase != "FINDING"
            )
        )

    def test_activity_and_evidence_for_one_risk_produce_one_finding(self) -> None:
        request = self._request()
        item = self._item(
            {"subject_key": "user_1", "restore_allowed": "true"},
            resource="backup_1",
            operation="BACKUP_CHECK",
            source="backup_service",
        )
        activity = (
            SystemActivity(
                "activity_backup",
                datetime(2026, 9, 1, tzinfo=timezone.utc),
                "CHECK_RESTORE_ACCESS",
                "deletion_worker",
                "backup_service",
                "backup_1",
                "SUCCESS",
                "subject_key=user_1 restore_allowed=true",
            ),
        )
        result = reconstruct_case(request, self._index(), (item,), activity)
        findings = [
            step for step in result.steps
            if step.phase == "FINDING" and step.operation == "REPORT_RESTORE_RISK"
        ]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].evidence_id, "evidence_test")

    def test_explicit_operation_category_overrides_resource_prefix(self) -> None:
        request = self._request()
        item = self._item(
            {"email": "person@example.com", "status": "PRESENT"},
            resource="support_4218",
            operation="SUPPORT_ATTACHMENT",
        )
        result = reconstruct_case(request, self._index(), (item,), ())
        self.assertEqual(
            [step.operation for step in result.steps],
            ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"],
        )

    def test_activity_steps_use_resource_owner_not_event_target(self) -> None:
        request = self._request()
        activity = (
            SystemActivity(
                "activity_flow",
                datetime(2026, 9, 1, tzinfo=timezone.utc),
                "SYNC_RECORD",
                "deletion_worker",
                "replica_gateway",
                "search_1",
                "SUCCESS",
                "customer_reference=user_1 enabled=true",
            ),
        )
        result = reconstruct_case(request, self._index(), (), activity)
        self.assertEqual(result.steps[0].system_id, "search_service")

    def test_empty_profile_snapshot_does_not_invent_account_resource(self) -> None:
        request = self._request()
        snapshot = EvidenceItem(
            "evidence_snapshot",
            "evidence/snapshot.sql",
            "fixture",
            datetime(2026, 9, 9, tzinfo=timezone.utc),
            None,
            "account_service",
            None,
            None,
            "PROFILE_SNAPSHOT_LOOKUP",
            None,
            (),
            (),
            {
                "_observation_kind": "SQL_ROW",
                "_table": "customer_profiles_primary",
                "user_id": "other_user",
            },
        )
        result = reconstruct_case(request, self._index(), (snapshot,), ())
        self.assertFalse(
            any(step.resource_id == "account_001" for step in result.steps)
        )

    def test_public_plans_obey_schema_and_provenance_invariants(self) -> None:
        dataset = self.ROOT / "dataset"
        loaded = load_all(dataset)
        index = build_identity_index(loaded["identities"], loaded["identity_changes"])
        evidence = EvidenceParser(dataset).parse_all()
        requests = load_requests(dataset / "sample_deletion_requests.csv")
        evidence_ids = {item.evidence_id for item in evidence}
        activity_ids = {event.activity_id for event in loaded["activity"]}
        audit_ids = {change.audit_id for change in loaded["identity_changes"]}
        supported_ids = evidence_ids | activity_ids | audit_ids
        for request in requests:
            result = reconstruct_case(
                request, index, evidence, loaded["activity"], loaded["rules"]
            )
            validate_plan_steps(result.steps)
            if result.status == "NOT_APPLICABLE":
                self.assertEqual(result.steps, ())
                continue
            for step in result.steps:
                if result.status == "INCOMPLETE" and step.phase != "FINDING":
                    self.assertEqual(step.evidence_id, "")
                else:
                    self.assertIn(step.evidence_id, supported_ids)

    def test_each_incomplete_remediation_has_matching_future_verification(self) -> None:
        dataset = self.ROOT / "dataset"
        loaded = load_all(dataset)
        index = build_identity_index(loaded["identities"], loaded["identity_changes"])
        evidence = EvidenceParser(dataset).parse_all()
        for request in load_requests(dataset / "sample_deletion_requests.csv"):
            result = reconstruct_case(
                request, index, evidence, loaded["activity"], loaded["rules"]
            )
            if result.status != "INCOMPLETE":
                continue
            remediations = {
                (step.system_id, step.resource_id, step.operation)
                for step in result.steps
                if step.phase == "REMEDIATION"
            }
            verifications = {
                (step.system_id, step.resource_id, step.operation)
                for step in result.steps
                if step.phase == "VERIFICATION"
            }
            expected_verification = {
                ("DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"),
                ("BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"),
                ("DELETE_RECORD", "VERIFY_RECORD_ABSENT"),
                ("REDACT_RECORD", "VERIFY_RECORD_REDACTED"),
                ("ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"),
            }
            for system_id, resource_id, operation in remediations:
                verify_operation = dict(expected_verification)[operation]
                self.assertIn(
                    (system_id, resource_id, verify_operation),
                    {(s[0], s[1], s[2]) for s in verifications},
                )

    def test_plan_validator_rejects_operation_in_wrong_phase(self) -> None:
        with self.assertRaises(ValueError):
            validate_plan_steps((
                PlanStep(
                    1,
                    "FINDING",
                    "account_service",
                    "account_1",
                    "DELETE_RECORD",
                    "ABSENT",
                    "",
                ),
            ))


if __name__ == "__main__":
    unittest.main()
