from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

CODE_DIR = Path(__file__).parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from evidence.parser import filter_by_audit_cutoff, parse_evidence_file, parse_manifest
from models import EvidenceManifestEntry


class Phase2Tests(unittest.TestCase):
    def _entry(self, root: Path, name: str, captured_at: str) -> EvidenceManifestEntry:
        return EvidenceManifestEntry(
            "evidence_test",
            f"evidence/{name}",
            "test_origin",
            datetime.fromisoformat(captured_at.replace("Z", "+00:00")),
        )

    def test_valid_and_nested_json_preserves_payload_and_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "nested.json").write_text(
                json.dumps(
                    {
                        "exported_at": "2026-09-10T12:00:00Z",
                        "snapshots": [
                            {
                                "captured_at": "2026-09-09T12:00:00Z",
                                "data_store": "account_service",
                                "records": [
                                    {
                                        "resource_id": "account_1",
                                        "email": "person@example.com",
                                        "status": "NOT_FOUND",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            items = parse_evidence_file(
                self._entry(root, "nested.json", "2026-09-10T12:00:00Z"), root
            )
            record = next(item for item in items if item.resource_id == "account_1")
            self.assertEqual(record.source_system, "account_service")
            self.assertIn("person@example.com", record.identifiers)
            self.assertEqual(record.reported_outcome, "NOT_FOUND")
            self.assertIsNone(record.event_time)
            self.assertEqual(record.payload["captured_at"], "2026-09-09T12:00:00Z")

    def test_sql_extracts_rows_and_table_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "snapshot.sql").write_text(
                "CREATE TABLE profiles (resource_id TEXT, email TEXT, result TEXT);"
                "INSERT INTO profiles VALUES ('account_7', 'person@example.com', 'PRESENT');",
                encoding="utf-8",
            )
            items = parse_evidence_file(
                self._entry(root, "snapshot.sql", "2026-09-10T12:00:00Z"), root
            )
            row = next(item for item in items if item.payload.get("_observation_kind") == "SQL_ROW")
            self.assertEqual(row.resource_id, "account_7")
            self.assertEqual(row.payload["_table"], "profiles")
            self.assertEqual(row.reported_outcome, "PRESENT")
            self.assertFalse(row.directly_observed)
            self.assertTrue(row.inferred)

    def test_sql_delete_statement_is_not_a_deletion_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "delete.sql").write_text(
                "CREATE TABLE profiles (resource_id TEXT, email TEXT);"
                "INSERT INTO profiles VALUES ('account_7', 'person@example.com');"
                "DELETE FROM profiles WHERE resource_id = 'account_7';",
                encoding="utf-8",
            )
            items = parse_evidence_file(
                self._entry(root, "delete.sql", "2026-09-10T12:00:00Z"), root
            )
            delete = next(
                item for item in items
                if item.payload.get("_statement_type") == "DELETE"
            )
            self.assertIsNone(delete.reported_outcome)
            self.assertIn("does not establish", delete.warnings[0])
            self.assertEqual(delete.operation, "DELETE")
            self.assertTrue(delete.directly_observed)
            self.assertFalse(delete.inferred)
            self.assertTrue(any(item.payload.get("_observation_kind") == "SQL_TABLE" for item in items))

    def test_sql_execution_error_and_empty_table_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "empty.sql").write_text(
                "CREATE TABLE profiles (resource_id TEXT);", encoding="utf-8"
            )
            empty = parse_evidence_file(
                self._entry(root, "empty.sql", "2026-09-10T12:00:00Z"), root
            )
            self.assertTrue(
                any("Empty executed table" in warning for item in empty for warning in item.warnings)
            )
            (evidence / "broken.sql").write_text(
                "CREATE TABLE profiles (resource_id TEXT);"
                "INSERT INTO profiles VALUES ('account_1');"
                "INSERT INTO missing VALUES ('account_2');",
                encoding="utf-8",
            )
            broken = parse_evidence_file(
                self._entry(root, "broken.sql", "2026-09-10T12:00:00Z"), root
            )
            self.assertEqual(broken[0].payload["_observation_kind"], "SQL_EXECUTION_ERROR")
            self.assertIn("missing", broken[0].payload["_execution_error"])
            self.assertFalse(broken[0].directly_observed)
            self.assertTrue(broken[0].inferred)

    def test_log_parser_preserves_outcome_without_inferring_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "events.log").write_text(
                "2026-09-10T12:00:00Z service=account_service "
                "event=deletion_requested resource_id=account_1 result=QUEUED\n"
                "2026-09-10T12:01:00Z service=account_service "
                "event=deletion_completed resource_id=account_1 result=SUCCESS\n",
                encoding="utf-8",
            )
            items = parse_evidence_file(
                self._entry(root, "events.log", "2026-09-10T12:00:00Z"), root
            )
            self.assertEqual([item.reported_outcome for item in items], ["QUEUED", "SUCCESS"])
            self.assertEqual(items[0].operation, "deletion_requested")

    def test_log_outcomes_and_malformed_records_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "events.log").write_text(
                "2026-09-10T12:00:00Z event=deletion_completed resource_id=a result=SUCCESS\n"
                "2026-09-10T12:01:00Z event=deletion_failed resource_id=b result=FAILED\n"
                "2026-09-10T12:02:00Z event=deletion_requested resource_id=c result=QUEUED\n"
                "2026-09-10T12:03:00Z event=deletion_requested resource_id=d result=REQUESTED\n"
                "2026-09-10T12:04:00Z event=deletion_started resource_id=e result=STARTED\n"
                "2026-99-99T99:99:99Z event=bad resource_id=f\n"
                "not|enough|fields\n",
                encoding="utf-8",
            )
            items = parse_evidence_file(
                self._entry(root, "events.log", "2026-09-10T12:00:00Z"), root
            )
            self.assertEqual(
                [item.reported_outcome for item in items[:5]],
                ["SUCCESS", "FAILED", "QUEUED", "REQUESTED", "STARTED"],
            )
            self.assertTrue(any("Malformed timestamp" in warning for item in items for warning in item.warnings))
            self.assertTrue(any("Malformed pipe" in warning for item in items for warning in item.warnings))
            self.assertTrue(any("no explicit outcome" in warning.lower() for item in items for warning in item.warnings))

    def test_nested_json_does_not_inherit_conflicting_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "nested.json").write_text(
                json.dumps({
                    "user_id": "parent-user",
                    "snapshots": [{"records": [
                        {"resource_id": "a", "user_id": "child-user", "email": "a@example.com"},
                        {"resource_id": "b", "email": "b@example.com"},
                    ]}],
                }),
                encoding="utf-8",
            )
            items = parse_evidence_file(
                self._entry(root, "nested.json", "2026-09-10T12:00:00Z"), root
            )
            by_resource = {item.resource_id: item for item in items if item.resource_id}
            self.assertEqual(by_resource["a"].identifiers, ("a@example.com", "child-user"))
            self.assertEqual(by_resource["b"].identifiers, ("b@example.com",))

    def test_cutoff_uses_manifest_capture_time(self) -> None:
        from models import EvidenceItem

        items = (
            EvidenceItem("old", "old", "origin", datetime(2026, 9, 10, tzinfo=timezone.utc), None,
                         None, None, None, None, None, (), (), {}),
            EvidenceItem("new", "new", "origin", datetime(2026, 9, 18, tzinfo=timezone.utc), None,
                         None, None, None, None, None, (), (), {}),
        )
        kept = filter_by_audit_cutoff(items, datetime(2026, 9, 17, tzinfo=timezone.utc))
        self.assertEqual([item.evidence_id for item in kept], ["old"])

    def test_event_before_cutoff_is_excluded_when_capture_is_after_cutoff(self) -> None:
        from models import EvidenceItem

        item = EvidenceItem(
            "late", "path", "origin",
            datetime(2026, 9, 18, tzinfo=timezone.utc),
            datetime(2026, 9, 10, tzinfo=timezone.utc),
            "account_service", None, "account_1", "DELETE", "SUCCESS",
            (), (), {},
        )
        self.assertEqual(
            filter_by_audit_cutoff(
                (item,), datetime(2026, 9, 17, tzinfo=timezone.utc)
            ),
            (),
        )
        self.assertEqual(item.event_time, datetime(2026, 9, 10, tzinfo=timezone.utc))

    def test_cutoff_requires_aware_timestamp(self) -> None:
        with self.assertRaisesRegex(ValueError, "timezone"):
            filter_by_audit_cutoff((), datetime(2026, 9, 17))

    def test_cutoff_rejects_naive_evidence_capture_timestamp(self) -> None:
        from models import EvidenceItem

        item = EvidenceItem(
            "naive", "path", "origin", datetime(2026, 9, 10), None,
            None, None, None, None, None, (), (), {},
        )
        with self.assertRaisesRegex(ValueError, "naive capture"):
            filter_by_audit_cutoff(
                (item,), datetime(2026, 9, 17, tzinfo=timezone.utc)
            )

    def test_manifest_rejects_malformed_capture_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.csv"
            path.write_text(
                "file_id,file_path,origin,captured_at\n"
                "evidence_1,evidence/a.json,test,not-a-time\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "captured_at"):
                parse_manifest(path)

    def test_missing_file_has_explicit_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            entry = self._entry(root, "missing.json", "2026-09-10T12:00:00Z")
            items = parse_evidence_file(entry, root)
            self.assertEqual(len(items), 1)
            self.assertTrue(items[0].warnings)
            self.assertIn("missing", items[0].warnings[0].lower())

    def test_malformed_json_has_explicit_warning(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "broken.json").write_text("{", encoding="utf-8")
            items = parse_evidence_file(
                self._entry(root, "broken.json", "2026-09-10T12:00:00Z"), root
            )
            self.assertIn("JSON parse failed", items[0].warnings[0])

    def test_pdf_and_png_limitations_never_claim_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            (evidence / "document.pdf").write_bytes(b"%PDF-1.4\n")
            png = parse_evidence_file(
                self._entry(root, "image.png", "2026-09-10T12:00:00Z"), root
            )[0]
            pdf = parse_evidence_file(
                self._entry(root, "document.pdf", "2026-09-10T12:00:00Z"), root
            )[0]
            self.assertFalse(png.identifiers)
            self.assertFalse(png.payload)
            self.assertTrue(png.warnings)
            self.assertFalse(pdf.identifiers)
            self.assertTrue(pdf.warnings)

    def test_observation_order_and_provenance_are_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "evidence"
            evidence.mkdir()
            (evidence / "records.json").write_text(
                '[{"resource_id": "a"}, {"resource_id": "b"}]', encoding="utf-8"
            )
            entry = self._entry(root, "records.json", "2026-09-10T12:00:00Z")
            first = parse_evidence_file(entry, root)
            second = parse_evidence_file(entry, root)
            self.assertEqual(first, second)
            self.assertTrue(all(item.evidence_id == "evidence_test" for item in first))
            self.assertTrue(all(item.source_path == "evidence/records.json" for item in first))


if __name__ == "__main__":
    unittest.main()
