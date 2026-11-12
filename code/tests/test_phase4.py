from __future__ import annotations

import sys
import unittest
import csv
import json
import tempfile
from pathlib import Path

CODE_DIR = Path(__file__).parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from main import (
    _case_sort_key,
    _validate_result_case_ids,
    _validate_steps,
    run_pipeline,
    validate_pipeline_results,
    write_output_csv,
)
from io_loader import load_requests
from models import PlanStep


class Phase4RunnerTests(unittest.TestCase):
    ROOT = Path(__file__).parents[2]

    def test_full_dataset_is_processed_in_sorted_memory_results(self) -> None:
        records = run_pipeline(self.ROOT / "dataset")
        self.assertEqual(len(records), 518)
        self.assertEqual(
            [record["case_id"] for record in records],
            sorted(
                (record["case_id"] for record in records),
                key=lambda case_id: (
                    0,
                    int(case_id.removeprefix("case_")),
                ),
            ),
        )
        self.assertTrue(all(
            set(record) == {"case_id", "deletion_status", "steps_json"}
            for record in records
        ))

    def test_result_validation_rejects_duplicate_and_invalid_records(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate result case_id"):
            validate_pipeline_results(
                (
                    {"case_id": "case_1", "deletion_status": "COMPLETE", "steps_json": []},
                    {"case_id": "case_1", "deletion_status": "COMPLETE", "steps_json": []},
                )
            )
        with self.assertRaisesRegex(ValueError, "invalid deletion_status"):
            validate_pipeline_results(
                ({"case_id": "case_1", "deletion_status": "UNKNOWN", "steps_json": []},)
            )
        with self.assertRaisesRegex(ValueError, "steps_json=\\[\\]"):
            validate_pipeline_results(
                (
                    {
                        "case_id": "case_1",
                        "deletion_status": "NOT_APPLICABLE",
                        "steps_json": [{"step_no": 1}],
                    },
                )
            )

    def test_result_validation_rejects_boolean_step_number(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-integer step_no"):
            validate_pipeline_results(
                (
                    {
                        "case_id": "case_1",
                        "deletion_status": "INCOMPLETE",
                        "steps_json": [
                            {
                                "step_no": True,
                                "phase": "FINDING",
                                "system_id": "account_service",
                                "resource_id": "account_1",
                                "operation": "REPORT_REMAINING_RECORD",
                                "state": "PRESENT",
                                "evidence_id": "",
                            }
                        ],
                    },
                )
            )

    def test_result_validation_rejects_missing_or_extra_step_fields(self) -> None:
        base_step = {
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": "account_1",
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "",
        }
        missing = dict(base_step)
        del missing["state"]
        extra = {**base_step, "unexpected": "value"}
        for step in (missing, extra):
            with self.subTest(step=step):
                with self.assertRaisesRegex(ValueError, "invalid step shape"):
                    validate_pipeline_results(
                        (
                            {
                                "case_id": "case_1",
                                "deletion_status": "INCOMPLETE",
                                "steps_json": [step],
                            },
                        )
                    )

    def test_result_validation_rejects_unsupported_provenance(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported evidence"):
            validate_pipeline_results(
                (
                    {
                        "case_id": "case_1",
                        "deletion_status": "INCOMPLETE",
                        "steps_json": [
                            {
                                "step_no": 1,
                                "phase": "FINDING",
                                "system_id": "account_service",
                                "resource_id": "account_1",
                                "operation": "REPORT_REMAINING_RECORD",
                                "state": "PRESENT",
                                "evidence_id": "not_allowed",
                            }
                        ],
                    },
                ),
                {"evidence_1"},
            )

    def test_result_validation_rejects_mismatched_case_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "do not match request case IDs"):
            _validate_result_case_ids({"case_1"}, ({"case_id": "case_2"},))

    def test_result_case_id_validation_rejects_duplicates(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate pipeline result case IDs"):
            _validate_result_case_ids(
                {"case_1"},
                ({"case_id": "case_1"}, {"case_id": "case_1"}),
            )

    def test_serialized_steps_must_match_evaluation_values(self) -> None:
        evaluated = PlanStep(
            1,
            "FINDING",
            "account_service",
            "account_1",
            "REPORT_REMAINING_RECORD",
            "PRESENT",
            "",
        )
        tampered = {
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": "account_2",
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "",
        }
        with self.assertRaisesRegex(ValueError, "do not match the evaluated steps"):
            _validate_steps(
                "case_1",
                type("Evaluation", (), {"steps": (evaluated,), "status": "INCOMPLETE"})(),
                (tampered,),
                set(),
            )

    def test_provenance_is_required_for_non_empty_ids(self) -> None:
        step = {
            "step_no": 1,
            "phase": "FINDING",
            "system_id": "account_service",
            "resource_id": "account_1",
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "evidence_1",
        }
        record = (
            {
                "case_id": "case_1",
                "deletion_status": "INCOMPLETE",
                "steps_json": [step],
            },
        )
        with self.assertRaisesRegex(ValueError, "unsupported evidence"):
            validate_pipeline_results(record)
        with self.assertRaisesRegex(ValueError, "unsupported evidence"):
            validate_pipeline_results(record, set())
        self.assertEqual(
            validate_pipeline_results(record, {"evidence_1"})[0]["steps_json"],
            [step],
        )

    def test_alternate_request_file_uses_validated_supporting_inputs(self) -> None:
        records = run_pipeline(
            self.ROOT / "dataset",
            request_filename="sample_deletion_requests.csv",
        )
        self.assertEqual(len(records), 32)
        self.assertEqual(
            [record["case_id"] for record in records],
            sorted(
                (record["case_id"] for record in records),
                key=lambda case_id: (
                    0,
                    int(case_id.removeprefix("case_")),
                ),
            ),
        )

    def test_run_pipeline_rejects_request_path_traversal(self) -> None:
        with self.assertRaisesRegex(ValueError, "within dataset_dir"):
            run_pipeline(self.ROOT / "dataset", request_filename="..\\requests.csv")

    def test_case_sort_key_uses_numeric_suffix(self) -> None:
        records = [
            {"case_id": "case_10"},
            {"case_id": "case_2"},
            {"case_id": "case_100"},
            {"case_id": "other"},
        ]
        ordered = sorted(records, key=_case_sort_key)
        self.assertEqual(
            [record["case_id"] for record in ordered],
            ["case_2", "case_10", "case_100", "other"],
        )

    def test_pipeline_case_sequence_matches_request_csv(self) -> None:
        expected = [
            request.case_id
            for request in load_requests(self.ROOT / "dataset" / "deletion_requests.csv")
        ]
        actual = [record["case_id"] for record in run_pipeline(self.ROOT / "dataset")]
        self.assertEqual(actual, expected)

    def test_output_csv_headers_and_row_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "output.csv"
            write_output_csv(self.ROOT / "dataset", output_path)
            with output_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.reader(handle))
        self.assertEqual(rows[0], ["case_id", "deletion_status", "steps_json"])
        self.assertEqual(len(rows) - 1, 518)

    def test_output_csv_steps_json_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "output.csv"
            write_output_csv(self.ROOT / "dataset", output_path)
            with output_path.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 518)
        for row in rows:
            steps = json.loads(row["steps_json"])
            self.assertIsInstance(steps, list)
            self.assertEqual(row["steps_json"], json.dumps(
                steps, ensure_ascii=False, separators=(",", ":")
            ))

    def test_output_csv_rejects_invalid_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            invalid_path = Path(temporary) / "missing" / "output.csv"
            with self.assertRaises(FileNotFoundError):
                write_output_csv(self.ROOT / "dataset", invalid_path)


if __name__ == "__main__":
    unittest.main()
