"""Phase 4.1 full-dataset pipeline runner.

The runner evaluates every deletion request in memory. CSV output generation is
deliberately kept out of this phase.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from authorization import classify_request
from evidence.parser import EvidenceParser
from identity import build_identity_index
from io_loader import (
    load_activity,
    load_all,
    load_evidence_manifest,
    load_identity_changes,
    load_identities,
    load_requests,
    load_rules,
)
from models import DeletionRequest, PlanStep, StateEvaluation
from state import reconstruct_case, steps_as_dicts, validate_plan_steps


_REQUEST_STATUSES = {"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"}
_RESULT_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
_STEP_KEYS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}


def _case_sort_key(record: Mapping[str, Any]) -> tuple[int, str, int, str]:
    case_id = record["case_id"]
    match = re.fullmatch(r"case_(\d+)", case_id)
    if match:
        return (0, "case", int(match.group(1)), case_id)
    return (1, case_id, 0, case_id)


def _status_value(status: Any) -> str:
    value = getattr(status, "value", status)
    if not isinstance(value, str):
        raise ValueError(f"state evaluation returned a non-string status: {status!r}")
    return value


def _validate_requests(requests: Sequence[DeletionRequest]) -> None:
    seen: set[str] = set()
    for request in requests:
        if not request.case_id:
            raise ValueError("request contains an empty case_id")
        if request.case_id in seen:
            raise ValueError(f"duplicate case_id: {request.case_id}")
        seen.add(request.case_id)
        if request.reported_status not in _REQUEST_STATUSES:
            raise ValueError(
                f"request {request.case_id} has invalid reported_status "
                f"{request.reported_status!r}"
            )


def _validate_steps(
    case_id: str,
    evaluation: StateEvaluation,
    steps: Sequence[Mapping[str, Any]],
    valid_provenance_ids: set[str],
) -> None:
    typed_steps = evaluation.steps
    validate_plan_steps(typed_steps)
    if len(steps) != len(typed_steps):
        raise ValueError(f"case {case_id} step serialization changed its length")
    for step in steps:
        if not isinstance(step, Mapping) or set(step) != _STEP_KEYS:
            raise ValueError(f"case {case_id} contains an invalid step shape: {step!r}")
        if type(step["step_no"]) is not int:
            raise ValueError(f"case {case_id} has a non-integer step_no")
        for field in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
            if not isinstance(step[field], str):
                raise ValueError(f"case {case_id} has a non-string step field: {field}")
        evidence_id = step["evidence_id"]
        if evidence_id and evidence_id not in valid_provenance_ids:
            raise ValueError(
                f"case {case_id} cites unsupported evidence or activity ID {evidence_id!r}"
            )
    expected_steps = steps_as_dicts(typed_steps)
    if list(steps) != expected_steps:
        raise ValueError(
            f"case {case_id} serialized steps do not match the evaluated steps"
        )

    status = _status_value(evaluation.status)
    if status == "NOT_APPLICABLE" and steps:
        raise ValueError(f"NOT_APPLICABLE case {case_id} must have no steps")
    if not isinstance(status, str) or status not in _RESULT_STATUSES:
        raise ValueError(f"case {case_id} has invalid deletion status {status!r}")


def validate_pipeline_results(
    records: Iterable[Mapping[str, Any]],
    valid_provenance_ids: set[str] | None = None,
) -> tuple[dict[str, Any], ...]:
    """Validate and deterministically order serialized in-memory results.

    When ``valid_provenance_ids`` is omitted, no non-empty evidence ID is
    accepted because provenance cannot be established. The pipeline always
    supplies the complete evidence/activity/audit ID set, so its non-empty
    citations are checked against actual participant-facing provenance.
    """

    provenance = valid_provenance_ids if valid_provenance_ids is not None else set()
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError(f"invalid result record: {record!r}")
        if set(record) != {"case_id", "deletion_status", "steps_json"}:
            raise ValueError(f"invalid result shape: {record!r}")
        case_id = record["case_id"]
        status = record["deletion_status"]
        steps = record["steps_json"]
        if not isinstance(case_id, str) or not case_id:
            raise ValueError(f"invalid result case_id: {case_id!r}")
        if case_id in seen:
            raise ValueError(f"duplicate result case_id: {case_id}")
        seen.add(case_id)
        if not isinstance(status, str) or status not in _RESULT_STATUSES:
            raise ValueError(f"case {case_id} has invalid deletion_status {status!r}")
        if not isinstance(steps, list):
            raise ValueError(f"case {case_id} steps_json must be a list")
        if status == "NOT_APPLICABLE" and steps:
            raise ValueError(f"NOT_APPLICABLE case {case_id} must have steps_json=[]")
        typed_steps: list[PlanStep] = []
        for step in steps:
            if not isinstance(step, Mapping) or set(step) != _STEP_KEYS:
                raise ValueError(f"case {case_id} contains an invalid step shape: {step!r}")
            step_no = step["step_no"]
            if type(step_no) is not int:
                raise ValueError(f"case {case_id} has a non-integer step_no")
            string_fields = (
                "phase",
                "system_id",
                "resource_id",
                "operation",
                "state",
                "evidence_id",
            )
            for field in string_fields:
                if not isinstance(step[field], str):
                    raise ValueError(
                        f"case {case_id} has a non-string step field: {field}"
                    )
            evidence_id = step["evidence_id"]
            if evidence_id and evidence_id not in provenance:
                raise ValueError(
                    f"case {case_id} cites unsupported evidence or activity ID "
                    f"{evidence_id!r}"
                )
            typed_steps.append(
                PlanStep(
                    step_no,
                    step["phase"],
                    step["system_id"],
                    step["resource_id"],
                    step["operation"],
                    step["state"],
                    evidence_id,
                )
            )
        validate_plan_steps(typed_steps)
        normalized.append(
            {
                "case_id": case_id,
                "deletion_status": status,
                "steps_json": [dict(step) for step in steps],
            }
        )
    return tuple(sorted(normalized, key=_case_sort_key))


def _validate_result_case_ids(
    request_case_ids: set[str],
    records: Sequence[Mapping[str, Any]],
) -> None:
    result_case_ids = [record["case_id"] for record in records]
    if len(result_case_ids) != len(set(result_case_ids)):
        raise ValueError("duplicate pipeline result case IDs")
    if set(result_case_ids) != request_case_ids:
        raise ValueError("pipeline result case IDs do not match request case IDs")


def run_pipeline(
    dataset_dir: Path,
    *,
    request_filename: str = "deletion_requests.csv",
) -> tuple[dict[str, Any], ...]:
    """Evaluate all requests and return validated results without writing files."""

    dataset_dir = dataset_dir.resolve()
    if not dataset_dir.is_dir():
        raise FileNotFoundError(f"dataset directory does not exist: {dataset_dir}")
    request_path = Path(request_filename)
    if request_path.is_absolute() or not request_path.parts or ".." in request_path.parts:
        raise ValueError("request_filename must resolve within dataset_dir")
    request_path = (dataset_dir / request_path).resolve()
    try:
        request_path.relative_to(dataset_dir)
    except ValueError as exc:
        raise ValueError("request_filename must resolve within dataset_dir") from exc
    if request_filename != "deletion_requests.csv":
        # load_all() only composes these individual loaders; it adds no
        # cross-file validation, so this branch preserves the same validation
        # while substituting only the request CSV.
        loaded = {
            "requests": load_requests(request_path),
            "identities": load_identities(dataset_dir / "user_identities.csv"),
            "identity_changes": load_identity_changes(dataset_dir / "user_audit_log.csv"),
            "activity": load_activity(dataset_dir / "system_activity.csv"),
            "rules": load_rules(dataset_dir / "deletion_rules.csv"),
            "evidence_manifest": load_evidence_manifest(dataset_dir / "evidence_files.csv"),
        }
        requests = loaded["requests"]
    else:
        loaded = load_all(dataset_dir)
        requests = loaded["requests"]
    if not isinstance(requests, list):
        raise ValueError("request loader returned an invalid collection")
    _validate_requests(requests)

    index = build_identity_index(loaded["identities"], loaded["identity_changes"])
    evidence = EvidenceParser(dataset_dir).parse_all()
    activity = loaded["activity"]
    rules = loaded["rules"]
    provenance_ids = {
        *(item.evidence_id for item in evidence),
        *(event.activity_id for event in activity),
        *(change.audit_id for change in loaded["identity_changes"]),
    }

    records: list[dict[str, Any]] = []
    for request in requests:
        evaluation = reconstruct_case(request, index, evidence, activity, rules)
        status = _status_value(evaluation.status)
        steps = steps_as_dicts(evaluation.steps)
        _validate_steps(request.case_id, evaluation, steps, provenance_ids)
        records.append(
            {
                "case_id": request.case_id,
                "deletion_status": status,
                "steps_json": steps,
            }
        )
    _validate_result_case_ids({request.case_id for request in requests}, records)
    return validate_pipeline_results(records, provenance_ids)


def _load_provenance_ids(dataset_dir: Path) -> set[str]:
    activity = load_activity(dataset_dir / "system_activity.csv")
    identity_changes = load_identity_changes(dataset_dir / "user_audit_log.csv")
    evidence = EvidenceParser(dataset_dir).parse_all()
    return {
        *(item.evidence_id for item in evidence),
        *(event.activity_id for event in activity),
        *(change.audit_id for change in identity_changes),
    }


def write_output_csv(
    dataset_dir: Path,
    output_path: Path | None = None,
) -> Path:
    """Validate and atomically write the complete output CSV."""

    destination = (
        output_path.resolve()
        if output_path is not None
        else Path(__file__).resolve().parents[1] / "output.csv"
    )
    records = run_pipeline(dataset_dir)
    validated = validate_pipeline_results(
        records,
        _load_provenance_ids(dataset_dir.resolve()),
    )
    validated = tuple(sorted(validated, key=_case_sort_key))

    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            writer = csv.writer(
                handle,
                delimiter=",",
                quoting=csv.QUOTE_MINIMAL,
                lineterminator="\n",
            )
            writer.writerow(("case_id", "deletion_status", "steps_json"))
            for record in validated:
                writer.writerow(
                    (
                        record["case_id"],
                        record["deletion_status"],
                        json.dumps(
                            record["steps_json"],
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ),
                    )
                )
        os.replace(temporary_path, destination)
    except (OSError, ValueError):
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
        raise
    return destination


def load_phase1_inputs(dataset_dir: Path) -> dict[str, list[object]]:
    """Backward-compatible access to the validated Phase 1 CSV inputs."""

    return load_all(dataset_dir)


def _default_dataset_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "dataset"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate the full deletion-request dataset in memory."
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=_default_dataset_dir(),
        help="participant-facing dataset directory (default: repository dataset/)",
    )
    parser.add_argument(
        "--request-file",
        default="deletion_requests.csv",
        help="request CSV filename inside --dataset-dir",
    )
    parser.add_argument(
        "--output-csv",
        type=Path,
        help="atomically generate the validated output CSV at this path",
    )
    args = parser.parse_args(argv)
    try:
        if args.output_csv is not None:
            destination = write_output_csv(args.dataset_dir, args.output_csv)
            print(f"Wrote {destination}")
            return 0
        records = run_pipeline(args.dataset_dir, request_filename=args.request_file)
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"Pipeline validation failed: {exc}", file=sys.stderr)
        return 2
    status_counts: dict[str, int] = {}
    for record in records:
        status = record["deletion_status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    print(f"Processed {len(records)} requests in memory.")
    print("Statuses: " + ", ".join(
        f"{status}={status_counts[status]}" for status in sorted(status_counts)
    ))
    return 0


__all__ = [
    "build_identity_index",
    "classify_request",
    "load_phase1_inputs",
    "main",
    "run_pipeline",
    "validate_pipeline_results",
    "write_output_csv",
]


if __name__ == "__main__":
    raise SystemExit(main())
