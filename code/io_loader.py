"""Validated loading of participant-facing Phase 1 CSV inputs."""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from models import (
    DeletionRequest,
    DeletionRule,
    EvidenceManifestEntry,
    IdentityChange,
    SystemActivity,
    UserIdentity,
)


REQUEST_COLUMNS = (
    "case_id",
    "email",
    "requested_at",
    "reported_status",
    "reported_at",
    "audit_at",
    "request_text",
)
IDENTITY_COLUMNS = ("user_id", "name", "email", "phone", "email_hash", "updated_at")
AUDIT_COLUMNS = (
    "audit_id",
    "user_id",
    "event_time",
    "field_name",
    "old_value",
    "new_value",
)
ACTIVITY_COLUMNS = (
    "activity_id",
    "event_time",
    "event_type",
    "source_system",
    "target_system",
    "resource_id",
    "reported_result",
    "details",
)
RULE_COLUMNS = ("rule_id", "data_category", "condition", "required_action")
EVIDENCE_COLUMNS = ("file_id", "file_path", "origin", "captured_at")


def parse_timestamp(value: str, *, field_name: str = "timestamp") -> datetime:
    """Parse an ISO-8601 timestamp and always return an aware UTC datetime."""

    text = value.strip()
    if not text:
        raise ValueError(f"{field_name} must not be empty")
    normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field_name} is not a valid ISO-8601 timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone offset: {value!r}")
    return parsed.astimezone(timezone.utc)


def _read_csv(path: Path, required_columns: Sequence[str]) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"{path} has no header row")
        actual = tuple(name.strip() for name in reader.fieldnames)
        missing = [name for name in required_columns if name not in actual]
        if missing:
            raise ValueError(f"{path} is missing required columns: {', '.join(missing)}")
        rows: list[dict[str, str]] = []
        for line_number, raw_row in enumerate(reader, start=2):
            if None in raw_row:
                raise ValueError(f"{path} row {line_number} has too many columns")
            row = {key: (value or "").strip() for key, value in raw_row.items()}
            if any(not row[column] for column in required_columns):
                empty = [column for column in required_columns if not row[column]]
                raise ValueError(f"{path} row {line_number} has empty columns: {', '.join(empty)}")
            rows.append(row)
    return rows


def _require_unique(rows: Sequence[Mapping[str, str]], column: str, path: Path) -> None:
    seen: set[str] = set()
    for row in rows:
        value = row[column]
        if value in seen:
            raise ValueError(f"{path} contains duplicate {column}: {value!r}")
        seen.add(value)


def load_requests(path: Path) -> list[DeletionRequest]:
    rows = _read_csv(path, REQUEST_COLUMNS)
    _require_unique(rows, "case_id", path)
    return [
        DeletionRequest(
            case_id=row["case_id"],
            email=row["email"],
            requested_at=parse_timestamp(row["requested_at"], field_name="requested_at"),
            reported_status=row["reported_status"],
            reported_at=parse_timestamp(row["reported_at"], field_name="reported_at"),
            audit_at=parse_timestamp(row["audit_at"], field_name="audit_at"),
            request_text=row["request_text"],
        )
        for row in _read_csv(path, REQUEST_COLUMNS)
    ]


def load_identities(path: Path) -> list[UserIdentity]:
    rows = _read_csv(path, IDENTITY_COLUMNS)
    _require_unique(rows, "user_id", path)
    return [
        UserIdentity(
            user_id=row["user_id"],
            name=row["name"],
            email=row["email"],
            phone=row["phone"],
            email_hash=row["email_hash"],
            updated_at=parse_timestamp(row["updated_at"], field_name="updated_at"),
        )
        for row in _read_csv(path, IDENTITY_COLUMNS)
    ]


def load_identity_changes(path: Path) -> list[IdentityChange]:
    rows = _read_csv(path, AUDIT_COLUMNS)
    _require_unique(rows, "audit_id", path)
    return [
        IdentityChange(
            audit_id=row["audit_id"],
            user_id=row["user_id"],
            event_time=parse_timestamp(row["event_time"], field_name="event_time"),
            field_name=row["field_name"],
            old_value=row["old_value"],
            new_value=row["new_value"],
        )
        for row in _read_csv(path, AUDIT_COLUMNS)
    ]


def load_activity(path: Path) -> list[SystemActivity]:
    rows = _read_csv(path, ACTIVITY_COLUMNS)
    _require_unique(rows, "activity_id", path)
    return [
        SystemActivity(
            activity_id=row["activity_id"],
            event_time=parse_timestamp(row["event_time"], field_name="event_time"),
            event_type=row["event_type"],
            source_system=row["source_system"],
            target_system=row["target_system"],
            resource_id=row["resource_id"],
            reported_result=row["reported_result"],
            details=row["details"],
        )
        for row in _read_csv(path, ACTIVITY_COLUMNS)
    ]


def load_rules(path: Path) -> list[DeletionRule]:
    rows = _read_csv(path, RULE_COLUMNS)
    _require_unique(rows, "rule_id", path)
    return [
        DeletionRule(
            rule_id=row["rule_id"],
            data_category=row["data_category"],
            condition=row["condition"],
            required_action=row["required_action"],
        )
        for row in _read_csv(path, RULE_COLUMNS)
    ]


def load_evidence_manifest(path: Path) -> list[EvidenceManifestEntry]:
    rows = _read_csv(path, EVIDENCE_COLUMNS)
    _require_unique(rows, "file_id", path)
    return [
        EvidenceManifestEntry(
            file_id=row["file_id"],
            file_path=row["file_path"],
            origin=row["origin"],
            captured_at=parse_timestamp(row["captured_at"], field_name="captured_at"),
        )
        for row in _read_csv(path, EVIDENCE_COLUMNS)
    ]


def load_all(dataset_dir: Path) -> dict[str, list[object]]:
    """Load all Phase 1 CSVs without interpreting evidence or producing output."""

    return {
        "requests": load_requests(dataset_dir / "deletion_requests.csv"),
        "identities": load_identities(dataset_dir / "user_identities.csv"),
        "identity_changes": load_identity_changes(dataset_dir / "user_audit_log.csv"),
        "activity": load_activity(dataset_dir / "system_activity.csv"),
        "rules": load_rules(dataset_dir / "deletion_rules.csv"),
        "evidence_manifest": load_evidence_manifest(dataset_dir / "evidence_files.csv"),
    }
