"""Deterministic, provenance-preserving parsers for participant evidence."""

from __future__ import annotations

import csv
import base64
import json
import re
import sqlite3
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from io_loader import parse_timestamp
from models import EvidenceItem, EvidenceManifestEntry


_EVENT_TIMESTAMP_KEYS = (
    "event_time",
    "timestamp",
    "occurred_at",
    "recorded_at",
    "created_at",
    "observed_at",
)
_TIMESTAMP_KEYS = _EVENT_TIMESTAMP_KEYS + (
    "captured_at",
    "exported_at",
)
_SOURCE_KEYS = ("source_system", "source", "system", "service", "data_store")
_TARGET_KEYS = ("target_system", "target", "destination")
_RESOURCE_KEYS = ("resource_id", "record_id", "document_id", "object_id")
_OPERATION_KEYS = ("operation", "event_type", "event", "action", "record_type")
_OUTCOME_KEYS = ("reported_outcome", "reported_result", "result", "outcome", "status")
_IDENTIFIER_KEYS = {
    "user_id",
    "customer_reference",
    "subject_reference",
    "email",
    "email_hash",
    "phone",
    "lookup_key",
    "subject_key",
    "subject_ref",
    "query",
    "customer_email",
    "requester_email",
    "owner_email",
    "correlation_key",
}
_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})\b"
)
_DATE_LIKE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T[^\s|]+\b")
_KEY_VALUE_RE = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\"[^\"]*\"|'[^']*'|\S+)")


def parse_manifest(path: Path) -> tuple[EvidenceManifestEntry, ...]:
    """Load and validate the official evidence manifest without inspecting content."""

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    required = {"file_id", "file_path", "origin", "captured_at"}
    if not rows or set(rows[0]) < required:
        raise ValueError(f"{path} is missing required evidence manifest columns")
    entries = tuple(
        EvidenceManifestEntry(
            file_id=row["file_id"],
            file_path=row["file_path"],
            origin=row["origin"],
            captured_at=parse_timestamp(row["captured_at"], field_name="captured_at"),
        )
        for row in rows
    )
    if len({entry.file_id for entry in entries}) != len(entries):
        raise ValueError(f"{path} contains duplicate evidence IDs")
    return entries


def _first(mapping: Mapping[str, Any], keys: Iterable[str]) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value)
    return None


def _timestamp(mapping: Mapping[str, Any]) -> datetime | None:
    for key in _EVENT_TIMESTAMP_KEYS:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            try:
                return parse_timestamp(value, field_name=key)
            except ValueError:
                continue
    return None


def _timestamp_warnings(mapping: Mapping[str, Any]) -> list[str]:
    warnings = []
    for key in _TIMESTAMP_KEYS:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            try:
                parse_timestamp(value, field_name=key)
            except ValueError as exc:
                warnings.append(f"Malformed timestamp: {exc}")
    return warnings


def _identifiers(mapping: Mapping[str, Any]) -> tuple[str, ...]:
    values = {
        str(value).strip()
        for key, value in mapping.items()
        if key.casefold() in _IDENTIFIER_KEYS
        and isinstance(value, (str, int, float))
        and str(value).strip()
    }
    return tuple(sorted(values))


def _claims(mapping: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        f"{key}={json.dumps(value, ensure_ascii=False, sort_keys=True)}"
        for key, value in sorted(mapping.items())
        if isinstance(value, (str, int, float, bool)) or value is None
    )


def _item(
    entry: EvidenceManifestEntry,
    *,
    payload: Mapping[str, Any],
    warning: str | None = None,
    event_time: datetime | None = None,
    source_system: str | None = None,
    target_system: str | None = None,
    resource_id: str | None = None,
    operation: str | None = None,
    reported_outcome: str | None = None,
    warnings: Iterable[str] = (),
    directly_observed: bool = True,
    inferred: bool = False,
) -> EvidenceItem:
    warning_values = list(warnings)
    if warning:
        warning_values.insert(0, warning)
    warning_values.extend(_timestamp_warnings(payload))
    if (
        operation is not None or _first(payload, _OPERATION_KEYS) is not None
    ) and reported_outcome is None and _first(payload, _OUTCOME_KEYS) is None:
        warning_values.append("Observation has no explicit outcome")
    return EvidenceItem(
        evidence_id=entry.file_id,
        source_path=entry.file_path,
        origin=entry.origin,
        captured_at=entry.captured_at,
        event_time=event_time if event_time is not None else _timestamp(payload),
        source_system=source_system if source_system is not None else _first(payload, _SOURCE_KEYS),
        target_system=target_system if target_system is not None else _first(payload, _TARGET_KEYS),
        resource_id=resource_id if resource_id is not None else _first(payload, _RESOURCE_KEYS),
        operation=operation if operation is not None else _first(payload, _OPERATION_KEYS),
        reported_outcome=(
            reported_outcome
            if reported_outcome is not None
            else _first(payload, _OUTCOME_KEYS)
        ),
        claims=_claims(payload),
        identifiers=_identifiers(payload),
        payload=dict(payload),
        warnings=tuple(dict.fromkeys(warning_values)),
        directly_observed=directly_observed,
        inferred=inferred,
    )


def _json_items(
    entry: EvidenceManifestEntry,
    value: Any,
    context: Mapping[str, Any] | None = None,
) -> list[EvidenceItem]:
    if isinstance(value, dict):
        inherited = dict(context or {})
        for key in (*_TIMESTAMP_KEYS, *_SOURCE_KEYS, *_TARGET_KEYS):
            if key in value:
                inherited[key] = value[key]
        payload = dict(inherited)
        payload.update(value)
        items: list[EvidenceItem] = []
        if any(key in payload for key in (*_RESOURCE_KEYS, *_IDENTIFIER_KEYS, *_OPERATION_KEYS)):
            items.append(_item(entry, payload=payload))
        for child in value.values():
            items.extend(_json_items(entry, child, inherited))
        return items
    if isinstance(value, list):
        items = []
        for child in value:
            items.extend(_json_items(entry, child, context))
        return items
    return []


def _parse_json(entry: EvidenceManifestEntry, path: Path) -> list[EvidenceItem]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [_item(entry, payload={}, warning=f"JSON parse failed: {exc}")]
    items = _json_items(entry, value)
    if not items:
        items.append(_item(entry, payload={"document": value}))
    return items


def _parse_sql(entry: EvidenceManifestEntry, path: Path) -> list[EvidenceItem]:
    statements: list[str] = []
    try:
        script = path.read_text(encoding="utf-8")
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.set_trace_callback(statements.append)
        try:
            connection.executescript(script)
            tables = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            ).fetchall()
            items: list[EvidenceItem] = [
                _item(
                    entry,
                    payload={
                        "_observation_kind": "SQL_STATEMENT",
                        "_sql_statement": statement,
                        "_statement_type": statement.split(None, 1)[0].upper()
                        if statement.split()
                        else "",
                    },
                    operation=(
                        statement.split(None, 1)[0].upper()
                        if statement.split()
                        else None
                    ),
                    warning=(
                        "SQL statement execution does not establish original system state"
                        if statement.lstrip().upper().startswith(
                            ("DELETE", "UPDATE", "INSERT", "REPLACE")
                        )
                        else None
                    ),
                )
                for statement in statements
            ]
            for table_row in tables:
                table = table_row["name"]
                quoted = '"' + table.replace('"', '""') + '"'
                rows = connection.execute(f"SELECT * FROM {quoted}").fetchall()
                if not rows:
                    items.append(
                        _item(
                            entry,
                            payload={
                                "_observation_kind": "SQL_TABLE",
                                "_table": table,
                                "_row_count": 0,
                            },
                            warning=(
                                "Empty executed table is not evidence of the original "
                                "system state"
                            ),
                            directly_observed=False,
                            inferred=True,
                        )
                    )
                for row in rows:
                    payload = dict(row)
                    payload["_table"] = table
                    payload["_observation_kind"] = "SQL_ROW"
                    items.append(
                        _item(
                            entry,
                            payload=payload,
                            directly_observed=False,
                            inferred=True,
                        )
                    )
            if not items:
                items.append(
                    _item(
                        entry,
                        payload={"_observation_kind": "SQL_SCRIPT", "_sql_tables": []},
                        warning="SQL script produced no observable rows or statements",
                    )
                )
            return items
        finally:
            connection.close()
    except (OSError, UnicodeError, sqlite3.Error) as exc:
        payload = {
            "_observation_kind": "SQL_EXECUTION_ERROR",
            "_sql_statements": tuple(statements),
            "_execution_error": str(exc),
        }
        return [
            _item(
                entry,
                payload=payload,
                warning=f"SQL execution failed; results may be partial: {exc}",
                directly_observed=False,
                inferred=True,
            )
        ]


def _parse_log_or_text(entry: EvidenceManifestEntry, path: Path) -> list[EvidenceItem]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        return [_item(entry, payload={}, warning=f"Text read failed: {exc}")]
    items: list[EvidenceItem] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        fields: dict[str, Any] = {"_line": line_number, "message": line}
        matches = list(_KEY_VALUE_RE.finditer(line))
        for match in matches:
            value = match.group("value").strip("\"'")
            fields[match.group("key")] = value
        if not matches and "|" in line:
            parts = [part.strip() for part in line.split("|")]
            if len(parts) >= 5 and _TIMESTAMP_RE.search(parts[0]):
                fields.update(
                    event_time=parts[0],
                    source_system=parts[1],
                    resource_id=parts[2],
                    operation=parts[3],
                    reported_outcome=parts[4],
                )
                if len(parts) >= 6 and parts[5] and parts[5].casefold() != "no direct identifier":
                    fields["lookup_key"] = parts[5]
        timestamp_match = _TIMESTAMP_RE.search(line)
        if timestamp_match and "event_time" not in fields:
            fields["event_time"] = timestamp_match.group(0)
        warnings = []
        if _DATE_LIKE_RE.search(line) and timestamp_match is None:
            warnings.append("Malformed timestamp in text record")
        if "|" in line and not matches and len(line.split("|")) < 5:
            warnings.append("Malformed pipe-delimited text record")
        items.append(_item(entry, payload=fields, warnings=warnings))
    if not items:
        items.append(_item(entry, payload={}, warning="No structured events found in text"))
    return items


def _parse_pdf(entry: EvidenceManifestEntry, path: Path) -> list[EvidenceItem]:
    try:
        raw_pdf = path.read_bytes()
    except (OSError, UnicodeError) as exc:
        return [_item(entry, payload={}, warning=f"PDF read failed: {exc}")]

    text_parts: list[str] = []
    for match in re.finditer(rb"stream\r?\n", raw_pdf):
        end = raw_pdf.find(b"endstream", match.end())
        if end < 0:
            continue
        stream = raw_pdf[match.end():end]
        header = raw_pdf[max(0, match.start() - 180):match.start()]
        try:
            if b"/ASCII85Decode" in header:
                stream = base64.a85decode(stream, adobe=True)
            if b"/FlateDecode" in header:
                stream = zlib.decompress(stream)
        except (ValueError, zlib.error):
            continue
        decoded = stream.decode("latin-1", errors="ignore")
        text_parts.extend(
            bytes(match.group(1), "latin-1").decode(
                "unicode_escape", errors="ignore"
            )
            for match in re.finditer(r"\((.*?)(?<!\\)\)\s*Tj", decoded)
        )
    stdlib_text = "\n".join(text_parts).strip()
    if stdlib_text:
        payload: dict[str, Any] = {"text": stdlib_text}
        resource = re.search(r"\b(?:support|attachment|account|export)_\d+\b", stdlib_text)
        email = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", stdlib_text)
        phone = re.search(r"(?<!\d)\+\d[\d ]{7,}\d(?!\d)", stdlib_text)
        if resource:
            payload["resource_id"] = resource.group(0)
        if email:
            payload["email"] = email.group(0)
        if phone:
            payload["phone"] = phone.group(0)
        if "attachment" in stdlib_text.casefold():
            payload["data_category"] = "SUPPORT_ATTACHMENT"
        return [_item(entry, payload=payload)]

    try:
        from pypdf import PdfReader
    except ImportError:
        return [_item(entry, payload={}, warning="PDF text extraction unavailable: pypdf is not installed")]
    try:
        text = "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
    except Exception as exc:
        return [_item(entry, payload={}, warning=f"PDF text extraction failed: {exc}")]
    if not text.strip():
        return [_item(entry, payload={}, warning="PDF contained no extractable text")]
    return [_item(entry, payload={"text": text})]


def _parse_binary(entry: EvidenceManifestEntry, path: Path) -> list[EvidenceItem]:
    return [_item(entry, payload={}, warning=f"Binary image not parsed: {path.suffix.lower()} content retained as metadata")]


def parse_evidence_file(entry: EvidenceManifestEntry, dataset_dir: Path) -> tuple[EvidenceItem, ...]:
    """Parse one manifest entry; failures become explicit warning-bearing items."""

    path = dataset_dir / entry.file_path
    if not path.is_file():
        return (_item(entry, payload={}, warning=f"Evidence file is missing: {entry.file_path}"),)
    suffix = path.suffix.casefold()
    if suffix == ".json":
        return tuple(_parse_json(entry, path))
    if suffix == ".sql":
        return tuple(_parse_sql(entry, path))
    if suffix in {".log", ".txt"}:
        return tuple(_parse_log_or_text(entry, path))
    if suffix == ".pdf":
        return tuple(_parse_pdf(entry, path))
    if suffix == ".png":
        return tuple(_parse_binary(entry, path))
    return (_item(entry, payload={}, warning=f"Unsupported evidence type: {suffix or 'no extension'}"),)


class EvidenceParser:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self.entries = parse_manifest(dataset_dir / "evidence_files.csv")

    def parse_all(self) -> tuple[EvidenceItem, ...]:
        items: list[EvidenceItem] = []
        for entry in self.entries:
            items.extend(parse_evidence_file(entry, self.dataset_dir))
        return tuple(items)


def filter_by_audit_cutoff(
    items: Iterable[EvidenceItem],
    audit_at: datetime,
) -> tuple[EvidenceItem, ...]:
    """Keep only artifacts captured at or before the audit cutoff."""

    if audit_at.tzinfo is None or audit_at.utcoffset() is None:
        raise ValueError("audit_at must include a timezone offset")
    audit_at = audit_at.astimezone(timezone.utc)
    filtered: list[EvidenceItem] = []
    for item in items:
        if item.captured_at.tzinfo is None or item.captured_at.utcoffset() is None:
            raise ValueError(f"evidence {item.evidence_id} has a naive capture timestamp")
        captured_at = item.captured_at.astimezone(timezone.utc)
        if captured_at <= audit_at:
            filtered.append(item)
    return tuple(filtered)
