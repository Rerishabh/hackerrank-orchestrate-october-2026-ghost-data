"""Typed Phase 1 domain models and official output vocabulary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Mapping


class DeletionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Phase(str, Enum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class State(str, Enum):
    PRESENT = "PRESENT"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    BLOCKED = "BLOCKED"
    ABSENT = "ABSENT"
    REDACTED = "REDACTED"
    ANONYMIZED = "ANONYMIZED"


class Operation(str, Enum):
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


@dataclass(frozen=True)
class DeletionRequest:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass(frozen=True)
class UserIdentity:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: datetime


@dataclass(frozen=True)
class IdentityChange:
    audit_id: str
    user_id: str
    event_time: datetime
    field_name: str
    old_value: str
    new_value: str


@dataclass(frozen=True)
class SystemActivity:
    activity_id: str
    event_time: datetime
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass(frozen=True)
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


@dataclass(frozen=True)
class EvidenceManifestEntry:
    file_id: str
    file_path: str
    origin: str
    captured_at: datetime


@dataclass(frozen=True)
class EvidenceItem:
    """A directly observed, provenance-linked fact from one evidence artifact."""

    evidence_id: str
    source_path: str
    origin: str
    captured_at: datetime
    event_time: datetime | None
    source_system: str | None
    target_system: str | None
    resource_id: str | None
    operation: str | None
    reported_outcome: str | None
    claims: tuple[str, ...]
    identifiers: tuple[str, ...]
    payload: Mapping[str, Any]
    warnings: tuple[str, ...] = ()
    directly_observed: bool = True
    inferred: bool = False


@dataclass(frozen=True)
class PlanStep:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str


@dataclass(frozen=True)
class StateEvaluation:
    status: DeletionStatus
    steps: tuple[PlanStep, ...]
    subject_id: str | None
    matched_evidence: tuple[EvidenceItem, ...]
    matched_activity: tuple[SystemActivity, ...]


@dataclass(frozen=True)
class SubjectIdentity:
    user_id: str
    current: UserIdentity
    historical_values: Mapping[str, tuple[str, ...]]
    all_identifiers: frozenset[str]


@dataclass(frozen=True)
class AuthorizationDecision:
    authorized: bool
    reason: str


@dataclass(frozen=True)
class CsvData:
    """Validated raw CSV rows, useful for callers not yet using typed models."""

    headers: tuple[str, ...]
    rows: tuple[Mapping[str, str], ...]


AnyRow = Mapping[str, Any]
