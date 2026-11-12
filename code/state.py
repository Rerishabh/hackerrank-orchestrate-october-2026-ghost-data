"""Phase 3 state reconstruction and deterministic policy evaluation."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from authorization import classify_request
from evidence.parser import filter_by_audit_cutoff
from identity import normalize_email, normalize_email_hash, normalize_phone, resolve_subject
from models import (
    DeletionRequest,
    DeletionRule,
    EvidenceItem,
    PlanStep,
    StateEvaluation,
    SubjectIdentity,
    SystemActivity,
)
from policy import ACTION_TO_REMEDIATION, OPERATION_ORDER, POLICY_ACTIONS


_POSITIVE = {"PRESENT", "FOUND", "SUCCESS", "ACTIVE", "200", "1", "HIT", "TRUE"}
_NEGATIVE = {"ABSENT", "NOT_FOUND", "FAILED", "404", "FALSE", "0", "REDACTED", "ANONYMIZED"}
_RESOURCE_PREFIXES = {
    "account_": "USER_PROFILE",
    "search_": "SEARCH_INDEX_ENTRY",
    "cache_": "CACHE_ENTRY",
    "support_": "SUPPORT_MESSAGE",
    "attachment_": "SUPPORT_ATTACHMENT",
    "export_": "USER_EXPORT",
    "analytics_": "ANALYTICS_PROFILE",
    "telemetry_": "PRODUCT_TELEMETRY",
    "email_delivery_": "EMAIL_DELIVERY_LOG",
    "audit_record_": "SECURITY_AUDIT_LOG",
    "backup_": "BACKUP_ARCHIVE",
    "tombstone_": "ACCOUNT_TOMBSTONE",
    "marketing_": "MARKETING_PROFILE",
}
_RESOURCE_SYSTEMS = {
    "account_": "account_service",
    "search_": "search_service",
    "cache_": "cache_service",
    "support_": "support_platform",
    "attachment_": "support_platform",
    "export_": "export_service",
    "analytics_": "analytics_platform",
    "telemetry_": "analytics_platform",
    "email_delivery_": "email_service",
    "audit_record_": "security_service",
    "backup_": "backup_service",
    "tombstone_": "identity_service",
    "marketing_": "marketing_service",
    "data_flow_": "integration_service",
}


def _normalize(value: str) -> set[str]:
    raw = value.strip()
    variants = {
        raw,
        raw.casefold(),
    }
    if "@" in raw:
        variants.add(normalize_email(raw))
    elif len(raw) >= 32 and all(character in "0123456789abcdefABCDEF" for character in raw):
        variants.add(normalize_email_hash(raw))
    elif sum(character.isdigit() for character in raw) >= 7:
        variants.add(normalize_phone(raw))
    return variants - {""}


def _flatten_strings(value: Any) -> Iterable[str]:
    if isinstance(value, Mapping):
        for child in value.values():
            yield from _flatten_strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _flatten_strings(child)
    elif isinstance(value, str):
        yield value


def _identifier_values(value: Any, key: str | None = None) -> Iterable[str]:
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            if child_key.casefold() in {
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
            }:
                if isinstance(child, (str, int, float)) and str(child).strip().lower() != "null":
                    yield str(child)
            yield from _identifier_values(child, child_key)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _identifier_values(child, key)
    elif isinstance(value, str):
        try:
            decoded = __import__("json").loads(value)
        except (TypeError, ValueError):
            return
        yield from _identifier_values(decoded, key)


def _nested_mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for child in value.values():
            yield from _nested_mappings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _nested_mappings(child)
    elif isinstance(value, str):
        try:
            decoded = __import__("json").loads(value)
        except (TypeError, ValueError):
            return
        yield from _nested_mappings(decoded)


def _item_matches_subject(item: EvidenceItem, subject: SubjectIdentity) -> bool:
    identifiers = set(subject.all_identifiers)
    haystack = list(item.identifiers) + list(_identifier_values(item.payload))
    normalized_haystack = set().union(*(_normalize(value) for value in haystack)) if haystack else set()
    for identifier in identifiers:
        if _normalize(identifier) & normalized_haystack:
            return True
    user_id = subject.user_id.casefold()
    return user_id in {value.casefold() for value in haystack}


def _activity_matches_subject(activity: SystemActivity, subject: SubjectIdentity) -> bool:
    identifiers = set(subject.all_identifiers) | {subject.user_id}
    text = f"{activity.resource_id} {activity.details}".casefold()
    return any(identifier.casefold() in text for identifier in identifiers)


def _first(payload: Mapping[str, Any], keys: Iterable[str]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value)
    return None


def _category(item: EvidenceItem) -> str | None:
    payload = item.payload
    explicit = _first(payload, ("data_category", "category", "record_type", "collection"))
    if explicit:
        upper = explicit.upper()
        for category in POLICY_ACTIONS:
            if category in upper:
                return category
    operation = (item.operation or "").upper()
    for category in POLICY_ACTIONS:
        if operation == category:
            return category
    resource = item.resource_id or ""
    if resource.startswith("data_flow_"):
        return None
    for prefix, category in _RESOURCE_PREFIXES.items():
        if resource.startswith(prefix):
            return category
    target = (item.target_system or "").casefold()
    if target == "search_service":
        return "SEARCH_INDEX_ENTRY"
    if target == "cache_service":
        return "CACHE_ENTRY"
    if target == "analytics_platform":
        return "ANALYTICS_PROFILE"
    return None


def _outcome(item: EvidenceItem) -> str | None:
    values = []
    if item.reported_outcome:
        values.append(item.reported_outcome)
    values.extend(
        str(value)
        for mapping in _nested_mappings(item.payload)
        for key, value in mapping.items()
        if key in {
            "status",
            "result",
            "rows",
            "http_status",
            "status_code",
            "download_available",
            "account_status",
            "enabled",
            "last_delivery_status",
            "restore_allowed",
        }
    )
    if any(value.upper() in {"IDENTIFIABLE", "EXPOSED", "PII_PRESENT"} for value in values):
        return "PRESENT"
    for value in values:
        upper = value.upper()
        if upper == "FALSE" and item.resource_id and item.resource_id.startswith("backup_"):
            return "BLOCKED"
        if upper == "FALSE" and item.resource_id and item.resource_id.startswith("data_flow_"):
            return "DISABLED"
        if upper in _NEGATIVE:
            return "ABSENT" if upper in {"NOT_FOUND", "404", "0", "FALSE"} else upper
        if upper in _POSITIVE:
            return "PRESENT" if upper in {"FOUND", "200", "1", "TRUE"} else upper
    nested = list(_nested_mappings(item.payload))
    if item.resource_id and item.resource_id.startswith("analytics_"):
        identifier_values = [
            mapping[key]
            for mapping in nested
            for key in ("customer_reference", "email", "phone", "email_hash")
            if key in mapping
        ]
        if any(value not in (None, "", "null") for value in identifier_values):
            return "PRESENT"
    if any(mapping.get(key) for mapping in nested for key in
           ("email", "phone", "email_hash")):
        return "PRESENT"
    if item.resource_id and item.resource_id.startswith("analytics_"):
        if identifier_values and all(value in (None, "", "null") for value in identifier_values):
            return "ANONYMIZED"
    if item.operation and "analytics_profile_read_completed" in item.operation:
        identifier_values = [
            item.payload[key]
            for key in ("customer_reference", "email", "phone", "email_hash")
            if key in item.payload
        ]
        if identifier_values and all(value in (None, "", "null") for value in identifier_values):
            return "ANONYMIZED"
    if item.operation and "support_ticket_read_completed" in item.operation:
        if all(item.payload.get(key) in (None, "", "null") for key in
               ("requester_name", "requester_email", "requester_phone")):
            return "REDACTED"
    if item.payload.get("message_text") == "[REDACTED]":
        return "REDACTED"
    if item.resource_id and item.resource_id.startswith("support_"):
        if all(
            item.payload.get(key) in (None, "", "null")
            for key in ("requester_name", "requester_email", "requester_phone")
        ) and any(key in item.payload for key in ("requester_name", "requester_email", "requester_phone")):
            return "REDACTED"
    if item.resource_id and item.resource_id.startswith("tombstone_"):
        if (
            str(item.payload.get("account_status", "")).upper() == "DELETED"
            and all(item.payload.get(key) in (None, "", "null")
                    for key in ("name", "email", "phone", "email_hash"))
        ):
            return "REDACTED"
    return None


def _system(item: EvidenceItem) -> str:
    resource_system = next(
        (
            system
            for prefix, system in _RESOURCE_SYSTEMS.items()
            if (item.resource_id or "").startswith(prefix)
        ),
        None,
    )
    return (
        resource_system
        or item.payload.get("data_store")
        or item.payload.get("service")
        or item.target_system
        or item.source_system
        or "unknown_system"
    )


def _system_for_resource(resource_id: str, fallback: str | None) -> str:
    for prefix, system in _RESOURCE_SYSTEMS.items():
        if resource_id.startswith(prefix):
            return system
    return fallback or "unknown_system"


def _resource(item: EvidenceItem) -> str:
    return item.resource_id or "unknown_resource"


def _is_active_flow(item: EvidenceItem) -> bool:
    enabled = str(item.payload.get("enabled", "")).casefold()
    delivery = str(item.payload.get("last_delivery_status", "")).casefold()
    outcome = (_outcome(item) or "").casefold()
    return (
        enabled in {"true", "1"}
        or delivery in {"delivered", "active", "running"}
        or outcome == "active"
    )


def _is_disabled_flow(item: EvidenceItem) -> bool:
    enabled = str(item.payload.get("enabled", "")).casefold()
    delivery = str(item.payload.get("last_delivery_status", "")).casefold()
    return enabled in {"false", "0"} or delivery in {"stopped", "disabled"}


def _is_restore_risk(item: EvidenceItem) -> bool:
    allowed = str(item.payload.get("restore_allowed", "")).casefold()
    eligible = str(item.payload.get("eligible", "")).casefold()
    blocked = str(item.payload.get("deletion_block", "")).casefold()
    return (
        item.operation == "RESTORE_BACKUP"
        or (item.resource_id or "").startswith("backup_")
        and allowed in {"true", "1"}
        or (
            item.resource_id is not None
            and item.resource_id.startswith("backup_")
            and eligible in {"true", "1"}
            and blocked in {"false", "0"}
        )
    )


def _is_restore_blocked(item: EvidenceItem) -> bool:
    allowed = str(item.payload.get("restore_allowed", "")).casefold()
    return allowed in {"false", "0"} or str(
        item.payload.get("deletion_block", "")
    ).casefold() in {"true", "1"}


def _observation_rank(item: EvidenceItem) -> tuple[int, int, datetime]:
    outcome = _outcome(item)
    explicit = 1 if outcome is not None else 0
    completed = 1 if "completed" in (item.operation or "").casefold() else 0
    return (explicit, completed, item.event_time or item.captured_at)


def _select_observations(items: Iterable[EvidenceItem]) -> tuple[EvidenceItem, ...]:
    grouped: dict[tuple[str, str], EvidenceItem] = {}
    for item in items:
        if not item.resource_id:
            continue
        key = (item.evidence_id, item.resource_id)
        previous = grouped.get(key)
        if previous is None or _observation_rank(item) > _observation_rank(previous):
            grouped[key] = item
    return tuple(sorted(
        grouped.values(),
        key=lambda item: (
            item.evidence_id,
            item.event_time or item.captured_at,
            item.source_system or "",
            item.resource_id or "",
        ),
    ))


def _expand_artifact_context(
    direct: tuple[EvidenceItem, ...],
    eligible: tuple[EvidenceItem, ...],
) -> tuple[EvidenceItem, ...]:
    """Correlate nearby records in a directly anchored snapshot or trace."""

    anchors: dict[str, list[datetime]] = {}
    direct_categories: dict[str, set[str]] = {}
    direct_traces: dict[str, set[str]] = {}
    for item in direct:
        if item.event_time is not None:
            anchors.setdefault(item.evidence_id, []).append(item.event_time)
        category = _category(item)
        if category:
            direct_categories.setdefault(item.evidence_id, set()).add(category)
        trace_id = item.payload.get("trace_id")
        if isinstance(trace_id, str) and trace_id:
            direct_traces.setdefault(item.evidence_id, set()).add(trace_id)
    expanded = list(direct)
    for evidence_id, anchor_times in anchors.items():
        latest_anchor = max(anchor_times)
        candidates: dict[str, list[EvidenceItem]] = {}
        for item in eligible:
            category = _category(item)
            if (
                not item.resource_id
                or item.evidence_id != evidence_id
                or item.event_time is None
                or abs((item.event_time - latest_anchor).total_seconds()) > 45 * 60
            ):
                continue
            if any(
                direct_item.evidence_id == item.evidence_id
                and direct_item.resource_id == item.resource_id
                for direct_item in direct
            ):
                expanded.append(item)
                continue
            if (
                item.payload.get("trace_id") in direct_traces.get(evidence_id, set())
                and item.resource_id
            ):
                expanded.append(item)
                continue
            if category in direct_categories.get(evidence_id, set()):
                continue
            if category not in {
                "USER_PROFILE",
                "ANALYTICS_PROFILE",
                "SECURITY_AUDIT_LOG",
                "ACCOUNT_TOMBSTONE",
            }:
                continue
            # A flow or archive is correlated only when its own identifier
            # directly anchors the subject; nearby unrelated controls are not
            # evidence of this subject's recreation risk.
            if item.resource_id.startswith(("data_flow_", "backup_")):
                continue
            candidate_outcome = _outcome(item)
            expected_outcomes = {
                "USER_PROFILE": {"ABSENT"},
                "ANALYTICS_PROFILE": {"ANONYMIZED"},
                "SECURITY_AUDIT_LOG": {"PRESENT", "SUCCESS"},
                "ACCOUNT_TOMBSTONE": {"REDACTED"},
            }
            if candidate_outcome not in expected_outcomes.get(category, set()):
                continue
            candidates.setdefault(category, []).append(item)
        for category_items in candidates.values():
            expanded.append(min(
                category_items,
                key=lambda item: (
                    abs((item.event_time - latest_anchor).total_seconds()),
                    item.resource_id or "",
                ),
            ))
    return _select_observations(expanded)


def _snapshot_absence_observations(
    subject: SubjectIdentity,
    eligible: tuple[EvidenceItem, ...],
    direct: tuple[EvidenceItem, ...],
) -> tuple[EvidenceItem, ...]:
    """Return only explicitly identified absence observations.

    A set of unrelated SQL rows does not identify the missing account record.
    In particular, deriving an account resource from a user's numeric suffix
    would fabricate provenance, so clean snapshots without an explicit lookup
    resource are intentionally not converted into plan steps.
    """

    return ()


def _step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> PlanStep:
    return PlanStep(0, phase, system_id, resource_id, operation, state, evidence_id)


def _sort_steps(steps: Iterable[PlanStep]) -> tuple[PlanStep, ...]:
    phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    ordered = sorted(
        steps,
        key=lambda step: (
            phase_order[step.phase],
            OPERATION_ORDER[step.operation],
            step.system_id,
            step.resource_id,
        ),
    )
    return tuple(
        PlanStep(
            number,
            step.phase,
            step.system_id,
            step.resource_id,
            step.operation,
            step.state,
            step.evidence_id,
        )
        for number, step in enumerate(ordered, start=1)
    )


def validate_plan_steps(steps: Iterable[PlanStep]) -> None:
    """Validate the public step schema and deterministic ordering contract."""

    phases = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    phase_operations = {
        "FINDING": {
            "REPORT_REMAINING_RECORD",
            "REPORT_EXPOSED_PII",
            "REPORT_ACTIVE_DATA_FLOW",
            "REPORT_RESTORE_RISK",
        },
        "REMEDIATION": {
            "DISABLE_DATA_FLOW",
            "BLOCK_RESTORE",
            "DELETE_RECORD",
            "REDACT_RECORD",
            "ANONYMIZE_RECORD",
        },
        "VERIFICATION": {
            "VERIFY_RECORD_ABSENT",
            "VERIFY_RECORD_PRESENT",
            "VERIFY_RECORD_REDACTED",
            "VERIFY_RECORD_ANONYMIZED",
            "VERIFY_DATA_FLOW_DISABLED",
            "VERIFY_RESTORE_BLOCKED",
        },
    }
    states_by_operation = {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    }
    ordered = tuple(steps)
    for number, step in enumerate(ordered, start=1):
        if step.step_no != number:
            raise ValueError("step numbers must be consecutive starting at 1")
        if step.phase not in phases:
            raise ValueError(f"unsupported phase: {step.phase}")
        if step.operation not in OPERATION_ORDER:
            raise ValueError(f"unsupported operation: {step.operation}")
        if step.operation not in phase_operations[step.phase]:
            raise ValueError(
                f"operation {step.operation} is invalid in phase {step.phase}"
            )
        if step.state != states_by_operation[step.operation]:
            raise ValueError(f"invalid state for {step.operation}: {step.state}")
        if step.phase == "REMEDIATION" and step.evidence_id:
            raise ValueError("remediation steps cannot cite evidence")
        if step.phase == "VERIFICATION" and step.evidence_id is None:
            raise ValueError("verification evidence_id must be a string")
    expected_order = tuple(
        sorted(
            ordered,
            key=lambda step: (
                phases[step.phase],
                OPERATION_ORDER[step.operation],
                step.system_id,
                step.resource_id,
            ),
        )
    )
    if ordered != expected_order:
        raise ValueError("steps violate deterministic phase and operation ordering")


def reconstruct_case(
    request: DeletionRequest,
    index: Any,
    evidence: Iterable[EvidenceItem],
    activity: Iterable[SystemActivity],
    rules: Iterable[DeletionRule] = (),
) -> StateEvaluation:
    """Reconstruct one case using only evidence available at its audit cutoff."""

    if not classify_request(request.request_text).authorized:
        return StateEvaluation(
            "NOT_APPLICABLE", (), None, (), ()
        )
    subject = resolve_subject(request.email, index, audit_at=request.audit_at)
    if subject is None:
        return StateEvaluation("INCOMPLETE", (), None, (), ())
    eligible = filter_by_audit_cutoff(evidence, request.audit_at)
    direct_evidence = tuple(item for item in eligible if _item_matches_subject(item, subject))
    matched_evidence = _expand_artifact_context(direct_evidence, eligible)
    matched_evidence = _select_observations(
        (*matched_evidence, *_snapshot_absence_observations(
            subject, eligible, matched_evidence
        ))
    )
    matched_activity = tuple(
        event for event in activity
        if event.event_time <= request.audit_at
        and (
            _activity_matches_subject(event, subject)
            or event.resource_id in {item.resource_id for item in matched_evidence}
        )
    )
    findings: list[PlanStep] = []
    remediation: list[PlanStep] = []
    verification: list[PlanStep] = []
    incomplete = False
    seen_resources: set[tuple[str, str]] = set()
    for item in matched_evidence:
        category = _category(item)
        action = POLICY_ACTIONS.get(category or "")
        if not category or not action:
            continue
        resource = _resource(item)
        key = (_system(item), resource)
        if key in seen_resources:
            continue
        seen_resources.add(key)
        outcome = _outcome(item)
        compliant = (
            (action == "DELETE" and outcome == "ABSENT")
            or (action == "REDACT" and outcome in {"REDACTED", "ABSENT"})
            or (action == "ANONYMIZE" and outcome == "ANONYMIZED")
            or (action == "RETAIN" and outcome in {"PRESENT", "SUCCESS"})
        )
        if not compliant and action != "RETAIN":
            incomplete = True
            finding_op = "REPORT_EXPOSED_PII" if action in {"REDACT", "ANONYMIZE"} else "REPORT_REMAINING_RECORD"
            findings.append(_step("FINDING", _system(item), resource, finding_op, "PRESENT", item.evidence_id))
            remediation_op, remediation_state, verify_op = ACTION_TO_REMEDIATION[action]
            remediation.append(_step("REMEDIATION", _system(item), resource, remediation_op, remediation_state, ""))
            verification.append(_step("VERIFICATION", _system(item), resource, verify_op, remediation_state, ""))
        else:
            if category == "BACKUP_ARCHIVE":
                continue
            verify_op = {
                "DELETE": "VERIFY_RECORD_ABSENT",
                "REDACT": "VERIFY_RECORD_REDACTED",
                "ANONYMIZE": "VERIFY_RECORD_ANONYMIZED",
                "RETAIN": "VERIFY_RECORD_PRESENT",
            }[action]
            verify_state = {
                "DELETE": "ABSENT",
                "REDACT": "REDACTED",
                "ANONYMIZE": "ANONYMIZED",
                "RETAIN": "PRESENT",
            }[action]
            verification.append(_step("VERIFICATION", _system(item), resource, verify_op, verify_state, item.evidence_id))
        if category == "BACKUP_ARCHIVE" and _is_restore_blocked(item):
            verification.append(_step(
                "VERIFICATION", _system(item), resource,
                "VERIFY_RESTORE_BLOCKED", "BLOCKED", item.evidence_id,
            ))
        if category == "ACCOUNT_TOMBSTONE" and outcome == "REDACTED":
            verification.append(_step(
                "VERIFICATION", _system(item), resource,
                "VERIFY_RECORD_REDACTED", "REDACTED", item.evidence_id,
            ))
    for item in matched_evidence:
        if not item.resource_id:
            continue
        if item.resource_id.startswith("data_flow_"):
            if _is_active_flow(item):
                incomplete = True
                findings.append(_step(
                    "FINDING", _system(item), item.resource_id,
                    "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", item.evidence_id,
                ))
                remediation.append(_step(
                    "REMEDIATION", _system(item), item.resource_id,
                    "DISABLE_DATA_FLOW", "DISABLED", "",
                ))
                verification.append(_step(
                    "VERIFICATION", _system(item), item.resource_id,
                    "VERIFY_DATA_FLOW_DISABLED", "DISABLED", "",
                ))
            elif _is_disabled_flow(item):
                verification.append(_step(
                    "VERIFICATION", _system(item), item.resource_id,
                    "VERIFY_DATA_FLOW_DISABLED", "DISABLED", item.evidence_id,
                ))
        if item.resource_id.startswith("backup_"):
            if _is_restore_risk(item):
                incomplete = True
                findings.append(_step(
                    "FINDING", _system(item), item.resource_id,
                    "REPORT_RESTORE_RISK", "ACTIVE", item.evidence_id,
                ))
                remediation.append(_step(
                    "REMEDIATION", _system(item), item.resource_id,
                    "BLOCK_RESTORE", "BLOCKED", "",
                ))
                verification.append(_step(
                    "VERIFICATION", _system(item), item.resource_id,
                    "VERIFY_RESTORE_BLOCKED", "BLOCKED", "",
                ))
            elif _is_restore_blocked(item):
                verification.append(_step(
                    "VERIFICATION", _system(item), item.resource_id,
                    "VERIFY_RESTORE_BLOCKED", "BLOCKED", item.evidence_id,
                ))
    for event in matched_activity:
        event_type = event.event_type.upper()
        if event_type in {"SYNC_RECORD", "INDEX_RECORD", "REFRESH_CACHE", "CHECK_DATA_FLOW"} and (
            event.reported_result == "SUCCESS"
            and any(flag in event.details.casefold() for flag in ("enabled=true", "delivered", "active", "running"))
        ):
            incomplete = True
            system = _system_for_resource(event.resource_id, event.target_system)
            findings.append(_step("FINDING", system, event.resource_id, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", event.activity_id))
            remediation.append(_step("REMEDIATION", system, event.resource_id, "DISABLE_DATA_FLOW", "DISABLED", ""))
            verification.append(_step("VERIFICATION", system, event.resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ""))
        if event_type in {"RESTORE_BACKUP", "CHECK_RESTORE_ACCESS"} and (
            event.reported_result == "SUCCESS"
            and (
                "restore_allowed=true" in event.details.casefold()
                or "restore_allowed=1" in event.details.casefold()
                or "can still be restored" in event.details.casefold()
                or event_type == "RESTORE_BACKUP"
            )
        ):
            incomplete = True
            system = _system_for_resource(event.resource_id, event.target_system)
            findings.append(_step("FINDING", system, event.resource_id, "REPORT_RESTORE_RISK", "ACTIVE", event.activity_id))
            remediation.append(_step("REMEDIATION", system, event.resource_id, "BLOCK_RESTORE", "BLOCKED", ""))
            verification.append(_step("VERIFICATION", system, event.resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", ""))
    unique_findings: dict[tuple[str, str, str], PlanStep] = {}
    unique_remediation: dict[tuple[str, str, str], PlanStep] = {}
    unique_verification: dict[tuple[str, str, str], PlanStep] = {}
    for step in findings:
        key = (step.system_id, step.resource_id, step.operation)
        previous = unique_findings.get(key)
        if previous is None or (
            not previous.evidence_id.startswith("evidence_")
            and step.evidence_id.startswith("evidence_")
        ):
            unique_findings[key] = step
    for step in remediation:
        unique_remediation.setdefault(
            (step.system_id, step.resource_id, step.operation), step
        )
    for step in verification:
        unique_verification.setdefault(
            (step.system_id, step.resource_id, step.operation), step
        )
    findings = list(unique_findings.values())
    remediation = list(unique_remediation.values())
    verification = list(unique_verification.values())
    if incomplete:
        verification = [
            PlanStep(
            step.step_no,
            step.phase,
            step.system_id,
            step.resource_id,
            step.operation,
            step.state,
            "",
            )
            for step in verification
        ]
        steps = _sort_steps([*findings, *remediation, *verification])
        validate_plan_steps(steps)
        return StateEvaluation("INCOMPLETE", steps, subject.user_id, matched_evidence, matched_activity)
    complete_steps = _sort_steps(verification)
    validate_plan_steps(complete_steps)
    return StateEvaluation("COMPLETE", complete_steps, subject.user_id, matched_evidence, matched_activity)


def steps_as_dicts(steps: Iterable[PlanStep]) -> list[dict[str, Any]]:
    return [
        {
            "step_no": step.step_no,
            "phase": step.phase,
            "system_id": step.system_id,
            "resource_id": step.resource_id,
            "operation": step.operation,
            "state": step.state,
            "evidence_id": step.evidence_id,
        }
        for step in steps
    ]
