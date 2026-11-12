"""Current and historical identifier indexing and resolution."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Mapping

from models import IdentityChange, SubjectIdentity, UserIdentity


def normalize_email(value: str) -> str:
    return value.strip().casefold()


def normalize_phone(value: str) -> str:
    return re.sub(r"\D", "", value)


def normalize_email_hash(value: str) -> str:
    return value.strip().casefold()


def normalize_identifier(field_name: str, value: str) -> str:
    if field_name == "email":
        return normalize_email(value)
    if field_name == "phone":
        return normalize_phone(value)
    if field_name == "email_hash":
        return normalize_email_hash(value)
    return value.strip()


@dataclass(frozen=True)
class IdentifierIndex:
    by_field: Mapping[str, Mapping[str, frozenset[str]]]
    subjects: Mapping[str, SubjectIdentity]
    changes_by_user: Mapping[str, tuple[IdentityChange, ...]]

    def resolve_email(self, email: str) -> frozenset[str]:
        return self.lookup("email", email)

    def resolve_phone(self, phone: str) -> frozenset[str]:
        return self.lookup("phone", phone)

    def resolve_email_hash(self, email_hash: str) -> frozenset[str]:
        return self.lookup("email_hash", email_hash)

    def lookup(self, field_name: str, value: str) -> frozenset[str]:
        normalized = normalize_identifier(field_name, value)
        return self.by_field.get(field_name, {}).get(normalized, frozenset())


def build_identity_index(
    identities: Iterable[UserIdentity],
    changes: Iterable[IdentityChange],
) -> IdentifierIndex:
    current = {identity.user_id: identity for identity in identities}
    history: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    changes_by_user: dict[str, list[IdentityChange]] = defaultdict(list)
    for change in changes:
        if change.user_id not in current:
            raise ValueError(f"identity change {change.audit_id} references unknown user {change.user_id}")
        if change.field_name not in {"email", "phone", "email_hash"}:
            raise ValueError(f"unsupported identity field {change.field_name!r}")
        changes_by_user[change.user_id].append(change)
        for value in (change.old_value, change.new_value):
            normalized = normalize_identifier(change.field_name, value)
            if normalized:
                history[change.user_id][change.field_name].add(normalized)

    by_field: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    subjects: dict[str, SubjectIdentity] = {}
    for user_id, identity in current.items():
        values: dict[str, set[str]] = defaultdict(set)
        for field_name, value in (
            ("email", identity.email),
            ("phone", identity.phone),
            ("email_hash", identity.email_hash),
        ):
            normalized = normalize_identifier(field_name, value)
            if normalized:
                values[field_name].add(normalized)
                by_field[field_name][normalized].add(user_id)
        for field_name, historical in history.get(user_id, {}).items():
            values[field_name].update(historical)
            for normalized in historical:
                by_field[field_name][normalized].add(user_id)
        historical_values = {
            field_name: tuple(sorted(value for value in field_values if value))
            for field_name, field_values in values.items()
        }
        all_identifiers = frozenset(
            identifier for field_values in historical_values.values() for identifier in field_values
        )
        subjects[user_id] = SubjectIdentity(
            user_id=user_id,
            current=identity,
            historical_values=historical_values,
            all_identifiers=all_identifiers,
        )
    frozen_index = {
        field_name: {value: frozenset(user_ids) for value, user_ids in values.items()}
        for field_name, values in by_field.items()
    }
    frozen_changes = {
        user_id: tuple(sorted(user_changes, key=lambda item: item.event_time))
        for user_id, user_changes in changes_by_user.items()
    }
    return IdentifierIndex(frozen_index, subjects, frozen_changes)


def resolve_subject(
    email: str,
    index: IdentifierIndex,
    *,
    audit_at: datetime | None = None,
) -> SubjectIdentity | None:
    """Resolve only an unambiguous email match.

    Future identity changes are excluded from the subject snapshot. A historical
    identifier is retained when its change occurred by the audit cutoff.
    """

    if audit_at is None:
        user_ids = index.resolve_email(email)
    else:
        user_ids = frozenset(
            user_id
            for user_id, subject in index.subjects.items()
            if normalize_email(email) in _subject_at(subject, index.changes_by_user.get(user_id, ()), audit_at).all_identifiers
        )
    if len(user_ids) != 1:
        return None
    user_id = next(iter(user_ids))
    if audit_at is None:
        return index.subjects[user_id]
    return _subject_at(index.subjects[user_id], index.changes_by_user.get(user_id, ()), audit_at)


def _subject_at(
    subject: SubjectIdentity,
    changes: Iterable[IdentityChange],
    audit_at: datetime,
) -> SubjectIdentity:
    current_values = {
        "email": subject.current.email,
        "phone": subject.current.phone,
        "email_hash": subject.current.email_hash,
    }
    cutoff_changes = [
        change for change in changes if change.event_time <= audit_at
    ]
    future_changes = sorted(
        (change for change in changes if change.event_time > audit_at),
        key=lambda item: (item.event_time, item.audit_id),
        reverse=True,
    )
    for change in future_changes:
        field_name = change.field_name
        if normalize_identifier(field_name, current_values[field_name]) == normalize_identifier(
            field_name, change.new_value
        ):
            current_values[field_name] = change.old_value
    values: dict[str, set[str]] = defaultdict(set)
    for field_name, value in current_values.items():
        normalized = normalize_identifier(field_name, value)
        if normalized:
            values[field_name].add(normalized)
    for change in cutoff_changes:
        for value in (change.old_value, change.new_value):
            normalized = normalize_identifier(change.field_name, value)
            if normalized:
                values[change.field_name].add(normalized)
    historical_values = {
        field_name: tuple(sorted(field_values))
        for field_name, field_values in values.items()
    }
    all_identifiers = frozenset(
        identifier for field_values in historical_values.values() for identifier in field_values
    )
    current = UserIdentity(
        subject.current.user_id,
        subject.current.name,
        current_values["email"],
        current_values["phone"],
        current_values["email_hash"],
        subject.current.updated_at,
    )
    return SubjectIdentity(subject.user_id, current, historical_values, all_identifiers)
