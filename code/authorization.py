# -*- coding: utf-8 -*-
"""Deterministic authorization classification for deletion requests."""

from __future__ import annotations

import re

from models import AuthorizationDecision


_NON_DELETION_PATTERNS = (
    re.compile(r"\b(?:access|view|see|obtain|receive)\b.*\b(?:data|information|records?)\b", re.I),
    re.compile(r"\b(?:correct|update|change|edit)\b.*\b(?:data|information|details|profile)\b", re.I),
    re.compile(r"\b(?:export|download)\b.*\b(?:data|information|records?)\b", re.I),
    re.compile(r"\b(?:marketing|promotional)\b.*\b(?:opt[- ]?out|unsubscribe|stop)\b", re.I),
)
_DELETION_PATTERNS = (
    re.compile(
        r"\b(?:delete|deleted|deleting|deletion|erase|erasure|remove|removed|removal|"
        r"purge|close|closed|closing|gone)\b",
        re.I,
    ),
    re.compile(r"\b(?:eliminar|borrar|suprimir)\b", re.I),
    re.compile(r"\b(?:suppression|supprimer|effacer|supprimée?)\b", re.I),
    re.compile(r"(?:削除|消去)", re.I),
)
_SUBJECT_PATTERNS = (
    re.compile(
        r"\b(?:account|profile|personal\s+(?:data|details|information)|my\s+data|"
        r"records?|copies?|identifiers?|archive)\b",
        re.I,
    ),
    re.compile(r"\b(?:cuenta|datos\s+personales|perfil|registros|identificadores)\b", re.I),
    re.compile(
        r"\b(?:compte|donn(?:e|é)es?\s+personnelles|profil|enregistrements?)\b",
        re.I,
    ),
    re.compile(r"(?:アカウント|個人情報)", re.I),
)
_NEGATED_PATTERNS = (
    re.compile(r"\b(?:do\s+not|don't|dont|never)\s+(?:delete|erase|remove|close)\b", re.I),
    re.compile(
        r"\b(?:cancel|withdraw|revoke)\s+(?:my\s+)?"
        r"(?:account\s+)?(?:deletion|erasure)\b",
        re.I,
    ),
    re.compile(r"\b(?:no|not)\s+(?:deletion|erasure)\b", re.I),
)
_ACTION_CONTEXT_PATTERNS = (
    re.compile(
        r"\b(?:please\s+(?:\w+\s+){0,3}(?:delete|erase|remove|close|purge|"
        r"inspect|check|audit|review|handle|process|finish|complete)|"
        r"i\s+(?:want|would\s+like|request|ask|am|['’]?m|have|deleted|deleting|"
        r"closed|removed|just)|my\s+(?:deletion|erasure)\s+request|"
        r"request\s+for\s+(?:permanent\s+)?(?:account\s+)?"
        r"(?:deletion|erasure))\b",
        re.I,
    ),
    re.compile(
        r"\bi['’]m\b.*\b(?:delet|eras|remov|clos|purge)\w*\b",
        re.I,
    ),
    re.compile(
        r"\b(?:can|could|would)\s+you\s+(?:delete|erase|remove|close|purge)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:delete|erase|remove|close|purge)\s+"
        r"(?:my|the|this|that|any|all|your)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:do\s+not|don't|dont)\s+(?:treat|consider|include)\b"
        r".*\b(?:record|result|match)\b",
        re.I,
    ),
    re.compile(r"\b(?:intent[ée]|solicito|quiero|pido)\b", re.I),
    re.compile(r"\b(?:je\s+(?:demande|souhaite)|je\s+demande)\b", re.I),
    re.compile(r"(?:依頼|お願いします|ください)", re.I),
    re.compile(
        r"\b(?:audit|investigate|inspect|review|handle|process|finish|complete)\b"
        r".*\b(?:delet(?:e|ed|ion)|eras(?:e|ure)|remov(?:e|ed|al))\b",
        re.I,
    ),
)
_INQUIRY_START_PATTERNS = (
    re.compile(r"^\s*(?:did|has|have|is|was|were)\s+.+\?$", re.I),
    re.compile(r"^\s*(?:please\s+)?(?:verify|check|confirm|inspect)\b", re.I),
    re.compile(r"^\s*(?:can|could)\s+you\s+(?:verify|check|confirm|inspect)\b", re.I),
    re.compile(r"^\s*(?:¿|est-ce que|avez-vous|pouvez-vous)", re.I),
)


def classify_request(text: str) -> AuthorizationDecision:
    """Classify whether text authorizes deletion, independent of workflow status."""

    normalized = " ".join(text.split())
    if not normalized:
        return AuthorizationDecision(False, "empty_request")
    if any(pattern.search(normalized) for pattern in _NEGATED_PATTERNS):
        return AuthorizationDecision(False, "negated_deletion_request")
    has_deletion = any(pattern.search(normalized) for pattern in _DELETION_PATTERNS)
    has_subject = any(pattern.search(normalized) for pattern in _SUBJECT_PATTERNS)
    has_non_deletion = any(pattern.search(normalized) for pattern in _NON_DELETION_PATTERNS)
    has_action_context = any(pattern.search(normalized) for pattern in _ACTION_CONTEXT_PATTERNS)
    is_inquiry = "?" in normalized or any(
        pattern.search(normalized) for pattern in _INQUIRY_START_PATTERNS
    )
    is_status_inquiry = bool(
        re.search(
            r"^\s*(?:did|has|have|is|was|were)\b|"
            r"^\s*(?:can|could)\s+you\s+(?:verify|check|confirm|inspect)\b",
            normalized,
            re.I,
        )
    )
    has_scope_instruction = bool(
        re.search(
            r"\b(?:do\s+not|don't|dont)\s+(?:treat|consider|include)\b"
            r".*\b(?:record|result|match)\b",
            normalized,
            re.I,
        )
    )
    if (
        has_deletion
        and has_subject
        and has_action_context
        and (not is_status_inquiry or has_scope_instruction)
    ):
        return AuthorizationDecision(True, "explicit_deletion_request")
    if has_non_deletion:
        return AuthorizationDecision(False, "non_deletion_request")
    if has_deletion and is_inquiry:
        return AuthorizationDecision(False, "deletion_status_inquiry")
    return AuthorizationDecision(False, "no_explicit_deletion_authorization")
