from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import unittest
import sys

CODE_DIR = Path(__file__).parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from authorization import classify_request
from identity import build_identity_index, normalize_email, normalize_phone, resolve_subject
from io_loader import load_all, load_requests, parse_timestamp
from models import IdentityChange, UserIdentity


ROOT = Path(__file__).parents[2]
DATASET = ROOT / "dataset"


class Phase1Tests(unittest.TestCase):
    def test_load_all_validates_and_loads_repository_inputs(self) -> None:
        loaded = load_all(DATASET)
        self.assertEqual(len(loaded["requests"]), 518)
        self.assertEqual(len(loaded["identities"]), 850)
        self.assertEqual(len(loaded["identity_changes"]), 306)
        self.assertEqual(len(loaded["activity"]), 4011)
        self.assertEqual(len(loaded["rules"]), 15)
        self.assertEqual(len(loaded["evidence_manifest"]), 94)

    def test_parse_timestamp_accepts_z_and_offsets_as_utc(self) -> None:
        expected = datetime(2026, 9, 15, 12, tzinfo=timezone.utc)
        self.assertEqual(parse_timestamp("2026-09-15T12:00:00Z"), expected)
        self.assertEqual(parse_timestamp("2026-09-15T14:00:00+02:00"), expected)

    def test_parse_timestamp_rejects_empty_invalid_or_naive_values(self) -> None:
        for value in ("", "2026-09-15T12:00:00", "not-a-time"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_timestamp(value)

    def test_loader_rejects_missing_required_columns(self) -> None:
        path = Path(__file__).parent / "invalid_requests.csv"
        try:
            path.write_text("case_id,email\ncase_1,a@example.com\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing required columns"):
                load_requests(path)
        finally:
            path.unlink(missing_ok=True)

    def test_loader_rejects_duplicate_case_ids(self) -> None:
        path = Path(__file__).parent / "duplicate_requests.csv"
        path.write_text(
            "case_id,email,requested_at,reported_status,reported_at,audit_at,request_text\n"
            "case_1,a@example.com,2026-01-01T00:00:00Z,COMPLETE,2026-01-01T00:00:00Z,"
            "2026-01-01T00:00:00Z,delete my account\n"
            "case_1,b@example.com,2026-01-01T00:00:00Z,COMPLETE,2026-01-01T00:00:00Z,"
            "2026-01-01T00:00:00Z,delete my account\n",
            encoding="utf-8",
        )
        try:
            with self.assertRaisesRegex(ValueError, "duplicate case_id"):
                load_requests(path)
        finally:
            path.unlink(missing_ok=True)

    def test_request_authorization_is_independent_of_status(self) -> None:
        cases = (
            ("Please permanently delete my account and personal data.", True),
            ("Intenté eliminar mi cuenta y mis datos personales.", True),
            ("Je demande la suppression définitive de mon compte.", True),
            ("このメールアドレスに関連するアカウントの完全な削除を依頼します。", True),
            ("Je demande la suppression définitive du compte associé à cette adresse e-mail.", True),
            ("Please export my data for me.", False),
            ("Please correct the details on my profile.", False),
            ("Please unsubscribe me from marketing.", False),
            ("Did you delete my account?", False),
            ("Has my account been deleted?", False),
            ("Do not delete my account.", False),
            ("Please cancel my deletion request.", False),
            ("Can you verify that my account was deleted?", False),
        )
        for text, authorized in cases:
            with self.subTest(text=text):
                self.assertEqual(classify_request(text).authorized, authorized)

    def test_deletion_word_without_authorizing_intent_is_not_enough(self) -> None:
        cases = (
            "The deletion is complete.",
            "My account was deleted yesterday.",
            "The profile removal status is complete.",
            "Could you tell me whether my account has been deleted?",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertFalse(classify_request(text).authorized)

    def test_negative_authorization_intents(self) -> None:
        cases = (
            "Please cancel my account deletion request.",
            "Do not delete my account.",
            "Please give me access to my personal data.",
            "Please export all records associated with my account.",
            "Please update the phone number on my profile.",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertFalse(classify_request(text).authorized)

    def test_raw_utf8_authorization_in_supported_languages(self) -> None:
        cases = (
            "Please delete my account and personal data.",
            "Solicito eliminar mi cuenta y mis datos personales.",
            "Je demande la suppression définitive de mon compte et de mes données.",
            "このアカウントと個人情報の完全な削除をお願いします。",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertTrue(classify_request(text).authorized)

    def test_all_public_sample_requests_are_authorized(self) -> None:
        from io_loader import load_requests

        requests = load_requests(DATASET / "sample_deletion_requests.csv")
        self.assertEqual(len(requests), 32)
        self.assertTrue(all(classify_request(request.request_text).authorized for request in requests))

    def test_public_japanese_request_is_read_as_raw_utf8(self) -> None:
        requests = load_requests(DATASET / "sample_deletion_requests.csv")
        japanese = next(request for request in requests if request.case_id == "case_14")
        self.assertIn("削除", japanese.request_text)
        self.assertIn("アカウント", japanese.request_text)
        self.assertTrue(classify_request(japanese.request_text).authorized)

    def test_historical_email_and_phone_are_indexed(self) -> None:
        identity = UserIdentity(
            "user_1",
            "Example",
            "new@example.com",
            "+1 (202) 555-0100",
            "ABCDEF",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        changes = [
            IdentityChange(
                "audit_1",
                "user_1",
                datetime(2025, 1, 1, tzinfo=timezone.utc),
                "email",
                "old@example.com",
                "new@example.com",
            ),
            IdentityChange(
                "audit_2",
                "user_1",
                datetime(2025, 2, 1, tzinfo=timezone.utc),
                "phone",
                "+1 202 555 0100",
                "+1 202 555 0199",
            ),
        ]
        index = build_identity_index([identity], changes)
        cutoff = datetime(2025, 3, 1, tzinfo=timezone.utc)
        subject = resolve_subject("OLD@EXAMPLE.COM", index, audit_at=cutoff)
        self.assertIsNotNone(subject)
        assert subject is not None
        self.assertIn(normalize_email("OLD@EXAMPLE.COM"), subject.all_identifiers)
        self.assertIn(normalize_phone("+1 202 555 0199"), subject.all_identifiers)
        self.assertEqual(index.resolve_phone("+1 202 555 0199"), frozenset({"user_1"}))
        self.assertEqual(index.resolve_email_hash("abcdef"), frozenset({"user_1"}))

    def test_future_identity_change_is_not_visible_at_audit_cutoff(self) -> None:
        identity = UserIdentity(
            "user_1",
            "Example",
            "new@example.com",
            "+1 202 555 0100",
            "newhash",
            datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
        change = IdentityChange(
            "audit_future",
            "user_1",
            datetime(2026, 2, 1, tzinfo=timezone.utc),
            "email",
            "old@example.com",
            "new@example.com",
        )
        index = build_identity_index([identity], [change])
        before = resolve_subject(
            "new@example.com",
            index,
            audit_at=datetime(2026, 1, 31, tzinfo=timezone.utc),
        )
        after = resolve_subject(
            "new@example.com",
            index,
            audit_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        self.assertIsNone(before)
        self.assertIsNotNone(after)

    def test_identity_change_at_or_before_cutoff_remains_searchable(self) -> None:
        identity = UserIdentity(
            "user_1",
            "Example",
            "new@example.com",
            "+1 202 555 0100",
            "newhash",
            datetime(2026, 3, 1, tzinfo=timezone.utc),
        )
        change = IdentityChange(
            "audit_past",
            "user_1",
            datetime(2026, 2, 1, tzinfo=timezone.utc),
            "email",
            "old@example.com",
            "new@example.com",
        )
        index = build_identity_index([identity], [change])
        subject = resolve_subject(
            "old@example.com",
            index,
            audit_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        self.assertIsNotNone(subject)
        assert subject is not None
        self.assertIn("old@example.com", subject.all_identifiers)

    def test_ambiguous_email_does_not_invent_a_subject(self) -> None:
        identities = [
            UserIdentity(
                "user_1", "One", "same@example.com", "111", "hash1",
                datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
            UserIdentity(
                "user_2", "Two", "same@example.com", "222", "hash2",
                datetime(2026, 1, 1, tzinfo=timezone.utc),
            ),
        ]
        index = build_identity_index(identities, [])
        self.assertIsNone(resolve_subject("same@example.com", index))

    def test_multiple_sequential_changes_are_unwound_at_cutoff(self) -> None:
        identity = UserIdentity(
            "user_1",
            "Example",
            "third@example.com",
            "+1 202 555 0102",
            "hash3",
            datetime(2026, 4, 1, tzinfo=timezone.utc),
        )
        changes = [
            IdentityChange(
                "audit_1", "user_1", datetime(2026, 1, 1, tzinfo=timezone.utc),
                "email", "first@example.com", "second@example.com",
            ),
            IdentityChange(
                "audit_2", "user_1", datetime(2026, 2, 1, tzinfo=timezone.utc),
                "email", "second@example.com", "third@example.com",
            ),
            IdentityChange(
                "audit_3", "user_1", datetime(2026, 3, 1, tzinfo=timezone.utc),
                "email", "third@example.com", "fourth@example.com",
            ),
        ]
        index = build_identity_index([identity], changes)
        before_second_change = resolve_subject(
            "second@example.com", index,
            audit_at=datetime(2026, 1, 15, tzinfo=timezone.utc),
        )
        after_third_change = resolve_subject(
            "third@example.com", index,
            audit_at=datetime(2026, 2, 15, tzinfo=timezone.utc),
        )
        self.assertIsNotNone(before_second_change)
        self.assertIsNotNone(after_third_change)
        assert before_second_change is not None
        assert after_third_change is not None
        self.assertEqual(before_second_change.current.email, "second@example.com")
        self.assertEqual(after_third_change.current.email, "third@example.com")
        self.assertNotIn("fourth@example.com", before_second_change.all_identifiers)

    def test_future_identifier_is_excluded_from_cutoff_subject(self) -> None:
        identity = UserIdentity(
            "user_1", "Example", "current@example.com", "+1 202 555 0100",
            "current-hash", datetime(2026, 4, 1, tzinfo=timezone.utc),
        )
        changes = [
            IdentityChange(
                "audit_past", "user_1", datetime(2026, 1, 1, tzinfo=timezone.utc),
                "email", "old@example.com", "current@example.com",
            ),
            IdentityChange(
                "audit_future", "user_1", datetime(2026, 3, 1, tzinfo=timezone.utc),
                "email", "current@example.com", "future@example.com",
            ),
        ]
        index = build_identity_index([identity], changes)
        subject = resolve_subject(
            "old@example.com", index,
            audit_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        self.assertIsNotNone(subject)
        assert subject is not None
        self.assertNotIn("future@example.com", subject.historical_values["email"])
        self.assertNotIn("future@example.com", subject.all_identifiers)
        self.assertIsNone(resolve_subject(
            "future@example.com", index,
            audit_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
        ))
