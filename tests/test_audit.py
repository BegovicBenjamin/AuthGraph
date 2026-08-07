from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from authgraph.audit import (
    AuditUnavailable,
    CommittedSecurityAuditEvent,
    InMemoryAuditSink,
    JsonLinesAuditSink,
    SecurityAuditLogger,
    SecurityAuditRecord,
    SecurityEventOutcome,
    SecurityEventType,
    verify_json_lines_audit,
    verify_json_lines_audit_report,
)
from authgraph.errors import ValidationError


class SecurityAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = b"audit-test-key-material-32-bytes!!"

    def test_logger_pseudonymizes_identifiers_and_chains_events(self) -> None:
        sink = InMemoryAuditSink()
        logger = SecurityAuditLogger(sink, self.key, clock=lambda: 100.0)

        first = logger.record(
            SecurityEventType.UNLOCK_SUCCEEDED,
            SecurityEventOutcome.SUCCEEDED,
            principal_id="principal-secret",
            vault_id="vault-secret",
            scope_ids=("scope-secret",),
            session_token="session-secret",
            metadata={"provider": "one_time_code", "count": 1},
        )
        second = logger.record(
            SecurityEventType.SESSION_LOCKED,
            SecurityEventOutcome.SUCCEEDED,
            principal_id="principal-secret",
            vault_id="vault-secret",
            session_token="session-secret",
        )

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        assert first is not None and second is not None
        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertEqual(
            second.record.principal_ref,
            first.record.principal_ref,
        )
        serialized = first.canonical_json_bytes() + second.canonical_json_bytes()
        for forbidden in (
            b"principal-secret",
            b"vault-secret",
            b"scope-secret",
            b"session-secret",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_metadata_is_allowlisted_and_cannot_hold_freeform_secret(self) -> None:
        logger = SecurityAuditLogger(InMemoryAuditSink(), self.key)

        with self.assertRaises(ValidationError):
            logger.record(
                SecurityEventType.UNLOCK_DENIED,
                SecurityEventOutcome.DENIED,
                metadata={"exception": "password was hunter2"},
            )
        with self.assertRaises(ValidationError):
            logger.record(
                SecurityEventType.UNLOCK_DENIED,
                SecurityEventOutcome.DENIED,
                metadata={"reason_code": "password was hunter2"},
            )

    def test_optional_logger_swallows_sink_failure(self) -> None:
        class BrokenSink:
            def append(
                self,
                record: SecurityAuditRecord,
                *,
                signing_key: bytes,
            ) -> CommittedSecurityAuditEvent:
                raise OSError("unavailable")

        logger = SecurityAuditLogger(
            BrokenSink(),
            self.key,
            required=False,
        )
        self.assertIsNone(
            logger.record(
                SecurityEventType.UNLOCK_DENIED,
                SecurityEventOutcome.DENIED,
            )
        )

    def test_json_lines_sink_is_mode_0600_and_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "audit.jsonl")
            logger = SecurityAuditLogger(
                JsonLinesAuditSink(path),
                self.key,
                clock=lambda: 200.0,
            )
            logger.record(
                SecurityEventType.KEY_ENROLLED,
                SecurityEventOutcome.SUCCEEDED,
                principal_id="p1",
                vault_id="v1",
                scope_ids=("s1",),
                metadata={"provider": "aws_kms", "count": 1},
            )
            logger.record(
                SecurityEventType.KEY_REWRAPPED,
                SecurityEventOutcome.SUCCEEDED,
                principal_id="p1",
                vault_id="v1",
                scope_ids=("s1",),
                metadata={"provider": "aws_kms", "key_version": 2},
            )

            self.assertEqual(verify_json_lines_audit(path, self.key), 2)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            lines = path.read_text(encoding="ascii").splitlines()
            value = json.loads(lines[0])
            value["outcome"] = "failed"
            lines[0] = json.dumps(value, separators=(",", ":"))
            path.write_text("\n".join(lines) + "\n", encoding="ascii")
            if os.name == "posix":
                path.chmod(0o600)
            with self.assertRaises(AuditUnavailable):
                verify_json_lines_audit(path, self.key)

    def test_verifier_reports_unmatched_intent_and_linked_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "audit.jsonl")
            logger = SecurityAuditLogger(
                JsonLinesAuditSink(path),
                self.key,
                clock=lambda: 250.0,
            )
            operation = logger.prepare_operation(
                SecurityEventType.KEY_REVOKED,
                principal_id="principal-secret",
                vault_id="vault-secret",
                scope_ids=("scope-secret",),
            )

            pending = verify_json_lines_audit_report(path, self.key)
            self.assertEqual(pending.event_count, 1)
            self.assertEqual(pending.completed_operation_count, 0)
            self.assertEqual(len(pending.pending_operation_refs), 1)

            logger.complete_operation(
                operation,
                SecurityEventOutcome.SUCCEEDED,
                principal_id="principal-secret",
                vault_id="vault-secret",
                scope_ids=("scope-secret",),
                metadata={"count": 1},
            )
            completed = verify_json_lines_audit_report(path, self.key)
            self.assertEqual(completed.event_count, 2)
            self.assertEqual(completed.completed_operation_count, 1)
            self.assertEqual(completed.pending_operation_refs, ())

            values = [
                json.loads(line)
                for line in path.read_text(encoding="ascii").splitlines()
            ]
            self.assertEqual(values[0]["operation_ref"], values[1]["operation_ref"])
            serialized = path.read_bytes()
            self.assertNotIn(b"principal-secret", serialized)
            self.assertNotIn(b"vault-secret", serialized)
            self.assertNotIn(b"scope-secret", serialized)

    def test_verifier_accepts_existing_v1_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "audit.jsonl")
            sink = JsonLinesAuditSink(path)
            sink.append(
                SecurityAuditRecord(
                    format_version=1,
                    event_id="1" * 32,
                    occurred_at=10.0,
                    event_type=SecurityEventType.UNLOCK_DENIED,
                    outcome=SecurityEventOutcome.DENIED,
                    principal_ref=None,
                    vault_ref=None,
                    scope_refs=(),
                    session_ref=None,
                    operation_ref=None,
                    source_refs=(),
                    metadata={},
                ),
                signing_key=self.key,
            )

            self.assertEqual(verify_json_lines_audit(path, self.key), 1)

    @unittest.skipUnless(os.name == "posix", "POSIX permission behavior required")
    def test_json_lines_sink_rejects_group_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory, "unsafe")
            parent.mkdir(mode=0o700)
            parent.chmod(0o770)
            path = parent / "audit.jsonl"
            logger = SecurityAuditLogger(JsonLinesAuditSink(path), self.key)
            try:
                with self.assertRaises(AuditUnavailable):
                    logger.record(
                        SecurityEventType.UNLOCK_DENIED,
                        SecurityEventOutcome.DENIED,
                    )
                self.assertFalse(path.exists())
            finally:
                parent.chmod(0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX permission behavior required")
    def test_verifier_rejects_group_writable_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory, "unsafe")
            parent.mkdir(mode=0o700)
            path = parent / "audit.jsonl"
            logger = SecurityAuditLogger(JsonLinesAuditSink(path), self.key)
            logger.record(
                SecurityEventType.UNLOCK_DENIED,
                SecurityEventOutcome.DENIED,
            )
            parent.chmod(0o770)
            try:
                with self.assertRaises(AuditUnavailable):
                    verify_json_lines_audit_report(path, self.key)
            finally:
                parent.chmod(0o700)

    @unittest.skipUnless(os.name == "posix", "POSIX symlink behavior required")
    def test_json_lines_sink_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "target")
            target.write_text("", encoding="ascii")
            target.chmod(0o600)
            link = Path(directory, "link")
            link.symlink_to(target)
            logger = SecurityAuditLogger(JsonLinesAuditSink(link), self.key)

            with self.assertRaises(AuditUnavailable):
                logger.record(
                    SecurityEventType.UNLOCK_DENIED,
                    SecurityEventOutcome.DENIED,
                )


if __name__ == "__main__":
    unittest.main()
