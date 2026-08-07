from __future__ import annotations

import unittest
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import replace

from authgraph.audit import (
    AuditUnavailable,
    CommittedSecurityAuditEvent,
    InMemoryAuditSink,
    SecurityAuditLogger,
    SecurityAuditRecord,
    SecurityEventOutcome,
    SecurityEventType,
)
from authgraph.errors import SessionUnavailable
from authgraph.key_custody import (
    EnvelopeScopeKeyProvider,
    InMemoryAesKeyWrappingBackend,
    InMemoryKeySlotStore,
    KeyCustodyConflict,
    KeySlotIdentity,
    KeySlotRow,
    KeySlotState,
    RecoveryRewrapResult,
    WrappedKeyBlob,
)
from authgraph.lifecycle import (
    VaultLifecyclePhase,
    VaultLifecycleState,
    VaultManagementTransition,
)
from authgraph.recovery import MirroredKeyWrappingBackend
from authgraph.scoped_sessions import ScopedSessionBroker, ScopeKeyMaterial
from authgraph.security_operations import SecurityOperations
from authgraph.unlock_policy import ScopeGrantDenied, ScopeUnlockGrant

PRINCIPAL = "idp|operations-owner"
VAULT = "v2_operations-vault"
SCOPE_A = "scope_operations-a"
SCOPE_B = "scope_operations-b"


class RecordingVaultGuard:
    def __init__(self, events: list[str]) -> None:
        self._events = events

    @property
    def principal_id(self) -> str:
        return PRINCIPAL

    @property
    def vault_id(self) -> str:
        return VAULT

    @property
    def generation(self) -> int:
        return 1

    def renew(self) -> None:
        self._events.append("renew")

    def assert_active(self) -> None:
        self._events.append("assert")


class RecordingSessionRevoker:
    def __init__(
        self,
        events: list[str] | None = None,
        *,
        fail_finalize: bool = False,
    ) -> None:
        self.calls: list[tuple[str, str]] = []
        self.events = [] if events is None else events
        self.blocked = False
        self.fail_finalize = fail_finalize

    @contextmanager
    def vault_guard(
        self,
        principal_id: str,
        vault_id: str,
    ) -> Iterator[RecordingVaultGuard]:
        self.events.append("guard-enter")
        try:
            yield RecordingVaultGuard(self.events)
        finally:
            self.events.append("guard-exit")

    def begin_management_transition(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> VaultManagementTransition:
        self.events.append("begin")
        self.calls.append((principal_id, vault_id))
        self.blocked = True
        return VaultManagementTransition(
            principal_id=principal_id,
            vault_id=vault_id,
            envelope_revision=envelope_revision,
            generation=1,
        )

    def finalize_management_transition(
        self,
        transition: VaultManagementTransition,
    ) -> VaultLifecycleState:
        self.events.append("finalize")
        if self.fail_finalize:
            raise RuntimeError("finalize unavailable")
        self.blocked = False
        return VaultLifecycleState(
            principal_id=transition.principal_id,
            vault_id=transition.vault_id,
            phase=VaultLifecyclePhase.ACTIVE,
            current_revision=transition.envelope_revision,
            next_revision=None,
            generation=transition.generation,
        )


class CountingBackend:
    def __init__(self, delegate: InMemoryAesKeyWrappingBackend) -> None:
        self.delegate = delegate
        self.unwrap_calls = 0

    @property
    def backend_id(self) -> str:
        return self.delegate.backend_id

    def wrap_key(
        self,
        plaintext: bytes | bytearray | memoryview,
        *,
        aad: bytes,
    ) -> WrappedKeyBlob:
        return self.delegate.wrap_key(plaintext, aad=aad)

    @contextmanager
    def unwrap_key(
        self,
        wrapped_key: WrappedKeyBlob,
        *,
        aad: bytes,
    ) -> Iterator[bytearray]:
        self.unwrap_calls += 1
        with self.delegate.unwrap_key(wrapped_key, aad=aad) as plaintext:
            yield plaintext


class RecordingStore(InMemoryKeySlotStore):
    def __init__(self, events: list[str]) -> None:
        super().__init__()
        self.events = events

    def compare_and_swap_slots(
        self,
        *,
        expected_versions: Mapping[KeySlotIdentity, int | None],
        replacement_rows: tuple[KeySlotRow, ...],
    ) -> bool:
        self.events.append("slot-mutation")
        return super().compare_and_swap_slots(
            expected_versions=expected_versions,
            replacement_rows=replacement_rows,
        )


class CrashAfterCommitStore(RecordingStore):
    def __init__(self, events: list[str]) -> None:
        super().__init__(events)
        self.armed = False

    def compare_and_swap_slots(
        self,
        *,
        expected_versions: Mapping[KeySlotIdentity, int | None],
        replacement_rows: tuple[KeySlotRow, ...],
    ) -> bool:
        committed = super().compare_and_swap_slots(
            expected_versions=expected_versions,
            replacement_rows=replacement_rows,
        )
        if self.armed and committed:
            raise SystemExit("simulated process loss after provider CAS")
        return committed


class AdmissionProbeStore(InMemoryKeySlotStore):
    def __init__(self) -> None:
        super().__init__()
        self.probe: Callable[[], None] | None = None

    def compare_and_swap_slots(
        self,
        *,
        expected_versions: Mapping[KeySlotIdentity, int | None],
        replacement_rows: tuple[KeySlotRow, ...],
    ) -> bool:
        if self.probe is not None:
            self.probe()
        return super().compare_and_swap_slots(
            expected_versions=expected_versions,
            replacement_rows=replacement_rows,
        )


class SingleUseGrantConsumer:
    def __init__(self, expected: ScopeUnlockGrant) -> None:
        self._expected = expected
        self._used = False

    def consume(self, grant: ScopeUnlockGrant) -> ScopeUnlockGrant:
        if self._used or grant != self._expected:
            raise ScopeGrantDenied()
        self._used = True
        return replace(self._expected)

    @property
    def used(self) -> bool:
        return self._used


def recovery_grant(*, profile_id: str = "recovery") -> ScopeUnlockGrant:
    return ScopeUnlockGrant(
        principal_id=PRINCIPAL,
        profile_id=profile_id,
        vault_id=VAULT,
        scope_ids=(SCOPE_A, SCOPE_B),
        client_binding="security-console",
        authorization_epoch=9,
        evidence_provider="one_time_code",
        evidence_id="recovery-evidence",
        issued_at=100.0,
        expires_at=160.0,
        grant_id="recovery-grant",
    )


class SecurityOperationsTests(unittest.TestCase):
    def test_lifecycle_types_are_available_from_public_api(self) -> None:
        import authgraph

        self.assertIs(authgraph.VaultLifecyclePhase, VaultLifecyclePhase)
        self.assertIs(authgraph.VaultLifecycleState, VaultLifecycleState)
        self.assertIs(
            authgraph.VaultManagementTransition,
            VaultManagementTransition,
        )
        self.assertTrue(hasattr(authgraph, "VaultRevisionTransition"))
        self.assertTrue(hasattr(authgraph, "VaultGuard"))

    def setUp(self) -> None:
        self.store = InMemoryKeySlotStore()
        self.old_primary = InMemoryAesKeyWrappingBackend(
            backend_id="test-primary-old",
            key_id="test-primary-old-key",
            wrapping_key=b"o" * 32,
        )
        self.old_recovery_delegate = InMemoryAesKeyWrappingBackend(
            backend_id="test-recovery-old",
            key_id="test-recovery-old-key",
            wrapping_key=b"r" * 32,
        )
        self.old_recovery = CountingBackend(self.old_recovery_delegate)
        self.new_primary = InMemoryAesKeyWrappingBackend(
            backend_id="test-primary-new",
            key_id="test-primary-new-key",
            wrapping_key=b"n" * 32,
        )
        self.new_recovery_delegate = InMemoryAesKeyWrappingBackend(
            backend_id="test-recovery-new",
            key_id="test-recovery-new-key",
            wrapping_key=b"s" * 32,
        )
        self.new_recovery = CountingBackend(self.new_recovery_delegate)
        self.old_backend = MirroredKeyWrappingBackend(
            self.old_primary,
            self.old_recovery,
            backend_id="test-mirror-old",
        )
        self.new_backend = MirroredKeyWrappingBackend(
            self.new_primary,
            self.new_recovery,
            backend_id="test-mirror-new",
        )
        self.addCleanup(self.old_primary.close)
        self.addCleanup(self.old_recovery_delegate.close)
        self.addCleanup(self.new_primary.close)
        self.addCleanup(self.new_recovery_delegate.close)
        self.provider = EnvelopeScopeKeyProvider(
            self.store,
            {
                self.old_backend.backend_id: self.old_backend,
                self.new_backend.backend_id: self.new_backend,
            },
            active_backend_id=self.old_backend.backend_id,
        )
        self.scope_keys = {
            SCOPE_A: ScopeKeyMaterial(1, bytearray(b"a" * 32)),
            SCOPE_B: ScopeKeyMaterial(1, bytearray(b"b" * 32)),
        }
        self.addCleanup(self._clear_scope_keys)
        self.provider.enroll_scope_keys(
            principal_id=PRINCIPAL,
            vault_id=VAULT,
            envelope_revision=1,
            root_key_version=1,
            scope_keys=self.scope_keys,
        )
        self.sessions = RecordingSessionRevoker()
        self.sink = InMemoryAuditSink()
        self.audit = SecurityAuditLogger(
            self.sink,
            b"audit-signing-key-for-tests-0001",
            clock=lambda: 500.0,
        )
        self.operations = SecurityOperations(
            self.sessions,
            self.provider,
            self.audit,
        )

    def _clear_scope_keys(self) -> None:
        for material in self.scope_keys.values():
            material.dek[:] = b"\x00" * len(material.dek)

    def _rows(self):
        return self.store.get_slots(
            principal_id=PRINCIPAL,
            vault_id=VAULT,
            scope_ids=(SCOPE_A, SCOPE_B),
        )

    def test_rewrap_rotates_provider_generation_and_is_idempotent(self) -> None:
        changed = self.operations.rewrap_provider_keys(
            PRINCIPAL,
            VAULT,
            (SCOPE_A, SCOPE_B),
            envelope_revision=1,
            destination_backend_id=self.new_backend.backend_id,
        )
        self.assertEqual(changed, 2)
        self.assertTrue(
            all(
                row.wrapped_key is not None
                and row.wrapped_key.backend_id == self.new_backend.backend_id
                for row in self._rows()
            )
        )
        self.assertEqual(
            self.operations.rewrap_provider_keys(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, SCOPE_B),
                envelope_revision=1,
                destination_backend_id=self.new_backend.backend_id,
            ),
            0,
        )
        records = [event.record for event in self.sink.events]
        self.assertEqual(
            [record.event_type for record in records],
            [SecurityEventType.KEY_REWRAPPED] * 4,
        )
        self.assertEqual(
            [record.outcome for record in records],
            [
                SecurityEventOutcome.PENDING,
                SecurityEventOutcome.SUCCEEDED,
                SecurityEventOutcome.PENDING,
                SecurityEventOutcome.SUCCEEDED,
            ],
        )
        serialized = repr(records)
        self.assertNotIn(PRINCIPAL, serialized)
        self.assertNotIn(VAULT, serialized)
        self.assertNotIn(SCOPE_A, serialized)

    def test_revocation_first_revokes_sessions_then_tombstones_slots(self) -> None:
        changed = self.operations.revoke_scope_access(
            PRINCIPAL,
            VAULT,
            (SCOPE_A, SCOPE_B),
            envelope_revision=1,
        )
        self.assertEqual(changed, 2)
        self.assertEqual(self.sessions.calls, [(PRINCIPAL, VAULT)])
        self.assertTrue(
            all(
                row.state is KeySlotState.REVOKED and row.wrapped_key is None
                for row in self._rows()
            )
        )
        self.assertEqual(
            self.sink.events[-1].record.event_type,
            SecurityEventType.KEY_REVOKED,
        )

    def test_recovery_consumes_fixed_profile_once_and_revokes_sessions(self) -> None:
        grant = recovery_grant()
        consumer = SingleUseGrantConsumer(grant)
        self.old_primary.close()
        result = self.operations.recover_provider_keys(
            grant,
            consumer,
            destination_backend_id=self.new_backend.backend_id,
        )
        self.assertIsInstance(result, RecoveryRewrapResult)
        self.assertEqual(result.changed_count, 2)
        self.assertEqual(result.sources[0].backend_id, "test-recovery-old")
        self.assertEqual(self.sessions.calls, [(PRINCIPAL, VAULT)])
        event = self.sink.events[-1].record
        self.assertEqual(event.metadata["recovery_used"], True)
        self.assertTrue(event.source_refs)
        serialized = b"".join(
            audit_event.canonical_json_bytes()
            for audit_event in self.sink.events
        )
        self.assertNotIn(b"test-recovery-old", serialized)
        self.assertNotIn(b"test-recovery-old-key", serialized)
        recovery_calls = self.old_recovery.unwrap_calls
        new_recovery_calls = self.new_recovery.unwrap_calls
        with self.assertRaises(ScopeGrantDenied):
            self.operations.recover_provider_keys(
                grant,
                consumer,
                destination_backend_id=self.old_backend.backend_id,
            )
        self.assertEqual(self.old_recovery.unwrap_calls, recovery_calls)
        self.assertEqual(self.new_recovery.unwrap_calls, new_recovery_calls)

    def test_wrong_recovery_profile_fails_before_session_or_key_change(self) -> None:
        grant = recovery_grant(profile_id="ordinary-unlock")
        consumer = SingleUseGrantConsumer(grant)
        before = self._rows()
        with self.assertRaises(ScopeGrantDenied):
            self.operations.recover_provider_keys(
                grant,
                consumer,
                destination_backend_id=self.new_backend.backend_id,
            )
        self.assertEqual(self.sessions.calls, [])
        self.assertEqual(self._rows(), before)
        self.assertEqual(self.sink.events, ())
        self.assertEqual(self.old_recovery.unwrap_calls, 0)
        self.assertEqual(self.new_recovery.unwrap_calls, 0)

    def test_same_source_recovery_fails_and_leaves_vault_blocked(self) -> None:
        grant = recovery_grant()
        consumer = SingleUseGrantConsumer(grant)

        with self.assertRaises(KeyCustodyConflict):
            self.operations.recover_provider_keys(
                grant,
                consumer,
                destination_backend_id=self.old_backend.backend_id,
            )

        self.assertTrue(self.sessions.blocked)
        self.assertNotIn("finalize", self.sessions.events)
        self.assertEqual(self.old_recovery.unwrap_calls, 0)
        self.assertEqual(self.new_recovery.unwrap_calls, 0)
        self.assertEqual(
            [event.record.outcome for event in self.sink.events],
            [SecurityEventOutcome.PENDING, SecurityEventOutcome.FAILED],
        )

    def test_required_intent_failure_prevents_every_mutation(self) -> None:
        class BrokenSink:
            def append(
                self,
                record: SecurityAuditRecord,
                *,
                signing_key: bytes,
            ) -> CommittedSecurityAuditEvent:
                raise OSError("secret provider exception must not escape")

        audit = SecurityAuditLogger(
            BrokenSink(),
            b"audit-signing-key-for-tests-0002",
            required=False,
        )
        operations = SecurityOperations(self.sessions, self.provider, audit)
        before = self._rows()

        with self.assertRaises(AuditUnavailable):
            operations.revoke_scope_access(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, SCOPE_B),
                envelope_revision=1,
            )

        self.assertEqual(self.sessions.events, [])
        self.assertEqual(self._rows(), before)

    def test_required_recovery_intent_failure_preserves_one_time_grant(self) -> None:
        class BrokenSink:
            def append(
                self,
                record: SecurityAuditRecord,
                *,
                signing_key: bytes,
            ) -> CommittedSecurityAuditEvent:
                raise OSError("unavailable")

        audit = SecurityAuditLogger(
            BrokenSink(),
            b"audit-signing-key-for-tests-0003",
            required=False,
        )
        operations = SecurityOperations(self.sessions, self.provider, audit)
        grant = recovery_grant()
        consumer = SingleUseGrantConsumer(grant)
        before = self._rows()

        with self.assertRaises(AuditUnavailable):
            operations.recover_provider_keys(
                grant,
                consumer,
                destination_backend_id=self.new_backend.backend_id,
            )

        self.assertFalse(consumer.used)
        self.assertEqual(self.sessions.events, [])
        self.assertEqual(self._rows(), before)
        self.assertEqual(self.old_recovery.unwrap_calls, 0)
        self.assertEqual(self.new_recovery.unwrap_calls, 0)

    def test_guard_covers_block_revoke_and_slot_tombstone(self) -> None:
        events: list[str] = []
        store = RecordingStore(events)
        provider = EnvelopeScopeKeyProvider(
            store,
            {
                self.old_backend.backend_id: self.old_backend,
                self.new_backend.backend_id: self.new_backend,
            },
            active_backend_id=self.old_backend.backend_id,
        )
        provider.enroll_scope_keys(
            principal_id=PRINCIPAL,
            vault_id=VAULT,
            envelope_revision=1,
            root_key_version=1,
            scope_keys=self.scope_keys,
        )
        events.clear()
        sessions = RecordingSessionRevoker(events)

        class EventAuditSink:
            def __init__(self) -> None:
                self.delegate = InMemoryAuditSink()

            def append(
                self,
                record: SecurityAuditRecord,
                *,
                signing_key: bytes,
            ) -> CommittedSecurityAuditEvent:
                events.append(f"audit-{record.outcome.value}")
                return self.delegate.append(record, signing_key=signing_key)

        operations = SecurityOperations(
            sessions,
            provider,
            SecurityAuditLogger(
                EventAuditSink(),
                b"audit-signing-key-for-tests-0006",
            ),
        )

        operations.revoke_scope_access(
            PRINCIPAL,
            VAULT,
            (SCOPE_A, SCOPE_B),
            envelope_revision=1,
        )

        self.assertEqual(
            events,
            [
                "audit-pending",
                "guard-enter",
                "assert",
                "begin",
                "assert",
                "slot-mutation",
                "assert",
                "audit-succeeded",
                "finalize",
                "guard-exit",
            ],
        )

    def test_real_session_admission_is_blocked_before_slot_revocation(self) -> None:
        sessions = ScopedSessionBroker(sweep_interval_seconds=None)
        self.addCleanup(sessions.close_all)
        initial = sessions.open(
            PRINCIPAL,
            VAULT,
            self.scope_keys,
            envelope_revision=1,
            root_key_version=1,
        )
        store = AdmissionProbeStore()
        provider = EnvelopeScopeKeyProvider(
            store,
            {self.old_backend.backend_id: self.old_backend},
            active_backend_id=self.old_backend.backend_id,
        )
        provider.enroll_scope_keys(
            principal_id=PRINCIPAL,
            vault_id=VAULT,
            envelope_revision=1,
            root_key_version=1,
            scope_keys=self.scope_keys,
        )
        admission_blocked: list[bool] = []

        def probe_admission() -> None:
            try:
                sessions.open(
                    PRINCIPAL,
                    VAULT,
                    self.scope_keys,
                    envelope_revision=1,
                    root_key_version=1,
                )
            except SessionUnavailable:
                admission_blocked.append(True)
            else:
                admission_blocked.append(False)

        store.probe = probe_admission
        operations = SecurityOperations(sessions, provider, self.audit)
        operations.revoke_scope_access(
            PRINCIPAL,
            VAULT,
            (SCOPE_A, SCOPE_B),
            envelope_revision=1,
        )

        self.assertEqual(admission_blocked, [True])
        with self.assertRaises(SessionUnavailable):
            with sessions.guarded_lease(initial):
                pass

    def test_rewrap_crash_after_cas_leaves_pending_intent_and_blocked_vault(
        self,
    ) -> None:
        events: list[str] = []
        store = CrashAfterCommitStore(events)
        provider = EnvelopeScopeKeyProvider(
            store,
            {
                self.old_backend.backend_id: self.old_backend,
                self.new_backend.backend_id: self.new_backend,
            },
            active_backend_id=self.old_backend.backend_id,
        )
        provider.enroll_scope_keys(
            principal_id=PRINCIPAL,
            vault_id=VAULT,
            envelope_revision=1,
            root_key_version=1,
            scope_keys=self.scope_keys,
        )
        store.armed = True
        sessions = RecordingSessionRevoker(events)
        sink = InMemoryAuditSink()
        audit = SecurityAuditLogger(
            sink,
            b"audit-signing-key-for-tests-0004",
        )
        operations = SecurityOperations(sessions, provider, audit)

        with self.assertRaises(SystemExit):
            operations.rewrap_provider_keys(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, SCOPE_B),
                envelope_revision=1,
                destination_backend_id=self.new_backend.backend_id,
            )

        rows = store.get_slots(
            principal_id=PRINCIPAL,
            vault_id=VAULT,
            scope_ids=(SCOPE_A, SCOPE_B),
        )
        self.assertTrue(
            all(
                row.wrapped_key is not None
                and row.wrapped_key.backend_id == self.new_backend.backend_id
                for row in rows
            )
        )
        self.assertTrue(sessions.blocked)
        self.assertNotIn("finalize", sessions.events)
        self.assertEqual(len(sink.events), 1)
        self.assertEqual(
            sink.events[0].record.outcome,
            SecurityEventOutcome.PENDING,
        )

    def test_terminal_audit_failure_keeps_rewrapped_vault_blocked(self) -> None:
        committed = InMemoryAuditSink()

        class FailSecondSink:
            def __init__(self) -> None:
                self.calls = 0

            def append(
                self,
                record: SecurityAuditRecord,
                *,
                signing_key: bytes,
            ) -> CommittedSecurityAuditEvent:
                self.calls += 1
                if self.calls == 2:
                    raise OSError("terminal audit unavailable")
                return committed.append(record, signing_key=signing_key)

        sessions = RecordingSessionRevoker()
        operations = SecurityOperations(
            sessions,
            self.provider,
            SecurityAuditLogger(
                FailSecondSink(),
                b"audit-signing-key-for-tests-0005",
            ),
        )

        with self.assertRaises(AuditUnavailable):
            operations.rewrap_provider_keys(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, SCOPE_B),
                envelope_revision=1,
                destination_backend_id=self.new_backend.backend_id,
            )

        self.assertTrue(sessions.blocked)
        self.assertNotIn("finalize", sessions.events)
        self.assertEqual(
            [event.record.outcome for event in committed.events],
            [SecurityEventOutcome.PENDING],
        )

    def test_ambiguous_terminal_append_never_adds_contradictory_failure(
        self,
    ) -> None:
        committed = InMemoryAuditSink()

        class CommitThenFailSink:
            def __init__(self) -> None:
                self.calls = 0

            def append(
                self,
                record: SecurityAuditRecord,
                *,
                signing_key: bytes,
            ) -> CommittedSecurityAuditEvent:
                self.calls += 1
                event = committed.append(record, signing_key=signing_key)
                if self.calls == 2:
                    raise OSError("ambiguous terminal append")
                return event

        sessions = RecordingSessionRevoker()
        operations = SecurityOperations(
            sessions,
            self.provider,
            SecurityAuditLogger(
                CommitThenFailSink(),
                b"audit-signing-key-for-tests-0007",
            ),
        )

        with self.assertRaises(AuditUnavailable):
            operations.rewrap_provider_keys(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, SCOPE_B),
                envelope_revision=1,
                destination_backend_id=self.new_backend.backend_id,
            )

        self.assertTrue(sessions.blocked)
        self.assertNotIn("finalize", sessions.events)
        self.assertEqual(
            [event.record.outcome for event in committed.events],
            [SecurityEventOutcome.PENDING, SecurityEventOutcome.SUCCEEDED],
        )

    def test_finalize_failure_does_not_append_failure_after_success(self) -> None:
        sessions = RecordingSessionRevoker(fail_finalize=True)
        operations = SecurityOperations(sessions, self.provider, self.audit)

        with self.assertRaisesRegex(RuntimeError, "finalize unavailable"):
            operations.rewrap_provider_keys(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, SCOPE_B),
                envelope_revision=1,
                destination_backend_id=self.new_backend.backend_id,
            )

        self.assertTrue(sessions.blocked)
        self.assertEqual(
            [event.record.outcome for event in self.sink.events],
            [SecurityEventOutcome.PENDING, SecurityEventOutcome.SUCCEEDED],
        )


if __name__ == "__main__":
    unittest.main()
