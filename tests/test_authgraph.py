from __future__ import annotations

import json
import threading
import unittest
from dataclasses import replace
from unittest.mock import patch

import authgraph.sessions as sessions_module
from authgraph import (
    AuthGraphService,
    ConflictError,
    CryptoEngine,
    InMemoryGraphRepository,
    InMemorySessionBroker,
    IntegrityViolation,
    KdfParameters,
    RecordNotFound,
    SessionUnavailable,
    UnlockDenied,
    ValidationError,
)
from authgraph.crypto import MAX_ACCEPTED_MEMORY_KIB, clear_bytearray
from authgraph.models import (
    AccessContext,
    EncryptedEntityRow,
    EncryptedPayload,
    EncryptedRelationshipRow,
)
from authgraph.neo4j_repository import IncompleteCommit, Neo4jGraphRepository
from authgraph.service import MAX_VAULT_SNAPSHOT_CIPHERTEXT_BYTES


class FakeClock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class FailingClock(FakeClock):
    def __init__(self) -> None:
        super().__init__()
        self.fail = False

    def __call__(self) -> float:
        if self.fail:
            raise RuntimeError("synthetic clock failure")
        return super().__call__()


class PausingWorkerCloseBroker(InMemorySessionBroker):
    """Pause a failed sweeper after it closes admission but before its drain."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        self.worker_before_close = threading.Event()
        self.release_worker_close = threading.Event()
        super().__init__(*args, **kwargs)

    def close_all(self) -> int:
        if (
            threading.current_thread() is self._sweeper
            and not self.worker_before_close.is_set()
        ):
            self.worker_before_close.set()
            if not self.release_worker_close.wait(timeout=5):
                raise RuntimeError("Timed out waiting to release worker shutdown.")
        return super().close_all()


class RecordingDriver:
    encrypted = True

    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = records
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute_query(self, query: str, **kwargs: object) -> object:
        self.calls.append((query, kwargs))
        return type("Result", (), {"records": self.records})()


class SequencedRecordingDriver:
    encrypted = True

    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute_query(self, query: str, **kwargs: object) -> object:
        self.calls.append((query, kwargs))
        records = self.responses.pop(0)
        if isinstance(records, BaseException):
            raise records
        return type("Result", (), {"records": records})()


class BlockingUnwrapCrypto(CryptoEngine):
    """Test helper that pauses exactly one successful unwrap."""

    def __init__(self) -> None:
        super().__init__(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        self.unwrap_started = threading.Event()
        self.release_unwrap = threading.Event()
        self._block_next = False

    def arm(self) -> None:
        self._block_next = True

    def unwrap_dek(self, *args: object, **kwargs: object) -> bytearray:
        result = super().unwrap_dek(*args, **kwargs)
        if self._block_next:
            self._block_next = False
            self.unwrap_started.set()
            if not self.release_unwrap.wait(timeout=5):
                clear_bytearray(result)
                raise RuntimeError("Timed out waiting to release test unwrap.")
        return result


class BlockingPutRepository(InMemoryGraphRepository):
    """Test helper that pauses an entity write before it reaches storage."""

    def __init__(self) -> None:
        super().__init__()
        self.put_started = threading.Event()
        self.release_put = threading.Event()
        self.order: list[str] = []

    def put_entity(self, *args: object, **kwargs: object) -> bool:
        self.put_started.set()
        if not self.release_put.wait(timeout=5):
            raise RuntimeError("Timed out waiting to release test write.")
        result = super().put_entity(*args, **kwargs)
        self.order.append("put")
        return result


class AmbiguousEnvelopeRepository(InMemoryGraphRepository):
    """Commit an envelope replacement, then simulate lost acknowledgement."""

    def replace_envelope(self, *args: object, **kwargs: object) -> bool:
        replaced = super().replace_envelope(*args, **kwargs)
        if replaced:
            raise RuntimeError("synthetic ambiguous envelope commit")
        return False


class AuthGraphSecurityTests(unittest.TestCase):
    ALICE_PASSWORD = bytearray(b"alice correct horse battery staple")
    ALICE_NEW_PASSWORD = bytearray(b"alice new correct horse battery staple")
    BOB_PASSWORD = bytearray(b"bob correct horse battery staple")

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.repository = InMemoryGraphRepository()
        self.crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        self.sessions = InMemorySessionBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(self.sessions.close_all)
        self.service = AuthGraphService(
            self.repository,
            self.crypto,
            self.sessions,
        )

    def create_alice(self) -> tuple[str, AccessContext]:
        vault_id = self.service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        context = self.service.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
        )
        return vault_id, context

    def test_weak_kdf_is_rejected_without_explicit_test_override(self) -> None:
        with self.assertRaises(ValidationError):
            CryptoEngine(KdfParameters.insecure_for_testing())

    def test_kdf_test_override_and_numeric_fields_require_exact_types(self) -> None:
        for override in ("false", 1, object()):
            with self.subTest(override=override), self.assertRaises(
                ValidationError
            ):
                CryptoEngine(  # type: ignore[arg-type]
                    KdfParameters.insecure_for_testing(),
                    allow_insecure_kdf_for_testing=override,
                )

        malformed = (
            replace(
                KdfParameters.insecure_for_testing(),
                memory_cost_kib=float("nan"),
            ),
            replace(
                KdfParameters.insecure_for_testing(),
                iterations=1.0,
            ),
            replace(
                KdfParameters.insecure_for_testing(),
                lanes=True,
            ),
        )
        for parameters in malformed:
            with self.subTest(parameters=parameters), self.assertRaises(
                ValidationError
            ):
                CryptoEngine(
                    parameters,  # type: ignore[arg-type]
                    allow_insecure_kdf_for_testing=True,
                )

    def test_untrusted_kdf_metadata_is_bounded_before_key_derivation(self) -> None:
        production_crypto = CryptoEngine()
        envelope, dek = production_crypto.provision_vault(
            "idp|synthetic",
            "synthetic-vault",
            bytearray(b"a sufficiently long synthetic passphrase"),
        )
        try:
            malicious = replace(
                envelope,
                kdf=replace(
                    envelope.kdf,
                    memory_cost_kib=MAX_ACCEPTED_MEMORY_KIB + 1,
                ),
            )
            with self.assertRaises(UnlockDenied):
                production_crypto.unwrap_dek(
                    "idp|synthetic",
                    "synthetic-vault",
                    bytearray(b"a sufficiently long synthetic passphrase"),
                    malicious,
                )
        finally:
            clear_bytearray(dek)

    def test_ciphertext_repository_does_not_contain_semantic_plaintext(self) -> None:
        _, context = self.create_alice()
        self.service.create_entity(
            context,
            "Diagnosis-PLAINTEXT-SENTINEL",
            {
                "display_name": "PLAINTEXT-SENTINEL-ALICE",
                "condition": "PLAINTEXT-SENTINEL-CONDITION",
            },
        )

        stored = json.dumps(self.repository.ciphertext_snapshot()).lower()
        self.assertNotIn("plaintext-sentinel", stored)
        self.assertNotIn("correct horse battery staple", stored)
        self.assertNotIn(context.session_token, repr(context))

    def test_wrong_password_and_wrong_principal_fail_generically(self) -> None:
        vault_id = self.service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )

        with self.assertRaisesRegex(UnlockDenied, "unlock was denied"):
            self.service.unlock(
                "idp|owner-alice",
                vault_id,
                bytearray(b"this is the wrong password"),
            )
        with self.assertRaisesRegex(UnlockDenied, "unlock was denied"):
            self.service.unlock(
                "idp|owner-bob",
                vault_id,
                self.ALICE_PASSWORD,
            )
        self.assertEqual(self.sessions.active_count, 0)

    def test_cross_owner_record_and_edge_access_fail_closed(self) -> None:
        alice_vault, alice = self.create_alice()
        bob_vault = self.service.create_vault(
            "idp|owner-bob",
            self.BOB_PASSWORD,
        )
        bob = self.service.unlock(
            "idp|owner-bob",
            bob_vault,
            self.BOB_PASSWORD,
        )

        alice_record = self.service.create_entity(
            alice,
            "Encounter",
            {"note": "Alice-only information"},
        )
        bob_record = self.service.create_entity(
            bob,
            "Encounter",
            {"note": "Bob-only information"},
        )

        with self.assertRaises(RecordNotFound):
            self.service.get_entity(alice, bob_record)
        with self.assertRaises(RecordNotFound):
            self.service.connect(
                alice,
                alice_record,
                bob_record,
                "MUST_NOT_CROSS_VAULTS",
            )

        forged = AccessContext(
            principal_id="idp|owner-bob",
            session_token=alice.session_token,
        )
        with self.assertRaises(SessionUnavailable):
            self.service.get_entity(forged, alice_record)

        # Sanity-check that legitimate access still succeeds.
        self.assertEqual(
            self.service.get_entity(alice, alice_record).properties["note"],
            "Alice-only information",
        )
        self.assertNotEqual(alice_vault, bob_vault)

    def test_session_expiry_and_explicit_lock_remove_decrypt_capability(self) -> None:
        vault_id = self.service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        expiring = self.service.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
            ttl_seconds=5,
        )
        record_id = self.service.create_entity(expiring, "Visit", {"year": 2026})

        self.clock.advance(6)
        with self.assertRaises(SessionUnavailable):
            self.service.get_entity(expiring, record_id)
        self.assertEqual(self.sessions.active_count, 0)

        active = self.service.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
        )
        self.service.lock(active)
        with self.assertRaises(SessionUnavailable):
            self.service.get_entity(active, record_id)

    def test_background_sweeper_removes_expired_resident_dek(self) -> None:
        clock = FakeClock()
        worker: threading.Thread | None = None
        resident_dek: bytearray | None = None
        with InMemorySessionBroker(
            default_ttl_seconds=1,
            max_ttl_seconds=10,
            sweep_interval_seconds=0.01,
            clock=clock,
        ) as broker:
            worker = broker._sweeper
            broker.open(
                "principal-1",
                "vault-1",
                b"a" * 32,
                envelope_revision=1,
                key_version=1,
            )
            resident_dek = next(iter(broker._records.values())).dek
            self.assertEqual(broker.resident_session_count, 1)
            clock.advance(2)
            for _ in range(200):
                if (
                    broker.resident_session_count == 0
                    and resident_dek == bytearray(32)
                ):
                    break
                threading.Event().wait(0.01)
            self.assertEqual(broker.resident_session_count, 0)
            self.assertEqual(resident_dek, bytearray(32))
        self.assertIsNotNone(worker)
        assert worker is not None
        self.assertFalse(worker.is_alive())
        self.assertTrue(broker.closed)

    def test_sweeper_failure_fails_closed_and_clears_resident_keys(self) -> None:
        clock = FailingClock()
        broker = InMemorySessionBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            sweep_interval_seconds=0.01,
            clock=clock,
        )
        self.addCleanup(broker.close_all)
        context = broker.open(
            "principal-1",
            "vault-1",
            b"a" * 32,
            envelope_revision=1,
            key_version=1,
        )
        resident_dek = next(iter(broker._records.values())).dek
        clock.fail = True
        for _ in range(200):
            if broker.closed:
                break
            threading.Event().wait(0.01)
        broker.close_all()
        self.assertTrue(broker.closed)
        self.assertTrue(broker.sweeper_failed)
        self.assertFalse(broker.sweeper_alive)
        self.assertEqual(broker.resident_session_count, 0)
        self.assertEqual(resident_dek, bytearray(32))
        with self.assertRaises(SessionUnavailable):
            with broker.lease(context):
                self.fail("A failed sweeper left the broker usable.")

    def test_sweeper_failure_closes_admission_before_shutdown_drain(self) -> None:
        clock = FailingClock()
        broker = PausingWorkerCloseBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            sweep_interval_seconds=0.01,
            clock=clock,
        )
        self.addCleanup(broker.close_all)
        self.addCleanup(broker.release_worker_close.set)
        context = broker.open(
            "principal-1",
            "vault-1",
            b"a" * 32,
            envelope_revision=1,
            key_version=1,
        )
        resident_dek = next(iter(broker._records.values())).dek
        clock.fail = True
        self.assertTrue(broker.worker_before_close.wait(timeout=2))

        self.assertTrue(broker.sweeper_failed)
        self.assertTrue(broker.closed)
        with self.assertRaises(SessionUnavailable):
            with broker.lease(context):
                self.fail("A failed sweeper admitted work before its drain.")

        broker.release_worker_close.set()
        broker.close_all()
        self.assertFalse(broker.sweeper_alive)
        self.assertEqual(broker.resident_session_count, 0)
        self.assertEqual(resident_dek, bytearray(32))

    def test_oversized_or_malformed_session_tokens_fail_before_hashing_input(
        self,
    ) -> None:
        _, context = self.create_alice()
        invalid_contexts = (
            AccessContext(
                principal_id=context.principal_id,
                session_token="x" * 100_000,
            ),
            AccessContext(
                principal_id=context.principal_id,
                session_token="!" * 43,
            ),
        )
        for invalid in invalid_contexts:
            with self.assertRaises(SessionUnavailable):
                with self.sessions.lease(invalid):
                    self.fail("Malformed token unexpectedly obtained a lease.")

    def test_non_integer_or_non_finite_session_ttls_are_rejected(self) -> None:
        vault_id = self.service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        invalid_ttls: tuple[object, ...] = (
            float("nan"),
            float("inf"),
            5.0,
            True,
            "5",
        )
        for ttl in invalid_ttls:
            with self.subTest(ttl=ttl), self.assertRaises(ValidationError):
                self.service.unlock(
                    "idp|owner-alice",
                    vault_id,
                    self.ALICE_PASSWORD,
                    ttl_seconds=ttl,  # type: ignore[arg-type]
                )
        self.assertEqual(self.sessions.active_count, 0)

        with self.assertRaises(ValidationError):
            InMemorySessionBroker(
                default_ttl_seconds=float("nan"),  # type: ignore[arg-type]
            )
        with self.assertRaises(ValidationError):
            InMemorySessionBroker(max_ttl_seconds=True)  # type: ignore[arg-type]
        with self.assertRaises(ValidationError):
            InMemorySessionBroker(max_ttl_seconds=24 * 60 * 60 + 1)
        for sweep_interval in (float("nan"), True, 0, 5e-324, 0.009, 61):
            with self.subTest(
                sweep_interval=sweep_interval
            ), self.assertRaises(ValidationError):
                InMemorySessionBroker(
                    sweep_interval_seconds=sweep_interval,  # type: ignore[arg-type]
                )

    def test_revision_tracker_capacity_fails_closed_without_key_leak(self) -> None:
        broker = InMemorySessionBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            max_tracked_vaults=1,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close_all)
        first = broker.open(
            "principal-1",
            "vault-1",
            b"a" * 32,
            envelope_revision=1,
            key_version=1,
        )
        with self.assertRaises(SessionUnavailable):
            broker.open(
                "principal-2",
                "vault-2",
                b"b" * 32,
                envelope_revision=1,
                key_version=1,
            )
        self.assertEqual(broker.active_count, 1)
        self.assertEqual(broker.tracked_vault_count, 1)
        broker.close(first)
        self.assertEqual(broker.close_all(), 0)
        self.assertEqual(broker.tracked_vault_count, 0)

    def test_existing_active_lifecycle_requires_exact_open_revision(self) -> None:
        broker = InMemorySessionBroker(
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close_all)
        old_context = broker.open(
            "principal-1",
            "vault-1",
            b"a" * 32,
            envelope_revision=1,
            key_version=1,
        )
        with self.assertRaises(SessionUnavailable):
            broker.open(
                "principal-1",
                "vault-1",
                b"a" * 32,
                envelope_revision=2,
                key_version=1,
            )
        broker.advance_envelope_revision("principal-1", "vault-1", 2)
        new_context = broker.open(
            "principal-1",
            "vault-1",
            b"a" * 32,
            envelope_revision=2,
            key_version=1,
        )
        with self.assertRaises(SessionUnavailable):
            with broker.lease(old_context):
                pass
        broker.close(new_context)

    def test_blocked_management_transition_cannot_be_implicitly_retried(
        self,
    ) -> None:
        broker = InMemorySessionBroker(
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close_all)
        context = broker.open(
            "principal-1",
            "vault-1",
            b"a" * 32,
            envelope_revision=1,
            key_version=1,
        )
        transition = broker.begin_management_transition(
            "principal-1",
            "vault-1",
            1,
        )
        with self.assertRaises(SessionUnavailable):
            broker.begin_management_transition("principal-1", "vault-1", 1)
        with self.assertRaises(SessionUnavailable):
            with broker.lease(context):
                pass
        with self.assertRaises(SessionUnavailable):
            broker.reconcile_management_transition(
                "principal-1",
                "vault-1",
                1,
                transition.generation + 1,
            )
        broker.reconcile_management_transition(
            "principal-1",
            "vault-1",
            1,
            transition.generation,
        )

    def test_revision_capacity_cannot_fail_after_password_commit(self) -> None:
        repository = InMemoryGraphRepository()
        broker = InMemorySessionBroker(
            max_tracked_vaults=1,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close_all)
        service = AuthGraphService(repository, self.crypto, broker)
        first_vault = service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        first_context = service.unlock(
            "idp|owner-alice",
            first_vault,
            self.ALICE_PASSWORD,
        )
        second_vault = service.create_vault(
            "idp|owner-bob",
            self.BOB_PASSWORD,
        )
        before = repository.get_vault("idp|owner-bob", second_vault)
        self.assertIsNotNone(before)

        with self.assertRaises(SessionUnavailable):
            service.change_passphrase(
                "idp|owner-bob",
                second_vault,
                self.BOB_PASSWORD,
                bytearray(b"bob new correct horse battery staple"),
            )

        after = repository.get_vault("idp|owner-bob", second_vault)
        self.assertEqual(after, before)
        assert after is not None
        dek = self.crypto.unwrap_dek(
            "idp|owner-bob",
            second_vault,
            self.BOB_PASSWORD,
            after.envelope,
        )
        clear_bytearray(dek)
        service.lock(first_context)

    def test_invalid_new_password_does_not_consume_revision_capacity(self) -> None:
        repository = InMemoryGraphRepository()
        broker = InMemorySessionBroker(
            max_tracked_vaults=1,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close_all)
        service = AuthGraphService(repository, self.crypto, broker)
        vault_id = service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        before = repository.get_vault("idp|owner-alice", vault_id)

        with self.assertRaises(ValidationError):
            service.change_passphrase(
                "idp|owner-alice",
                vault_id,
                self.ALICE_PASSWORD,
                bytearray(b"too-short"),
            )

        self.assertEqual(broker.tracked_vault_count, 0)
        self.assertEqual(
            repository.get_vault("idp|owner-alice", vault_id),
            before,
        )
        context = service.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
        )
        service.lock(context)

    def test_ciphertext_tampering_fails_authentication(self) -> None:
        vault_id, context = self.create_alice()
        record_id = self.service.create_entity(
            context,
            "ProtectedRecord",
            {"name": "synthetic-example"},
        )
        self.repository.tamper_entity_for_testing(vault_id, record_id)

        with self.assertRaises(IntegrityViolation):
            self.service.get_entity(context, record_id)

    def test_ciphertext_cannot_be_moved_between_entity_ids(self) -> None:
        vault_id, context = self.create_alice()
        first = self.service.create_entity(context, "First", {"value": 1})
        second = self.service.create_entity(context, "Second", {"value": 2})
        self.repository.swap_entity_payloads_for_testing(vault_id, first, second)

        with self.assertRaises(IntegrityViolation):
            self.service.get_entity(context, first)
        with self.assertRaises(IntegrityViolation):
            self.service.get_entity(context, second)

    def test_encrypted_relationship_round_trip_and_neighborhood(self) -> None:
        _, context = self.create_alice()
        activity = self.service.create_entity(
            context,
            "Activity",
            {"date": "2026-07-29"},
        )
        item = self.service.create_entity(
            context,
            "Item",
            {"name": "synthetic-item"},
        )
        self.service.connect(
            context,
            activity,
            item,
            "REFERENCES",
            {"source": "synthetic-test"},
        )

        neighborhood = self.service.get_neighborhood(context, activity)
        self.assertEqual(neighborhood.center.kind, "Activity")
        self.assertEqual(
            {neighbor.kind for neighbor in neighborhood.neighbors},
            {"Item"},
        )
        self.assertEqual(
            {relationship.kind for relationship in neighborhood.relationships},
            {"REFERENCES"},
        )

        stored = json.dumps(self.repository.ciphertext_snapshot())
        self.assertNotIn("REFERENCES", stored)
        self.assertNotIn("synthetic-item", stored)

    def test_relationship_bundle_rejects_unused_helper_without_writing(
        self,
    ) -> None:
        _, context = self.create_alice()
        with self.assertRaises(ValidationError):
            self.service.create_relationship_bundle(
                context,
                (
                    ("Helper", {"position": 0}),
                    ("Unused", {"position": 1}),
                ),
                0,
                0,
                "LINK",
            )
        snapshot = self.service.get_vault_snapshot(context)
        self.assertEqual(snapshot.entities, ())
        self.assertEqual(snapshot.relationships, ())

    def test_vault_snapshot_returns_complete_graph_including_isolated_entity(
        self,
    ) -> None:
        _, context = self.create_alice()
        profile = self.service.create_entity(
            context,
            "Profile",
            {
                "display_name": "Synthetic Alice",
                "contact": "alice@example.invalid",
            },
        )
        preference = self.service.create_entity(
            context,
            "Preference",
            {"theme": "synthetic-blue"},
        )
        isolated = self.service.create_entity(
            context,
            "PrivateNote",
            {"text": "synthetic isolated record"},
        )
        relationship = self.service.connect(
            context,
            profile,
            preference,
            "PREFERS",
            {"source": "synthetic-test"},
        )

        snapshot = self.service.get_vault_snapshot(
            context,
            entity_limit=3,
            relationship_limit=1,
        )

        entities = {entity.entity_id: entity for entity in snapshot.entities}
        self.assertEqual(set(entities), {profile, preference, isolated})
        self.assertEqual(entities[profile].kind, "Profile")
        self.assertEqual(
            entities[profile].properties["contact"],
            "alice@example.invalid",
        )
        self.assertEqual(entities[isolated].kind, "PrivateNote")
        self.assertEqual(
            entities[isolated].properties["text"],
            "synthetic isolated record",
        )
        self.assertEqual(len(snapshot.relationships), 1)
        self.assertEqual(snapshot.relationships[0].relationship_id, relationship)
        self.assertEqual(snapshot.relationships[0].from_entity_id, profile)
        self.assertEqual(snapshot.relationships[0].to_entity_id, preference)
        self.assertEqual(snapshot.relationships[0].kind, "PREFERS")
        self.assertEqual(
            snapshot.relationships[0].properties,
            {"source": "synthetic-test"},
        )

    def test_vault_snapshot_supports_an_empty_vault(self) -> None:
        _, context = self.create_alice()

        snapshot = self.service.get_vault_snapshot(context)

        self.assertEqual(snapshot.entities, ())
        self.assertEqual(snapshot.relationships, ())

    def test_vault_snapshot_is_owner_isolated(self) -> None:
        _, alice = self.create_alice()
        bob_vault = self.service.create_vault(
            "idp|owner-bob",
            self.BOB_PASSWORD,
        )
        bob = self.service.unlock(
            "idp|owner-bob",
            bob_vault,
            self.BOB_PASSWORD,
        )
        alice_entity = self.service.create_entity(
            alice,
            "OwnerRecord",
            {"owner": "synthetic-alice-only"},
        )
        bob_entity = self.service.create_entity(
            bob,
            "OwnerRecord",
            {"owner": "synthetic-bob-only"},
        )

        alice_snapshot = self.service.get_vault_snapshot(alice)
        bob_snapshot = self.service.get_vault_snapshot(bob)

        self.assertEqual(
            {entity.entity_id for entity in alice_snapshot.entities},
            {alice_entity},
        )
        self.assertEqual(
            {entity.properties["owner"] for entity in alice_snapshot.entities},
            {"synthetic-alice-only"},
        )
        self.assertEqual(
            {entity.entity_id for entity in bob_snapshot.entities},
            {bob_entity},
        )
        self.assertEqual(
            {entity.properties["owner"] for entity in bob_snapshot.entities},
            {"synthetic-bob-only"},
        )

    def test_vault_snapshot_overflow_fails_instead_of_truncating(self) -> None:
        _, context = self.create_alice()
        first = self.service.create_entity(context, "Synthetic", {"index": 1})
        second = self.service.create_entity(context, "Synthetic", {"index": 2})
        third = self.service.create_entity(context, "Synthetic", {"index": 3})
        self.service.connect(context, first, second, "LINKS", {"index": 1})
        self.service.connect(context, second, third, "LINKS", {"index": 2})

        with self.assertRaisesRegex(ValidationError, "complete vault"):
            self.service.get_vault_snapshot(
                context,
                entity_limit=2,
                relationship_limit=2,
            )
        with self.assertRaisesRegex(ValidationError, "complete vault"):
            self.service.get_vault_snapshot(
                context,
                entity_limit=3,
                relationship_limit=1,
            )

        complete = self.service.get_vault_snapshot(
            context,
            entity_limit=3,
            relationship_limit=2,
        )
        self.assertEqual(len(complete.entities), 3)
        self.assertEqual(len(complete.relationships), 2)

    def test_vault_snapshot_limits_require_exact_bounded_integers(self) -> None:
        _, context = self.create_alice()
        for entity_limit in (0, -1, 101, True, 1.0, "1"):
            with self.subTest(
                entity_limit=entity_limit
            ), self.assertRaises(ValidationError):
                self.service.get_vault_snapshot(
                    context,
                    entity_limit=entity_limit,  # type: ignore[arg-type]
                )
        for relationship_limit in (0, -1, 201, True, 1.0, "1"):
            with self.subTest(
                relationship_limit=relationship_limit
            ), self.assertRaises(ValidationError):
                self.service.get_vault_snapshot(
                    context,
                    relationship_limit=relationship_limit,  # type: ignore[arg-type]
                )

    def test_vault_snapshot_rejects_aggregate_ciphertext_over_cap(self) -> None:
        vault_id, context = self.create_alice()
        self.service.create_entity(context, "Synthetic", {"index": 1})
        self.service.create_entity(context, "Synthetic", {"index": 2})
        vault = self.repository.get_vault("idp|owner-alice", vault_id)
        self.assertIsNotNone(vault)
        assert vault is not None
        encrypted = self.repository.get_vault_snapshot(
            "idp|owner-alice",
            vault_id,
            vault.envelope.envelope_revision,
            entity_limit=2,
            relationship_limit=1,
        )
        self.assertIsNotNone(encrypted)
        assert encrypted is not None
        per_row_size = MAX_VAULT_SNAPSHOT_CIPHERTEXT_BYTES // 2 + 1
        oversized = replace(
            encrypted,
            entities=tuple(
                replace(
                    row,
                    payload=replace(
                        row.payload,
                        ciphertext=b"x" * per_row_size,
                    ),
                )
                for row in encrypted.entities
            ),
        )

        with patch.object(
            self.repository,
            "get_vault_snapshot",
            return_value=oversized,
        ), self.assertRaisesRegex(ValidationError, "complete vault"):
            self.service.get_vault_snapshot(
                context,
                entity_limit=2,
                relationship_limit=1,
            )

    def test_vault_snapshot_fails_closed_on_structural_row_corruption(
        self,
    ) -> None:
        vault_id, context = self.create_alice()
        first = self.service.create_entity(context, "Synthetic", {"index": 1})
        second = self.service.create_entity(context, "Synthetic", {"index": 2})
        self.service.connect(context, first, second, "LINKS")
        vault = self.repository.get_vault("idp|owner-alice", vault_id)
        self.assertIsNotNone(vault)
        assert vault is not None
        encrypted = self.repository.get_vault_snapshot(
            "idp|owner-alice",
            vault_id,
            vault.envelope.envelope_revision,
            entity_limit=10,
            relationship_limit=10,
        )
        self.assertIsNotNone(encrypted)
        assert encrypted is not None
        self.assertEqual(len(encrypted.entities), 2)
        self.assertEqual(len(encrypted.relationships), 1)

        duplicate_entity_id = replace(
            encrypted,
            entities=encrypted.entities + (encrypted.entities[0],),
        )
        duplicate_relationship_id = replace(
            encrypted,
            relationships=(
                encrypted.relationships + (encrypted.relationships[0],)
            ),
        )
        missing_endpoint = replace(
            encrypted,
            relationships=(
                replace(
                    encrypted.relationships[0],
                    to_entity_id="opaque-missing-endpoint",
                ),
            ),
        )
        cross_vault_entity = replace(
            encrypted,
            entities=(
                replace(
                    encrypted.entities[0],
                    vault_id="opaque-other-vault",
                ),
                encrypted.entities[1],
            ),
        )
        cross_vault_relationship = replace(
            encrypted,
            relationships=(
                replace(
                    encrypted.relationships[0],
                    vault_id="opaque-other-vault",
                ),
            ),
        )
        corruptions = {
            "duplicate entity ID": duplicate_entity_id,
            "duplicate relationship ID": duplicate_relationship_id,
            "missing relationship endpoint": missing_endpoint,
            "cross-vault entity row": cross_vault_entity,
            "cross-vault relationship row": cross_vault_relationship,
        }

        for description, corrupted in corruptions.items():
            with self.subTest(description=description), patch.object(
                self.repository,
                "get_vault_snapshot",
                return_value=corrupted,
            ), self.assertRaises(IntegrityViolation):
                self.service.get_vault_snapshot(context)

    def test_password_change_rewraps_key_and_revokes_old_sessions(self) -> None:
        vault_id, old_context = self.create_alice()
        before = self.repository.get_vault("idp|owner-alice", vault_id)
        self.assertIsNotNone(before)
        entity_id = self.service.create_entity(
            old_context,
            "Preference",
            {"value": "synthetic"},
        )

        self.service.change_passphrase(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
            self.ALICE_NEW_PASSWORD,
        )
        after = self.repository.get_vault("idp|owner-alice", vault_id)
        self.assertIsNotNone(after)
        assert before is not None and after is not None
        self.assertEqual(
            after.envelope.envelope_revision,
            before.envelope.envelope_revision + 1,
        )
        self.assertEqual(
            after.envelope.key_version,
            before.envelope.key_version,
        )
        self.assertNotEqual(
            after.envelope.wrapped_dek,
            before.envelope.wrapped_dek,
        )

        with self.assertRaises(SessionUnavailable):
            self.service.get_entity(old_context, entity_id)
        with self.assertRaises(UnlockDenied):
            self.service.unlock(
                "idp|owner-alice",
                vault_id,
                self.ALICE_PASSWORD,
            )

        new_context = self.service.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_NEW_PASSWORD,
        )
        self.assertEqual(
            self.service.get_entity(new_context, entity_id).kind,
            "Preference",
        )

    def test_ambiguous_password_commit_conservatively_revokes_sessions(self) -> None:
        repository = AmbiguousEnvelopeRepository()
        sessions = InMemorySessionBroker(
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(sessions.close_all)
        service = AuthGraphService(repository, self.crypto, sessions)
        vault_id = service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        old_context = service.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
        )

        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            service.change_passphrase(
                "idp|owner-alice",
                vault_id,
                self.ALICE_PASSWORD,
                self.ALICE_NEW_PASSWORD,
            )

        with self.assertRaises(SessionUnavailable):
            with sessions.lease(old_context):
                self.fail("Ambiguous commit retained an old DEK session.")
        with self.assertRaises(SessionUnavailable):
            service.unlock(
                "idp|owner-alice",
                vault_id,
                self.ALICE_NEW_PASSWORD,
            )
        self.assertEqual(
            service.reconcile_passphrase_change(
                "idp|owner-alice",
                vault_id,
            ),
            2,
        )
        new_context = service.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_NEW_PASSWORD,
        )
        service.lock(new_context)

    def test_shared_broker_serializes_unlock_and_password_change(self) -> None:
        repository = InMemoryGraphRepository()
        crypto = BlockingUnwrapCrypto()
        sessions = InMemorySessionBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(sessions.close_all)
        # Separate service objects model two request workers sharing one
        # trusted in-process broker and its lifecycle guards.
        unlocking_service = AuthGraphService(repository, crypto, sessions)
        changing_service = AuthGraphService(repository, crypto, sessions)
        vault_id = unlocking_service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        crypto.arm()
        unlock_result: dict[str, object] = {}

        def stale_unlock() -> None:
            try:
                unlock_result["context"] = unlocking_service.unlock(
                    "idp|owner-alice",
                    vault_id,
                    self.ALICE_PASSWORD,
                )
            except BaseException as exc:
                unlock_result["error"] = exc

        unlock_thread = threading.Thread(target=stale_unlock)
        unlock_thread.start()
        self.assertTrue(crypto.unwrap_started.wait(timeout=2))

        change_result: dict[str, object] = {}
        change_started = threading.Event()

        def change_password() -> None:
            change_started.set()
            try:
                changing_service.change_passphrase(
                    "idp|owner-alice",
                    vault_id,
                    self.ALICE_PASSWORD,
                    self.ALICE_NEW_PASSWORD,
                )
            except BaseException as exc:
                change_result["error"] = exc

        change_thread = threading.Thread(target=change_password)
        change_thread.start()
        self.assertTrue(change_started.wait(timeout=2))
        crypto.release_unwrap.set()
        unlock_thread.join(timeout=5)
        change_thread.join(timeout=5)

        self.assertFalse(unlock_thread.is_alive())
        self.assertFalse(change_thread.is_alive())
        self.assertNotIn("error", unlock_result)
        self.assertNotIn("error", change_result)
        self.assertIn("context", unlock_result)
        self.assertEqual(sessions.active_count, 0)
        with self.assertRaises(UnlockDenied):
            unlocking_service.unlock(
                "idp|owner-alice",
                vault_id,
                self.ALICE_PASSWORD,
            )
        new_context = unlocking_service.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_NEW_PASSWORD,
        )
        self.assertEqual(sessions.active_count, 1)
        unlocking_service.lock(new_context)

    def test_shutdown_fences_an_in_flight_unlock_before_returning(self) -> None:
        repository = InMemoryGraphRepository()
        crypto = BlockingUnwrapCrypto()
        sessions = InMemorySessionBroker(
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(sessions.close_all)
        service = AuthGraphService(repository, crypto, sessions)
        vault_id = service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        crypto.arm()
        unlock_result: dict[str, object] = {}
        close_result: dict[str, object] = {}

        def unlock() -> None:
            try:
                unlock_result["context"] = service.unlock(
                    "idp|owner-alice",
                    vault_id,
                    self.ALICE_PASSWORD,
                )
            except BaseException as exc:
                unlock_result["error"] = exc

        def shutdown() -> None:
            close_result["count"] = sessions.close_all()

        unlock_thread = threading.Thread(target=unlock)
        unlock_thread.start()
        self.assertTrue(crypto.unwrap_started.wait(timeout=2))
        close_thread = threading.Thread(target=shutdown)
        close_thread.start()
        for _ in range(200):
            if sessions.closed:
                break
            threading.Event().wait(0.01)
        self.assertTrue(sessions.closed)
        crypto.release_unwrap.set()
        unlock_thread.join(timeout=5)
        close_thread.join(timeout=5)

        self.assertFalse(unlock_thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertNotIn("context", unlock_result)
        self.assertIsInstance(unlock_result.get("error"), SessionUnavailable)
        self.assertEqual(close_result.get("count"), 0)
        self.assertEqual(sessions.active_count, 0)

    def test_concurrent_close_waits_for_key_zeroization(self) -> None:
        broker = InMemorySessionBroker(
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close_all)
        broker.open(
            "principal-1",
            "vault-1",
            b"a" * 32,
            envelope_revision=1,
            key_version=1,
        )
        resident_dek = next(iter(broker._records.values())).dek
        clear_started = threading.Event()
        allow_clear = threading.Event()
        second_returned = threading.Event()
        results: dict[str, int] = {}
        errors: list[BaseException] = []

        def blocking_clear(value: bytearray) -> None:
            if value is resident_dek and not clear_started.is_set():
                clear_started.set()
                if not allow_clear.wait(timeout=5):
                    raise RuntimeError("Timed out waiting to clear a test DEK.")
            clear_bytearray(value)

        def first_close() -> None:
            try:
                results["first"] = broker.close_all()
            except BaseException as exc:
                errors.append(exc)

        def second_close() -> None:
            try:
                results["second"] = broker.close_all()
            except BaseException as exc:
                errors.append(exc)
            finally:
                second_returned.set()

        first_thread = threading.Thread(target=first_close)
        second_thread = threading.Thread(target=second_close)
        second_started = False
        with patch.object(
            sessions_module,
            "clear_bytearray",
            side_effect=blocking_clear,
        ):
            first_thread.start()
            clear_was_reached = clear_started.wait(timeout=2)
            if clear_was_reached:
                second_thread.start()
                second_started = True
                second_returned_early = second_returned.wait(timeout=0.05)
                key_was_zeroed_early = resident_dek == bytearray(32)
            else:
                second_returned_early = False
                key_was_zeroed_early = False
            allow_clear.set()
            first_thread.join(timeout=5)
            if second_started:
                second_thread.join(timeout=5)

        self.assertTrue(clear_was_reached)
        self.assertTrue(second_started)
        self.assertFalse(second_returned_early)
        self.assertFalse(key_was_zeroed_early)
        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, {"first": 1, "second": 0})
        self.assertEqual(resident_dek, bytearray(32))

    def test_shutdown_waits_for_concurrent_expiry_purge_zeroization(self) -> None:
        broker = InMemorySessionBroker(
            default_ttl_seconds=1,
            max_ttl_seconds=10,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close_all)
        broker.open(
            "principal-1",
            "vault-1",
            b"a" * 32,
            envelope_revision=1,
            key_version=1,
        )
        resident_dek = next(iter(broker._records.values())).dek
        self.clock.advance(2)
        clear_started = threading.Event()
        allow_clear = threading.Event()
        close_returned = threading.Event()
        results: dict[str, int] = {}
        errors: list[BaseException] = []

        def blocking_clear(value: bytearray) -> None:
            if value is resident_dek and not clear_started.is_set():
                clear_started.set()
                if not allow_clear.wait(timeout=5):
                    raise RuntimeError("Timed out waiting to clear a test DEK.")
            clear_bytearray(value)

        def purge() -> None:
            try:
                results["purged"] = broker.purge_expired()
            except BaseException as exc:
                errors.append(exc)

        def close() -> None:
            try:
                results["closed"] = broker.close_all()
            except BaseException as exc:
                errors.append(exc)
            finally:
                close_returned.set()

        purge_thread = threading.Thread(target=purge)
        close_thread = threading.Thread(target=close)
        close_started = False
        with patch.object(
            sessions_module,
            "clear_bytearray",
            side_effect=blocking_clear,
        ):
            purge_thread.start()
            clear_was_reached = clear_started.wait(timeout=2)
            if clear_was_reached:
                close_thread.start()
                close_started = True
                close_returned_early = close_returned.wait(timeout=0.05)
            else:
                close_returned_early = False
            allow_clear.set()
            purge_thread.join(timeout=5)
            if close_started:
                close_thread.join(timeout=5)

        self.assertTrue(clear_was_reached)
        self.assertTrue(close_started)
        self.assertFalse(close_returned_early)
        self.assertFalse(purge_thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, {"purged": 1, "closed": 0})
        self.assertEqual(resident_dek, bytearray(32))

    def test_stale_session_in_another_broker_is_fenced_at_repository(self) -> None:
        repository = InMemoryGraphRepository()
        crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        old_broker = InMemorySessionBroker(
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        changing_broker = InMemorySessionBroker(
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(old_broker.close_all)
        self.addCleanup(changing_broker.close_all)
        old_worker = AuthGraphService(repository, crypto, old_broker)
        changing_worker = AuthGraphService(repository, crypto, changing_broker)
        vault_id = old_worker.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        stale_context = old_worker.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
        )
        entity_id = old_worker.create_entity(
            stale_context,
            "Synthetic",
            {"value": "before-change"},
        )

        changing_worker.change_passphrase(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
            self.ALICE_NEW_PASSWORD,
        )

        # The separate old broker has not received revocation, but every
        # repository operation also matches the authenticated revision.
        with self.assertRaises(RecordNotFound):
            old_worker.get_entity(stale_context, entity_id)
        with self.assertRaises(ConflictError):
            old_worker.create_entity(stale_context, "MustFail", {})

    def test_in_flight_write_finishes_before_password_change_returns(self) -> None:
        repository = BlockingPutRepository()
        crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        sessions = InMemorySessionBroker(
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(sessions.close_all)
        writer = AuthGraphService(repository, crypto, sessions)
        changer = AuthGraphService(repository, crypto, sessions)
        vault_id = writer.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        context = writer.unlock(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
        )
        errors: list[BaseException] = []

        def write_entity() -> None:
            try:
                writer.create_entity(context, "Synthetic", {"value": 1})
            except BaseException as exc:
                errors.append(exc)

        def change_password() -> None:
            try:
                changer.change_passphrase(
                    "idp|owner-alice",
                    vault_id,
                    self.ALICE_PASSWORD,
                    self.ALICE_NEW_PASSWORD,
                )
                repository.order.append("change")
            except BaseException as exc:
                errors.append(exc)

        write_thread = threading.Thread(target=write_entity)
        write_thread.start()
        self.assertTrue(repository.put_started.wait(timeout=2))
        change_thread = threading.Thread(target=change_password)
        change_thread.start()
        repository.release_put.set()
        write_thread.join(timeout=5)
        change_thread.join(timeout=5)

        self.assertFalse(write_thread.is_alive())
        self.assertFalse(change_thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(repository.order, ["put", "change"])
        with self.assertRaises(SessionUnavailable):
            writer.create_entity(context, "AfterRevocation", {})

    def test_envelope_replacement_is_compare_and_swap(self) -> None:
        vault_id = self.service.create_vault(
            "idp|owner-alice",
            self.ALICE_PASSWORD,
        )
        row = self.repository.get_vault("idp|owner-alice", vault_id)
        self.assertIsNotNone(row)
        assert row is not None
        dek = self.crypto.unwrap_dek(
            "idp|owner-alice",
            vault_id,
            self.ALICE_PASSWORD,
            row.envelope,
        )
        try:
            replacement = self.crypto.wrap_dek(
                "idp|owner-alice",
                vault_id,
                self.ALICE_NEW_PASSWORD,
                dek,
                envelope_revision=row.envelope.envelope_revision + 1,
                key_version=row.envelope.key_version,
            )
        finally:
            clear_bytearray(dek)

        self.assertTrue(
            self.repository.replace_envelope(
                "idp|owner-alice",
                vault_id,
                row.envelope.envelope_revision,
                replacement,
            )
        )
        self.assertFalse(
            self.repository.replace_envelope(
                "idp|owner-alice",
                vault_id,
                row.envelope.envelope_revision,
                replacement,
            )
        )

    def test_neighborhood_size_is_bounded(self) -> None:
        _, context = self.create_alice()
        center = self.service.create_entity(context, "Center", {})
        with self.assertRaises(ValidationError):
            self.service.get_neighborhood(context, center, limit=101)
        for invalid_limit in (float("nan"), True, 1.0):
            with self.subTest(limit=invalid_limit), self.assertRaises(
                ValidationError
            ):
                self.service.get_neighborhood(
                    context,
                    center,
                    limit=invalid_limit,  # type: ignore[arg-type]
                )

    def test_graph_object_ids_are_bounded_before_storage_or_aad(self) -> None:
        _, context = self.create_alice()
        valid = self.service.create_entity(context, "Synthetic", {})
        invalid_ids: tuple[object, ...] = (
            "x" * 257,
            "line\nbreak",
            123,
        )
        for object_id in invalid_ids:
            with self.subTest(object_id=object_id), self.assertRaises(
                ValidationError
            ):
                self.service.get_entity(
                    context,
                    object_id,  # type: ignore[arg-type]
                )
            with self.subTest(object_id=object_id), self.assertRaises(
                ValidationError
            ):
                self.service.connect(
                    context,
                    valid,
                    object_id,  # type: ignore[arg-type]
                    "MustFail",
                )

    def test_all_neo4j_operations_are_fixed_and_vault_scoped(self) -> None:
        query_names = (
            "_CREATE_VAULT",
            "_GET_VAULT",
            "_REPLACE_ENVELOPE",
            "_PUT_ENTITY",
            "_GET_ENTITY",
            "_PUT_RELATIONSHIP",
            "_PUT_ENTITY_RELATIONSHIP_BUNDLE",
            "_GET_NEIGHBORS",
            "_GET_RELATIONSHIP",
            "_GET_VAULT_SNAPSHOT",
        )
        for name in query_names:
            query = getattr(Neo4jGraphRepository, name)
            self.assertIn("$principal_id", query, name)
            self.assertIn("$vault_id", query, name)
        self.assertNotIn("$kind", Neo4jGraphRepository._PUT_ENTITY)
        self.assertNotIn("$properties", Neo4jGraphRepository._PUT_ENTITY)
        self.assertNotIn("$kind", Neo4jGraphRepository._PUT_RELATIONSHIP)
        self.assertNotIn(
            "$kind",
            Neo4jGraphRepository._PUT_ENTITY_RELATIONSHIP_BUNDLE,
        )
        self.assertNotIn(
            "$properties",
            Neo4jGraphRepository._PUT_ENTITY_RELATIONSHIP_BUNDLE,
        )
        self.assertIn(
            "vault.envelope_revision = $expected_revision",
            Neo4jGraphRepository._REPLACE_ENVELOPE,
        )
        for name in (
            "_PUT_ENTITY",
            "_GET_ENTITY",
            "_PUT_RELATIONSHIP",
            "_PUT_ENTITY_RELATIONSHIP_BUNDLE",
            "_GET_NEIGHBORS",
            "_GET_RELATIONSHIP",
            "_GET_VAULT_SNAPSHOT",
        ):
            self.assertIn("$envelope_revision", getattr(Neo4jGraphRepository, name))
        for name in (
            "_REPLACE_ENVELOPE",
            "_PUT_ENTITY",
            "_PUT_RELATIONSHIP",
            "_PUT_ENTITY_RELATIONSHIP_BUNDLE",
            "_GET_VAULT_SNAPSHOT",
        ):
            query = getattr(Neo4jGraphRepository, name)
            self.assertIn("SET vault._authgraph_lock = true", query)
            self.assertIn("REMOVE vault._authgraph_lock", query)
            self.assertLess(
                query.index("SET vault._authgraph_lock"),
                query.index("vault.envelope_revision"),
            )

    def test_neo4j_adapter_sends_ciphertext_with_explicit_database(self) -> None:
        driver = RecordingDriver([{"created": 1}])
        repository = Neo4jGraphRepository(driver, database="authgraph")
        row = EncryptedEntityRow(
            vault_id="opaque-vault",
            entity_id="opaque-entity",
            payload=EncryptedPayload(
                version=1,
                key_version=1,
                algorithm="AES-256-GCM",
                nonce=b"n" * 12,
                ciphertext=b"ciphertext-and-tag",
            ),
        )

        self.assertTrue(
            repository.put_entity(
                "opaque-principal",
                "opaque-vault",
                1,
                row,
            )
        )
        _, kwargs = driver.calls[0]
        self.assertEqual(kwargs["database_"], "authgraph")
        parameters = kwargs["parameters_"]
        self.assertIsInstance(parameters, dict)
        self.assertEqual(parameters["ciphertext"], b"ciphertext-and-tag")
        self.assertNotIn("kind", parameters)
        self.assertNotIn("properties", parameters)

    def test_neo4j_adapter_sends_atomic_bundle_as_ciphertext_only(self) -> None:
        driver = RecordingDriver(
            [{"created_entities": 2, "created_relationships": 1}]
        )
        repository = Neo4jGraphRepository(driver, database="authgraph")
        first = EncryptedEntityRow(
            vault_id="opaque-vault",
            entity_id="helper-one",
            payload=EncryptedPayload(
                version=1,
                key_version=1,
                algorithm="AES-256-GCM",
                nonce=b"a" * 12,
                ciphertext=b"first-ciphertext-and-tag",
            ),
        )
        second = EncryptedEntityRow(
            vault_id="opaque-vault",
            entity_id="helper-two",
            payload=EncryptedPayload(
                version=1,
                key_version=1,
                algorithm="AES-256-GCM",
                nonce=b"b" * 12,
                ciphertext=b"second-ciphertext-and-tag",
            ),
        )
        relationship = EncryptedRelationshipRow(
            vault_id="opaque-vault",
            relationship_id="opaque-link",
            from_entity_id=first.entity_id,
            to_entity_id=second.entity_id,
            payload=EncryptedPayload(
                version=1,
                key_version=1,
                algorithm="AES-256-GCM",
                nonce=b"c" * 12,
                ciphertext=b"link-ciphertext-and-tag",
            ),
        )

        self.assertTrue(
            repository.put_entity_relationship_bundle(
                "opaque-principal",
                "opaque-vault",
                1,
                (first, second),
                relationship,
            )
        )
        query, kwargs = driver.calls[0]
        self.assertEqual(
            query,
            Neo4jGraphRepository._PUT_ENTITY_RELATIONSHIP_BUNDLE,
        )
        parameters = kwargs["parameters_"]
        self.assertEqual(kwargs["database_"], "authgraph")
        self.assertEqual(
            [row["ciphertext"] for row in parameters["entity_rows"]],
            [
                b"first-ciphertext-and-tag",
                b"second-ciphertext-and-tag",
            ],
        )
        self.assertEqual(
            parameters["relationship_ciphertext"],
            b"link-ciphertext-and-tag",
        )
        self.assertNotIn("kind", repr(parameters))
        self.assertNotIn("properties", repr(parameters))

    def test_neo4j_atomic_bundle_reconciles_incomplete_commit_exactly(
        self,
    ) -> None:
        entity_payload = EncryptedPayload(
            version=1,
            key_version=1,
            algorithm="AES-256-GCM",
            nonce=b"a" * 12,
            ciphertext=b"entity-ciphertext-and-tag",
        )
        relationship_payload = EncryptedPayload(
            version=1,
            key_version=1,
            algorithm="AES-256-GCM",
            nonce=b"b" * 12,
            ciphertext=b"relationship-ciphertext-and-tag",
        )
        entity = EncryptedEntityRow(
            vault_id="opaque-vault",
            entity_id="helper-one",
            payload=entity_payload,
        )
        relationship = EncryptedRelationshipRow(
            vault_id="opaque-vault",
            relationship_id="opaque-link",
            from_entity_id=entity.entity_id,
            to_entity_id=entity.entity_id,
            payload=relationship_payload,
        )
        driver = SequencedRecordingDriver(
            [
                IncompleteCommit(),
                [
                    {
                        "payload_version": entity_payload.version,
                        "key_version": entity_payload.key_version,
                        "algorithm": entity_payload.algorithm,
                        "nonce": entity_payload.nonce,
                        "ciphertext": entity_payload.ciphertext,
                    }
                ],
                [
                    {
                        "payload_version": relationship_payload.version,
                        "key_version": relationship_payload.key_version,
                        "algorithm": relationship_payload.algorithm,
                        "nonce": relationship_payload.nonce,
                        "ciphertext": relationship_payload.ciphertext,
                    }
                ],
            ]
        )
        repository = Neo4jGraphRepository(driver, database="authgraph")

        self.assertTrue(
            repository.put_entity_relationship_bundle(
                "opaque-principal",
                "opaque-vault",
                1,
                (entity,),
                relationship,
            )
        )
        self.assertEqual(len(driver.calls), 3)

    def test_neo4j_adapter_decodes_snapshot_and_fetches_limit_plus_one(
        self,
    ) -> None:
        driver = RecordingDriver(
            [
                {
                    "entities": [
                        {
                            "entity_id": "opaque-entity",
                            "payload_version": 1,
                            "key_version": 2,
                            "algorithm": "AES-256-GCM",
                            "nonce": b"e" * 12,
                            "ciphertext": b"entity-ciphertext-and-tag",
                        }
                    ],
                    "relationships": [
                        {
                            "relationship_id": "opaque-link",
                            "from_entity_id": "opaque-entity",
                            "to_entity_id": "opaque-other-entity",
                            "payload_version": 1,
                            "key_version": 2,
                            "algorithm": "AES-256-GCM",
                            "nonce": b"r" * 12,
                            "ciphertext": b"relationship-ciphertext-and-tag",
                        }
                    ],
                }
            ]
        )
        repository = Neo4jGraphRepository(driver, database="authgraph")

        snapshot = repository.get_vault_snapshot(
            "opaque-principal",
            "opaque-vault",
            7,
            entity_limit=5,
            relationship_limit=8,
        )

        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(len(snapshot.entities), 1)
        self.assertEqual(snapshot.entities[0].vault_id, "opaque-vault")
        self.assertEqual(snapshot.entities[0].entity_id, "opaque-entity")
        self.assertEqual(snapshot.entities[0].payload.key_version, 2)
        self.assertEqual(
            snapshot.entities[0].payload.ciphertext,
            b"entity-ciphertext-and-tag",
        )
        self.assertEqual(len(snapshot.relationships), 1)
        self.assertEqual(
            snapshot.relationships[0].relationship_id,
            "opaque-link",
        )
        self.assertEqual(
            snapshot.relationships[0].from_entity_id,
            "opaque-entity",
        )
        self.assertEqual(
            snapshot.relationships[0].to_entity_id,
            "opaque-other-entity",
        )
        self.assertEqual(
            snapshot.relationships[0].payload.ciphertext,
            b"relationship-ciphertext-and-tag",
        )

        self.assertEqual(len(driver.calls), 1)
        query, kwargs = driver.calls[0]
        self.assertEqual(query, Neo4jGraphRepository._GET_VAULT_SNAPSHOT)
        self.assertEqual(kwargs["database_"], "authgraph")
        parameters = kwargs["parameters_"]
        self.assertIsInstance(parameters, dict)
        self.assertEqual(parameters["principal_id"], "opaque-principal")
        self.assertEqual(parameters["vault_id"], "opaque-vault")
        self.assertEqual(parameters["envelope_revision"], 7)
        self.assertEqual(parameters["entity_fetch_limit"], 6)
        self.assertEqual(parameters["relationship_fetch_limit"], 9)

    def test_neo4j_adapter_rejects_unencrypted_driver(self) -> None:
        driver = RecordingDriver([])
        driver.encrypted = False
        with self.assertRaisesRegex(ValueError, "encrypted transport"):
            Neo4jGraphRepository(driver, database="authgraph")

    def test_neo4j_write_retry_accepts_only_the_exact_existing_row(self) -> None:
        row = EncryptedEntityRow(
            vault_id="opaque-vault",
            entity_id="opaque-entity",
            payload=EncryptedPayload(
                version=1,
                key_version=1,
                algorithm="AES-256-GCM",
                nonce=b"n" * 12,
                ciphertext=b"ciphertext-and-tag",
            ),
        )
        driver = SequencedRecordingDriver(
            [
                [{"created": 0}],
                [
                    {
                        "payload_version": 1,
                        "key_version": 1,
                        "algorithm": "AES-256-GCM",
                        "nonce": b"n" * 12,
                        "ciphertext": b"ciphertext-and-tag",
                    }
                ],
            ]
        )
        repository = Neo4jGraphRepository(driver, database="authgraph")

        self.assertTrue(
            repository.put_entity(
                "opaque-principal",
                "opaque-vault",
                1,
                row,
            )
        )
        self.assertEqual(len(driver.calls), 2)
        self.assertIn("CREATE (entity:AGEntity", driver.calls[0][0])
        self.assertIn("RETURN", driver.calls[1][0])

    def test_neo4j_incomplete_commit_reconciles_the_exact_row(self) -> None:
        row = EncryptedEntityRow(
            vault_id="opaque-vault",
            entity_id="opaque-entity",
            payload=EncryptedPayload(
                version=1,
                key_version=1,
                algorithm="AES-256-GCM",
                nonce=b"n" * 12,
                ciphertext=b"ciphertext-and-tag",
            ),
        )
        driver = SequencedRecordingDriver(
            [
                IncompleteCommit("synthetic ambiguous commit"),
                [
                    {
                        "payload_version": 1,
                        "key_version": 1,
                        "algorithm": "AES-256-GCM",
                        "nonce": b"n" * 12,
                        "ciphertext": b"ciphertext-and-tag",
                    }
                ],
            ]
        )
        repository = Neo4jGraphRepository(driver, database="authgraph")

        self.assertTrue(
            repository.put_entity(
                "opaque-principal",
                "opaque-vault",
                1,
                row,
            )
        )
        self.assertEqual(len(driver.calls), 2)

    def test_neo4j_adapter_rejects_row_scope_mismatch_before_query(self) -> None:
        driver = RecordingDriver([{"created": 1}])
        repository = Neo4jGraphRepository(driver, database="authgraph")
        payload = EncryptedPayload(
            version=1,
            key_version=1,
            algorithm="AES-256-GCM",
            nonce=b"n" * 12,
            ciphertext=b"ciphertext-and-tag",
        )
        entity = EncryptedEntityRow(
            vault_id="different-vault",
            entity_id="opaque-entity",
            payload=payload,
        )
        relationship = EncryptedRelationshipRow(
            vault_id="different-vault",
            relationship_id="opaque-link",
            from_entity_id="from",
            to_entity_id="to",
            payload=payload,
        )

        self.assertFalse(
            repository.put_entity(
                "opaque-principal",
                "requested-vault",
                1,
                entity,
            )
        )
        self.assertFalse(
            repository.put_relationship(
                "opaque-principal",
                "requested-vault",
                1,
                relationship,
            )
        )
        self.assertEqual(driver.calls, [])

    def test_neo4j_adapter_normalizes_malformed_storage_metadata(self) -> None:
        malformed_payload_driver = RecordingDriver(
            [
                {
                    "payload_version": 1,
                    "key_version": 1,
                    "algorithm": "AES-256-GCM",
                    "nonce": 12,
                    "ciphertext": b"ciphertext-and-tag",
                }
            ]
        )
        repository = Neo4jGraphRepository(
            malformed_payload_driver,
            database="authgraph",
        )
        with self.assertRaises(IntegrityViolation):
            repository.get_entity(
                "opaque-principal",
                "opaque-vault",
                1,
                "opaque-entity",
            )

        malformed_envelope_driver = RecordingDriver(
            [{"envelope_version": 1}]
        )
        repository = Neo4jGraphRepository(
            malformed_envelope_driver,
            database="authgraph",
        )
        with self.assertRaises(IntegrityViolation):
            repository.get_vault("opaque-principal", "opaque-vault")

    def test_neo4j_adapter_rejects_malformed_snapshot_nested_lists(
        self,
    ) -> None:
        malformed_snapshots = (
            {
                "entities": {"entity_id": "not-a-list"},
                "relationships": [],
            },
            {
                "entities": [None],
                "relationships": [],
            },
            {
                "entities": [],
                "relationships": ["not-a-row"],
            },
        )
        for malformed in malformed_snapshots:
            with self.subTest(malformed=malformed):
                repository = Neo4jGraphRepository(
                    RecordingDriver([malformed]),
                    database="authgraph",
                )
                with self.assertRaises(IntegrityViolation):
                    repository.get_vault_snapshot(
                        "opaque-principal",
                        "opaque-vault",
                        1,
                        entity_limit=5,
                        relationship_limit=5,
                    )


if __name__ == "__main__":
    unittest.main()
