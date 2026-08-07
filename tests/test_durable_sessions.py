from __future__ import annotations

import multiprocessing
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import authgraph.durable_sessions as durable_sessions_module
from authgraph.crypto import CryptoEngine
from authgraph.durable_sessions import DurableScopedSessionBroker
from authgraph.errors import SessionUnavailable
from authgraph.key_custody import InMemoryAesKeyWrappingBackend
from authgraph.lifecycle import VaultLifecyclePhase
from authgraph.memory_repository import InMemoryGraphRepository
from authgraph.models import AccessContext, KdfParameters
from authgraph.scoped_service import ScopedAuthGraphService
from authgraph.scoped_sessions import ScopeKeyMaterial


class Clock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class SystemExitEnvelopeRepository(InMemoryGraphRepository):
    """Commit the envelope and simulate process termination before return."""

    def replace_envelope(self, *args: object, **kwargs: object) -> bool:
        replaced = super().replace_envelope(*args, **kwargs)
        if replaced:
            raise SystemExit("synthetic termination after envelope commit")
        return False


def _crash_with_active_lease(
    path: str,
    token_key: bytes,
    wrapping_key: bytes,
    context: AccessContext,
    now: float,
    ready: object,
) -> None:
    backend = InMemoryAesKeyWrappingBackend(
        backend_id="test-session-kms-v1",
        key_id="test-session-key-v1",
        wrapping_key=wrapping_key,
    )
    broker = DurableScopedSessionBroker(
        path,
        token_key,
        {backend.backend_id: backend},
        active_backend_id=backend.backend_id,
        default_ttl_seconds=300,
        max_ttl_seconds=600,
        lease_ttl_seconds=30,
        clock=lambda: now,
    )
    with broker.guarded_lease(context):
        ready.set()
        os._exit(0)


def _construct_durable_broker(
    path: str,
    token_key: bytes,
    wrapping_key: bytes,
    start: object,
    results: object,
) -> None:
    backend = InMemoryAesKeyWrappingBackend(
        backend_id="test-session-kms-v1",
        key_id="test-session-key-v1",
        wrapping_key=wrapping_key,
    )
    try:
        start.wait(10)
        broker = DurableScopedSessionBroker(
            path,
            token_key,
            {backend.backend_id: backend},
            active_backend_id=backend.backend_id,
        )
        broker.close_all()
        results.put("success")
    except BaseException as exc:
        results.put(type(exc).__name__)
    finally:
        backend.close()


class DurableScopedSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name, "sessions.sqlite3")
        self.token_key = b"t" * 32
        self.wrapping_key = b"w" * 32
        self.clock = Clock()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def broker(
        self,
        *,
        path: Path | None = None,
        lease_ttl_seconds: int = 60,
        guard_ttl_seconds: int = 60,
    ) -> tuple[
        DurableScopedSessionBroker,
        InMemoryAesKeyWrappingBackend,
    ]:
        backend = InMemoryAesKeyWrappingBackend(
            backend_id="test-session-kms-v1",
            key_id="test-session-key-v1",
            wrapping_key=self.wrapping_key,
        )
        broker = DurableScopedSessionBroker(
            self.path if path is None else path,
            self.token_key,
            {backend.backend_id: backend},
            active_backend_id=backend.backend_id,
            default_ttl_seconds=300,
            max_ttl_seconds=600,
            lease_ttl_seconds=lease_ttl_seconds,
            guard_ttl_seconds=guard_ttl_seconds,
            guard_wait_seconds=2,
            clock=self.clock,
        )
        return broker, backend

    @staticmethod
    def materials() -> dict[str, ScopeKeyMaterial]:
        return {
            "scope-1": ScopeKeyMaterial(1, bytearray(b"a" * 32)),
            "scope-2": ScopeKeyMaterial(2, bytearray(b"b" * 32)),
        }

    @staticmethod
    def clear(materials: dict[str, ScopeKeyMaterial]) -> None:
        for material in materials.values():
            material.dek[:] = b"\x00" * len(material.dek)

    def create_legacy_database(self, path: Path) -> None:
        connection = sqlite3.connect(path)
        try:
            connection.executescript(
                """
                CREATE TABLE authgraph_session (
                    token_digest BLOB PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    vault_id TEXT NOT NULL,
                    envelope_revision INTEGER NOT NULL,
                    root_key_version INTEGER NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    active_leases INTEGER NOT NULL DEFAULT 0,
                    format_version INTEGER NOT NULL
                );
                CREATE TABLE authgraph_session_scope (
                    token_digest BLOB NOT NULL,
                    scope_id TEXT NOT NULL,
                    scope_key_version INTEGER NOT NULL,
                    wrapped_format_version INTEGER NOT NULL,
                    backend_id TEXT NOT NULL,
                    provider_key_id TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    PRIMARY KEY(token_digest, scope_id),
                    FOREIGN KEY(token_digest)
                        REFERENCES authgraph_session(token_digest)
                        ON DELETE CASCADE
                );
                CREATE TABLE authgraph_vault_revision (
                    principal_id TEXT NOT NULL,
                    vault_id TEXT NOT NULL,
                    minimum_envelope_revision INTEGER NOT NULL,
                    PRIMARY KEY(principal_id, vault_id)
                );
                CREATE TABLE authgraph_vault_guard (
                    principal_id TEXT NOT NULL,
                    vault_id TEXT NOT NULL,
                    owner_token TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY(principal_id, vault_id)
                );
                """
            )
            connection.execute(
                "INSERT INTO authgraph_vault_revision VALUES (?, ?, ?)",
                ("principal-1", "vault-1", 1),
            )
            connection.commit()
        finally:
            connection.close()
        path.chmod(0o600)

    def concurrent_broker_start(
        self,
        path: Path,
        *,
        workers: int = 8,
    ) -> tuple[
        list[tuple[DurableScopedSessionBroker, InMemoryAesKeyWrappingBackend]],
        list[BaseException],
    ]:
        barrier = threading.Barrier(workers)
        result_lock = threading.Lock()
        brokers: list[
            tuple[DurableScopedSessionBroker, InMemoryAesKeyWrappingBackend]
        ] = []
        errors: list[BaseException] = []

        def construct() -> None:
            try:
                barrier.wait(timeout=10)
                created = self.broker(path=path)
                with result_lock:
                    brokers.append(created)
            except BaseException as exc:
                with result_lock:
                    errors.append(exc)

        threads = [threading.Thread(target=construct) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        return brokers, errors

    def open_context(self, broker: DurableScopedSessionBroker) -> AccessContext:
        materials = self.materials()
        try:
            return broker.open(
                "principal-1",
                "vault-1",
                materials,
                envelope_revision=1,
                root_key_version=1,
            )
        finally:
            self.clear(materials)

    def test_session_survives_broker_restart(self) -> None:
        first, first_backend = self.broker()
        context = self.open_context(first)
        self.assertEqual(first.active_count, 1)
        first.close_all()
        first_backend.close()

        restarted, backend = self.broker()
        with restarted.guarded_lease(context) as lease:
            self.assertEqual(set(lease.scope_keys), {"scope-1", "scope-2"})
            self.assertEqual(lease.scope_keys["scope-1"].dek, b"a" * 32)
            self.assertEqual(lease.scope_keys["scope-2"].key_version, 2)
        restarted.close(context)
        restarted.close_all()
        backend.close()

    def test_every_reopened_connection_uses_full_synchronous_mode(self) -> None:
        broker, backend = self.broker()
        connection = broker._connect()
        try:
            self.assertEqual(
                str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                "wal",
            )
            self.assertEqual(
                int(connection.execute("PRAGMA synchronous").fetchone()[0]),
                2,
            )
            self.assertEqual(
                int(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
                1,
            )
        finally:
            connection.close()
        broker.close_all()
        backend.close()

    def test_cross_worker_logout_blocks_new_leases(self) -> None:
        first, first_backend = self.broker()
        second, second_backend = self.broker()
        context = self.open_context(first)

        second.close(context)
        with self.assertRaises(SessionUnavailable):
            first.guarded_lease(context).__enter__()
        self.assertEqual(first.active_count, 0)
        first.close_all()
        second.close_all()
        first_backend.close()
        second_backend.close()

    def test_revocation_linearizes_before_new_lease_but_allows_active_finish(
        self,
    ) -> None:
        first, first_backend = self.broker()
        second, second_backend = self.broker()
        context = self.open_context(first)
        entered = threading.Event()
        release = threading.Event()
        observed: list[bytes] = []

        def hold_lease() -> None:
            with first.guarded_lease(context) as lease:
                observed.append(bytes(lease.scope_keys["scope-1"].dek))
                entered.set()
                release.wait(2)

        thread = threading.Thread(target=hold_lease)
        thread.start()
        self.assertTrue(entered.wait(2))
        second.close(context)
        with self.assertRaises(SessionUnavailable):
            with second.guarded_lease(context):
                pass
        release.set()
        thread.join(2)

        self.assertEqual(observed, [b"a" * 32])
        self.assertEqual(second.resident_scope_ciphertext_count, 0)
        first.close_all()
        second.close_all()
        first_backend.close()
        second_backend.close()

    def test_envelope_revision_fence_survives_restart(self) -> None:
        first, first_backend = self.broker()
        context = self.open_context(first)
        self.assertEqual(
            first.advance_envelope_revision("principal-1", "vault-1", 2),
            1,
        )
        first.close_all()
        first_backend.close()

        restarted, backend = self.broker()
        with self.assertRaises(SessionUnavailable):
            with restarted.guarded_lease(context):
                pass
        old_materials = self.materials()
        with self.assertRaises(SessionUnavailable):
            restarted.open(
                "principal-1",
                "vault-1",
                old_materials,
                envelope_revision=1,
                root_key_version=1,
            )
        self.clear(old_materials)
        restarted.close_all()
        backend.close()

    def test_expiry_is_enforced_after_restart(self) -> None:
        first, first_backend = self.broker()
        context = self.open_context(first)
        first.close_all()
        first_backend.close()
        self.clock.value += 301

        restarted, backend = self.broker()
        self.assertEqual(restarted.purge_expired(), 1)
        with self.assertRaises(SessionUnavailable):
            with restarted.guarded_lease(context):
                pass
        self.assertEqual(restarted.active_count, 0)
        restarted.close_all()
        backend.close()

    def test_database_contains_no_token_or_plaintext_scope_key(self) -> None:
        broker, backend = self.broker()
        context = self.open_context(broker)
        broker.close_all()
        backend.close()

        stored = b"".join(
            path.read_bytes()
            for path in Path(self.directory.name).iterdir()
            if path.is_file()
        )
        self.assertNotIn(context.session_token.encode("ascii"), stored)
        self.assertNotIn(b"a" * 32, stored)
        self.assertNotIn(b"b" * 32, stored)

    def test_vault_guard_is_shared_between_broker_instances(self) -> None:
        first, first_backend = self.broker()
        second, second_backend = self.broker()
        entered = threading.Event()
        release = threading.Event()
        order: list[str] = []

        def first_worker() -> None:
            with first.vault_guard("principal-1", "vault-1"):
                order.append("first-enter")
                entered.set()
                release.wait(2)
                order.append("first-exit")

        def second_worker() -> None:
            entered.wait(2)
            with second.vault_guard("principal-1", "vault-1"):
                order.append("second-enter")

        one = threading.Thread(target=first_worker)
        two = threading.Thread(target=second_worker)
        one.start()
        two.start()
        self.assertTrue(entered.wait(2))
        time.sleep(0.05)
        self.assertEqual(order, ["first-enter"])
        release.set()
        one.join(2)
        two.join(2)
        self.assertEqual(order, ["first-enter", "first-exit", "second-enter"])
        first.close_all()
        second.close_all()
        first_backend.close()
        second_backend.close()

    def test_scoped_service_can_resume_session_after_broker_restart(self) -> None:
        repository = InMemoryGraphRepository()
        crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        first, first_backend = self.broker()
        service = ScopedAuthGraphService(
            repository,
            crypto,
            first,
            clock=self.clock,
        )
        passphrase = bytearray(b"correct horse battery staple")
        vault_id = service.create_vault("principal-1", passphrase)
        scope_id = service.create_protection_scope(
            "principal-1",
            vault_id,
            passphrase,
        )
        context = service.unlock(
            "principal-1",
            vault_id,
            passphrase,
            (scope_id,),
        )
        entity_id = service.create_entity(
            context,
            scope_id,
            "Order",
            {"status": "processing"},
        )
        first.close_all()
        first_backend.close()

        restarted, backend = self.broker()
        resumed = ScopedAuthGraphService(
            repository,
            crypto,
            restarted,
            clock=self.clock,
        )
        entity = resumed.get_entity(context, entity_id)
        self.assertEqual(entity.properties, {"status": "processing"})
        resumed.lock(context)
        restarted.close_all()
        backend.close()

    def test_existing_active_revision_rejects_open_time_auto_advance(self) -> None:
        broker, backend = self.broker()
        old_context = self.open_context(broker)
        materials = self.materials()
        try:
            with self.assertRaises(SessionUnavailable):
                broker.open(
                    "principal-1",
                    "vault-1",
                    materials,
                    envelope_revision=2,
                    root_key_version=1,
                )
            self.assertEqual(
                broker.advance_envelope_revision("principal-1", "vault-1", 2),
                1,
            )
            new_context = broker.open(
                "principal-1",
                "vault-1",
                materials,
                envelope_revision=2,
                root_key_version=1,
            )
        finally:
            self.clear(materials)
        with self.assertRaises(SessionUnavailable):
            with broker.guarded_lease(old_context):
                pass
        broker.close(new_context)
        broker.close_all()
        backend.close()

    def test_pending_revision_survives_restart_and_reconciles_exactly(self) -> None:
        first, first_backend = self.broker()
        old_context = self.open_context(first)
        transition = first.prepare_revision_change(
            "principal-1",
            "vault-1",
            1,
            2,
        )
        self.assertEqual(transition.generation, 2)
        with self.assertRaises(SessionUnavailable):
            with first.guarded_lease(old_context):
                pass
        first.close_all()
        first_backend.close()

        restarted, backend = self.broker()
        state = restarted.get_lifecycle_state("principal-1", "vault-1")
        self.assertIsNotNone(state)
        assert state is not None
        self.assertIs(state.phase, VaultLifecyclePhase.REVISION_PENDING)
        materials = self.materials()
        try:
            with self.assertRaises(SessionUnavailable):
                restarted.open(
                    "principal-1",
                    "vault-1",
                    materials,
                    envelope_revision=1,
                    root_key_version=1,
                )
            with self.assertRaises(SessionUnavailable):
                restarted.reconcile_revision_change(
                    "principal-1",
                    "vault-1",
                    3,
                )
            active = restarted.reconcile_revision_change(
                "principal-1",
                "vault-1",
                1,
            )
            self.assertIs(active.phase, VaultLifecyclePhase.ACTIVE)
            restored = restarted.open(
                "principal-1",
                "vault-1",
                materials,
                envelope_revision=1,
                root_key_version=1,
            )
        finally:
            self.clear(materials)
        restarted.close(restored)
        restarted.close_all()
        backend.close()

    def test_management_block_requires_explicit_generation_reconciliation(
        self,
    ) -> None:
        first, first_backend = self.broker()
        old_context = self.open_context(first)
        transition = first.begin_management_transition(
            "principal-1",
            "vault-1",
            1,
        )
        with self.assertRaises(SessionUnavailable):
            first.begin_management_transition("principal-1", "vault-1", 1)
        with self.assertRaises(SessionUnavailable):
            with first.guarded_lease(old_context):
                pass
        first.close_all()
        first_backend.close()

        restarted, backend = self.broker()
        state = restarted.get_lifecycle_state("principal-1", "vault-1")
        self.assertIsNotNone(state)
        assert state is not None
        self.assertIs(state.phase, VaultLifecyclePhase.BLOCKED)
        with self.assertRaises(SessionUnavailable):
            restarted.reconcile_management_transition(
                "principal-1",
                "vault-1",
                1,
                transition.generation + 1,
            )
        active = restarted.reconcile_management_transition(
            "principal-1",
            "vault-1",
            1,
            transition.generation,
        )
        self.assertIs(active.phase, VaultLifecyclePhase.ACTIVE)
        with self.assertRaises(SessionUnavailable):
            restarted.finalize_management_transition(transition)
        restarted.close_all()
        backend.close()

    def test_expired_guard_is_stolen_with_higher_fence_generation(self) -> None:
        first, first_backend = self.broker(guard_ttl_seconds=1)
        second, second_backend = self.broker(guard_ttl_seconds=1)
        first_generation = 0
        with self.assertRaises(SessionUnavailable):
            with first.vault_guard("principal-1", "vault-1") as first_guard:
                first_generation = first_guard.generation
                with first.vault_guard(
                    "principal-1",
                    "vault-1",
                ) as nested_guard:
                    self.assertEqual(nested_guard.generation, first_generation)
                self.clock.value += 2
                with second.vault_guard(
                    "principal-1",
                    "vault-1",
                ) as second_guard:
                    self.assertGreater(second_guard.generation, first_generation)
                    with self.assertRaises(SessionUnavailable):
                        first_guard.assert_active()
                    materials = self.materials()
                    try:
                        with self.assertRaises(SessionUnavailable):
                            first.open(
                                "principal-1",
                                "vault-1",
                                materials,
                                envelope_revision=1,
                                root_key_version=1,
                            )
                    finally:
                        self.clear(materials)
        first.close_all()
        second.close_all()
        first_backend.close()
        second_backend.close()

    def test_guard_renewal_extends_ownership_with_same_generation(self) -> None:
        broker, backend = self.broker(guard_ttl_seconds=60)
        with broker.vault_guard("principal-1", "vault-1") as guard:
            generation = guard.generation
            self.clock.value += 30
            guard.renew()
            self.clock.value += 31
            guard.assert_active()
            self.assertEqual(guard.generation, generation)
        broker.close_all()
        backend.close()

    def test_automatic_heartbeat_prevents_guard_expiry_overlap(self) -> None:
        first, first_backend = self.broker(guard_ttl_seconds=1)
        second, second_backend = self.broker(guard_ttl_seconds=1)
        initial_time = self.clock.value
        entered = threading.Event()
        release = threading.Event()
        renewed_after_advance = threading.Event()
        second_entered = threading.Event()
        errors: list[BaseException] = []
        original_renew = first._renew_guard

        def observed_renew(guard) -> None:
            original_renew(guard)
            if self.clock.value >= initial_time + 0.5:
                renewed_after_advance.set()

        def first_worker() -> None:
            try:
                with first.vault_guard("principal-1", "vault-1"):
                    entered.set()
                    release.wait(5)
            except BaseException as exc:
                errors.append(exc)

        def second_worker() -> None:
            try:
                with second.vault_guard("principal-1", "vault-1"):
                    second_entered.set()
            except BaseException as exc:
                errors.append(exc)

        first_thread = threading.Thread(target=first_worker)
        second_thread = threading.Thread(target=second_worker)
        with patch.object(first, "_renew_guard", side_effect=observed_renew):
            first_thread.start()
            self.assertTrue(entered.wait(5))
            self.clock.value = initial_time + 0.5
            self.assertTrue(renewed_after_advance.wait(2))
            self.clock.value = initial_time + 1.25
            second_thread.start()
            self.assertFalse(second_entered.wait(0.05))
            release.set()
            first_thread.join(5)
            second_thread.join(5)
        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())
        self.assertTrue(second_entered.is_set())
        self.assertEqual(errors, [])
        first.close_all()
        second.close_all()
        first_backend.close()
        second_backend.close()

    def test_close_all_drains_guard_without_allowing_owner_overlap(self) -> None:
        broker, backend = self.broker()
        entered = threading.Event()
        release = threading.Event()
        close_finished = threading.Event()
        other_close_finished = threading.Event()
        second_entered = threading.Event()
        handles: list[object] = []
        outcomes: list[object] = []
        order: list[str] = []

        def hold_guard() -> None:
            try:
                with broker.vault_guard("principal-1", "vault-1") as guard:
                    handles.append(guard)
                    order.append("first-enter")
                    entered.set()
                    release.wait(5)
                    transition = broker.begin_management_transition(
                        "principal-1",
                        "vault-1",
                        1,
                    )
                    broker.finalize_management_transition(transition)
                    order.append("first-exit")
            except BaseException as exc:
                outcomes.append(exc)

        def close_broker(finished: threading.Event) -> None:
            try:
                broker.close_all()
            except BaseException as exc:
                outcomes.append(exc)
            finally:
                finished.set()

        restarted, restarted_backend = self.broker()

        def take_second_guard() -> None:
            try:
                with restarted.vault_guard("principal-1", "vault-1"):
                    order.append("second-enter")
                    second_entered.set()
            except BaseException as exc:
                outcomes.append(exc)

        thread = threading.Thread(target=hold_guard)
        close_thread = threading.Thread(target=close_broker, args=(close_finished,))
        other_close_thread = threading.Thread(
            target=close_broker,
            args=(other_close_finished,),
        )
        second_thread = threading.Thread(target=take_second_guard)
        thread.start()
        self.assertTrue(entered.wait(5))
        close_thread.start()
        other_close_thread.start()
        self.assertFalse(close_finished.wait(0.05))
        self.assertFalse(other_close_finished.wait(0.05))
        second_thread.start()
        self.assertFalse(second_entered.wait(0.05))
        self.assertEqual(len(handles), 1)
        handle = handles[0]
        self.assertTrue(handle._thread.is_alive())

        release.set()
        thread.join(5)
        close_thread.join(5)
        other_close_thread.join(5)
        second_thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertFalse(other_close_thread.is_alive())
        self.assertFalse(second_thread.is_alive())
        self.assertTrue(close_finished.is_set())
        self.assertTrue(other_close_finished.is_set())
        self.assertTrue(second_entered.is_set())
        self.assertEqual(outcomes, [])
        self.assertEqual(order, ["first-enter", "first-exit", "second-enter"])
        self.assertFalse(handle._thread.is_alive())
        self.assertEqual(broker._active_guards, set())
        state = restarted.get_lifecycle_state("principal-1", "vault-1")
        self.assertIsNotNone(state)
        assert state is not None
        self.assertIs(state.phase, VaultLifecyclePhase.ACTIVE)
        restarted.close_all()
        backend.close()
        restarted_backend.close()

    def test_close_all_drains_local_plaintext_lease_before_returning(self) -> None:
        broker, backend = self.broker()
        context = self.open_context(broker)
        entered = threading.Event()
        release = threading.Event()
        close_finished = threading.Event()
        observed: list[bytes] = []
        errors: list[BaseException] = []

        def hold_lease() -> None:
            try:
                with broker.guarded_lease(context) as lease:
                    observed.append(bytes(lease.scope_keys["scope-1"].dek))
                    entered.set()
                    release.wait(5)
                    observed.append(bytes(lease.scope_keys["scope-1"].dek))
            except BaseException as exc:
                errors.append(exc)

        def close_broker() -> None:
            try:
                broker.close_all()
            except BaseException as exc:
                errors.append(exc)
            finally:
                close_finished.set()

        lease_thread = threading.Thread(target=hold_lease)
        close_thread = threading.Thread(target=close_broker)
        lease_thread.start()
        self.assertTrue(entered.wait(5))
        close_thread.start()
        self.assertFalse(close_finished.wait(0.05))
        self.assertTrue(broker.closed)
        with self.assertRaises(SessionUnavailable):
            with broker.guarded_lease(context):
                pass

        release.set()
        lease_thread.join(5)
        close_thread.join(5)
        self.assertFalse(lease_thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertTrue(close_finished.is_set())
        self.assertEqual(errors, [])
        self.assertEqual(observed, [b"a" * 32, b"a" * 32])
        self.assertEqual(broker._active_local_leases, 0)
        backend.close()

    def test_guard_thread_start_failure_releases_persisted_fence(self) -> None:
        broker, backend = self.broker()
        with patch.object(
            durable_sessions_module._DurableVaultGuard,
            "_start",
            side_effect=RuntimeError("synthetic thread start failure"),
        ):
            with self.assertRaises(SessionUnavailable):
                with broker.vault_guard("principal-1", "vault-1"):
                    pass
        self.assertEqual(broker._active_guards, set())

        second, second_backend = self.broker()
        with second.vault_guard("principal-1", "vault-1"):
            pass
        broker.close_all()
        second.close_all()
        backend.close()
        second_backend.close()

    def test_crashed_process_lease_ciphertext_is_reclaimed_after_expiry(
        self,
    ) -> None:
        broker, backend = self.broker(lease_ttl_seconds=30)
        context = self.open_context(broker)
        process_context = multiprocessing.get_context("spawn")
        ready = process_context.Event()
        process = process_context.Process(
            target=_crash_with_active_lease,
            args=(
                str(self.path),
                self.token_key,
                self.wrapping_key,
                context,
                self.clock.value,
                ready,
            ),
        )
        process.start()
        self.assertTrue(ready.wait(10))
        process.join(10)
        self.assertEqual(process.exitcode, 0)

        broker.close(context)
        self.assertEqual(broker.resident_scope_ciphertext_count, 2)
        self.clock.value += 31
        broker.purge_expired()
        self.assertEqual(broker.resident_scope_ciphertext_count, 0)
        broker.close_all()
        backend.close()

    def test_system_exit_after_graph_commit_leaves_durable_pending_state(
        self,
    ) -> None:
        repository = SystemExitEnvelopeRepository()
        crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        first, first_backend = self.broker()
        service = ScopedAuthGraphService(repository, crypto, first, clock=self.clock)
        password = bytearray(b"synthetic original password")
        new_password = bytearray(b"synthetic replacement password")
        vault_id = service.create_vault("principal-1", password)
        scope_id = service.create_protection_scope(
            "principal-1",
            vault_id,
            password,
        )
        old_context = service.unlock(
            "principal-1",
            vault_id,
            password,
            (scope_id,),
        )
        with self.assertRaises(SystemExit):
            service.change_passphrase(
                "principal-1",
                vault_id,
                password,
                new_password,
            )
        with self.assertRaises(SessionUnavailable):
            with first.guarded_lease(old_context):
                pass
        first.close_all()
        first_backend.close()

        restarted, backend = self.broker()
        resumed = ScopedAuthGraphService(
            repository,
            crypto,
            restarted,
            clock=self.clock,
        )
        with self.assertRaises(SessionUnavailable):
            resumed.unlock(
                "principal-1",
                vault_id,
                new_password,
                (scope_id,),
            )
        self.assertEqual(
            resumed.reconcile_passphrase_change("principal-1", vault_id),
            2,
        )
        context = resumed.unlock(
            "principal-1",
            vault_id,
            new_password,
            (scope_id,),
        )
        resumed.lock(context)
        restarted.close_all()
        backend.close()

    def test_legacy_scalar_lease_database_migrates_fail_closed(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript(
                """
                CREATE TABLE authgraph_session (
                    token_digest BLOB PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    vault_id TEXT NOT NULL,
                    envelope_revision INTEGER NOT NULL,
                    root_key_version INTEGER NOT NULL,
                    expires_at REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    active_leases INTEGER NOT NULL DEFAULT 0,
                    format_version INTEGER NOT NULL
                );
                CREATE TABLE authgraph_session_scope (
                    token_digest BLOB NOT NULL,
                    scope_id TEXT NOT NULL,
                    scope_key_version INTEGER NOT NULL,
                    wrapped_format_version INTEGER NOT NULL,
                    backend_id TEXT NOT NULL,
                    provider_key_id TEXT NOT NULL,
                    algorithm TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    PRIMARY KEY(token_digest, scope_id),
                    FOREIGN KEY(token_digest)
                        REFERENCES authgraph_session(token_digest)
                        ON DELETE CASCADE
                );
                CREATE TABLE authgraph_vault_revision (
                    principal_id TEXT NOT NULL,
                    vault_id TEXT NOT NULL,
                    minimum_envelope_revision INTEGER NOT NULL,
                    PRIMARY KEY(principal_id, vault_id)
                );
                CREATE TABLE authgraph_vault_guard (
                    principal_id TEXT NOT NULL,
                    vault_id TEXT NOT NULL,
                    owner_token TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY(principal_id, vault_id)
                );
                """
            )
            connection.execute(
                """
                INSERT INTO authgraph_vault_revision VALUES (?, ?, ?)
                """,
                ("principal-1", "vault-1", 1),
            )
            connection.execute(
                """
                INSERT INTO authgraph_session VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    b"d" * 32,
                    "principal-1",
                    "vault-1",
                    1,
                    1,
                    self.clock.value + 300,
                    1,
                    7,
                    1,
                ),
            )
            connection.commit()
        finally:
            connection.close()
        self.path.chmod(0o600)

        broker, backend = self.broker()
        state = broker.get_lifecycle_state("principal-1", "vault-1")
        self.assertIsNotNone(state)
        assert state is not None
        self.assertIs(state.phase, VaultLifecyclePhase.ACTIVE)
        broker.purge_expired()
        migrated = sqlite3.connect(self.path)
        try:
            guard_columns = {
                row[1]
                for row in migrated.execute(
                    "PRAGMA table_info(authgraph_vault_guard)"
                )
            }
            self.assertIn("generation", guard_columns)
            lease_table = migrated.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'authgraph_session_lease'
                """
            ).fetchone()
            self.assertIsNotNone(lease_table)
            self.assertEqual(
                migrated.execute(
                    "SELECT count(*) FROM authgraph_session"
                ).fetchone()[0],
                0,
            )
        finally:
            migrated.close()
        broker.close_all()
        backend.close()

    def test_concurrent_fresh_database_constructors_are_serialized(self) -> None:
        path = Path(self.directory.name, "fresh-concurrent.sqlite3")
        brokers, errors = self.concurrent_broker_start(path)
        self.assertEqual(errors, [])
        self.assertEqual(len(brokers), 8)
        for broker, backend in brokers:
            broker.close_all()
            backend.close()

    def test_concurrent_legacy_database_migration_is_serialized(self) -> None:
        path = Path(self.directory.name, "legacy-concurrent.sqlite3")
        self.create_legacy_database(path)
        brokers, errors = self.concurrent_broker_start(path)
        self.assertEqual(errors, [])
        self.assertEqual(len(brokers), 8)
        for broker, backend in brokers:
            state = broker.get_lifecycle_state("principal-1", "vault-1")
            self.assertIsNotNone(state)
            broker.close_all()
            backend.close()

    def test_spawned_concurrent_fresh_and_legacy_initialization(self) -> None:
        process_context = multiprocessing.get_context("spawn")
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                path = Path(
                    self.directory.name,
                    f"spawn-{'legacy' if legacy else 'fresh'}.sqlite3",
                )
                if legacy:
                    self.create_legacy_database(path)
                start = process_context.Event()
                results = process_context.Queue()
                processes = [
                    process_context.Process(
                        target=_construct_durable_broker,
                        args=(
                            str(path),
                            self.token_key,
                            self.wrapping_key,
                            start,
                            results,
                        ),
                    )
                    for _ in range(4)
                ]
                for process in processes:
                    process.start()
                start.set()
                for process in processes:
                    process.join(15)
                self.assertTrue(
                    all(process.exitcode == 0 for process in processes)
                )
                self.assertEqual(
                    sorted(results.get(timeout=5) for _ in processes),
                    ["success"] * len(processes),
                )
                results.close()
                results.join_thread()

    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_rejects_state_in_a_writable_untrusted_directory(self) -> None:
        insecure = Path(self.directory.name, "writable")
        insecure.mkdir(mode=0o700)
        insecure.chmod(0o777)
        backend = InMemoryAesKeyWrappingBackend(
            backend_id="test-session-kms-v1",
            key_id="test-session-key-v1",
            wrapping_key=self.wrapping_key,
        )
        try:
            with self.assertRaises(SessionUnavailable):
                DurableScopedSessionBroker(
                    insecure / "sessions.sqlite3",
                    self.token_key,
                    {backend.backend_id: backend},
                    active_backend_id=backend.backend_id,
                )
        finally:
            backend.close()
            insecure.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
