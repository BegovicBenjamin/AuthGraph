from __future__ import annotations

import multiprocessing
import tempfile
import unittest
from pathlib import Path

from authgraph.durable_grants import DurableScopeGrantPolicy
from authgraph.durable_otp import DurableOneTimeCodeBroker
from authgraph.durable_sessions import DurableScopedSessionBroker
from authgraph.errors import SessionUnavailable
from authgraph.key_custody import (
    EnvelopeScopeKeyProvider,
    InMemoryAesKeyWrappingBackend,
    KeyCustodyConflict,
)
from authgraph.otp import OneTimeCodeDenied
from authgraph.scoped_sessions import ScopeKeyMaterial
from authgraph.sqlite_key_slots import SqliteKeySlotStore
from authgraph.unlock_policy import ScopeGrantDenied, UnlockProfile


def _otp_verify_worker(
    path: str,
    key: bytes,
    challenge_id: str,
    code: str,
    start: object,
    results: object,
) -> None:
    broker = DurableOneTimeCodeBroker(path, key, ttl_seconds=600)
    try:
        start.wait(10)
        try:
            broker.verify(
                challenge_id,
                code,
                principal_id="principal-multiprocess",
                profile_id="support",
                client_binding="browser-multiprocess",
            )
            outcome = "success"
        except OneTimeCodeDenied:
            outcome = "denied"
        results.put(outcome)
    finally:
        broker.close()


def _grant_consume_worker(
    path: str,
    key: bytes,
    grant: object,
    start: object,
    results: object,
) -> None:
    policy = DurableScopeGrantPolicy(
        {
            "support": UnlockProfile(
                profile_id="support",
                scope_ids=("scope-orders",),
                session_ttl_seconds=300,
                allow_one_time_code=True,
            )
        },
        path,
        key,
    )
    try:
        start.wait(10)
        try:
            policy.consume(grant)
            outcome = "success"
        except ScopeGrantDenied:
            outcome = "denied"
        results.put(outcome)
    finally:
        policy.close()


def _key_enroll_worker(
    path: str,
    wrapping_key: bytes,
    value: bytes,
    start: object,
    results: object,
) -> None:
    backend = InMemoryAesKeyWrappingBackend(
        backend_id="multiprocess-test-kms",
        key_id="multiprocess-test-key",
        wrapping_key=wrapping_key,
    )
    material = {"scope-1": ScopeKeyMaterial(1, bytearray(value))}
    try:
        provider = EnvelopeScopeKeyProvider(
            SqliteKeySlotStore(path),
            {backend.backend_id: backend},
            active_backend_id=backend.backend_id,
        )
        start.wait(10)
        try:
            provider.enroll_scope_keys(
                principal_id="principal-multiprocess",
                vault_id="vault-multiprocess",
                envelope_revision=1,
                root_key_version=1,
                scope_keys=material,
            )
            outcome = "success"
        except KeyCustodyConflict:
            outcome = "conflict"
        results.put(outcome)
    finally:
        material["scope-1"].dek[:] = b"\x00" * 32
        backend.close()


def _session_logout_worker(
    path: str,
    token_key: bytes,
    wrapping_key: bytes,
    context: object,
    results: object,
) -> None:
    backend = InMemoryAesKeyWrappingBackend(
        backend_id="multiprocess-session-kms",
        key_id="multiprocess-session-key",
        wrapping_key=wrapping_key,
    )
    broker = DurableScopedSessionBroker(
        path,
        token_key,
        {backend.backend_id: backend},
        active_backend_id=backend.backend_id,
    )
    try:
        broker.close(context)
        results.put("closed")
    finally:
        broker.close_all()
        backend.close()


class SqliteMultiprocessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.processes: list[multiprocessing.Process] = []
        self.queues: list[object] = []

    def tearDown(self) -> None:
        for process in self.processes:
            if process.is_alive():
                process.terminate()
            process.join(5)
        for queue in self.queues:
            queue.close()
            queue.join_thread()
        self.directory.cleanup()

    def _context(self):
        return multiprocessing.get_context("spawn")

    def _race(self, target, args: tuple[object, ...]) -> list[str]:
        context = self._context()
        start = context.Event()
        results = context.Queue()
        self.queues.append(results)
        workers = [
            context.Process(target=target, args=(*args, start, results))
            for _ in range(2)
        ]
        self.processes.extend(workers)
        for worker in workers:
            worker.start()
        start.set()
        outcomes = [results.get(timeout=20) for _ in workers]
        for worker in workers:
            worker.join(20)
            self.assertEqual(worker.exitcode, 0)
        return outcomes

    def test_otp_verification_has_one_winner_across_processes(self) -> None:
        path = str(Path(self.directory.name, "otp.sqlite3"))
        key = b"o" * 32
        issuer = DurableOneTimeCodeBroker(path, key, ttl_seconds=600)
        issued = issuer.issue(
            "principal-multiprocess",
            "support",
            "browser-multiprocess",
            authorization_context="vault-multiprocess",
        )
        code = bytes(issued.code).decode("ascii")
        issued.clear_code()
        issuer.close()

        outcomes = self._race(
            _otp_verify_worker,
            (path, key, issued.challenge_id, code),
        )
        self.assertEqual(sorted(outcomes), ["denied", "success"])

    def test_grant_consumption_has_one_winner_across_processes(self) -> None:
        path = str(Path(self.directory.name, "grants.sqlite3"))
        otp_key = b"o" * 32
        grant_key = b"g" * 32
        profiles = {
            "support": UnlockProfile(
                profile_id="support",
                scope_ids=("scope-orders",),
                session_ttl_seconds=300,
                allow_one_time_code=True,
            )
        }
        otp = DurableOneTimeCodeBroker(path, otp_key, ttl_seconds=600)
        issued = otp.issue(
            "principal-multiprocess",
            "support",
            "browser-multiprocess",
            authorization_context="vault-multiprocess",
        )
        evidence = otp.verify(
            issued.challenge_id,
            bytes(issued.code).decode("ascii"),
            principal_id="principal-multiprocess",
            profile_id="support",
            client_binding="browser-multiprocess",
        )
        issued.clear_code()
        policy = DurableScopeGrantPolicy(profiles, path, grant_key)
        grant = policy.authorize_one_time_code(
            evidence,
            vault_id="vault-multiprocess",
            evidence_consumer=otp,
        )
        policy.close()
        otp.close()

        outcomes = self._race(
            _grant_consume_worker,
            (path, grant_key, grant),
        )
        self.assertEqual(sorted(outcomes), ["denied", "success"])

    def test_key_slot_compare_and_swap_is_cross_process_atomic(self) -> None:
        context = self._context()
        path = str(Path(self.directory.name, "slots.sqlite3"))
        wrapping_key = b"w" * 32
        start = context.Event()
        results = context.Queue()
        self.queues.append(results)
        workers = [
            context.Process(
                target=_key_enroll_worker,
                args=(path, wrapping_key, value, start, results),
            )
            for value in (b"a" * 32, b"b" * 32)
        ]
        self.processes.extend(workers)
        for worker in workers:
            worker.start()
        start.set()
        outcomes = [results.get(timeout=20) for _ in workers]
        for worker in workers:
            worker.join(20)
            self.assertEqual(worker.exitcode, 0)
        self.assertEqual(sorted(outcomes), ["conflict", "success"])

    def test_session_logout_is_visible_to_another_process(self) -> None:
        context_factory = self._context()
        path = str(Path(self.directory.name, "sessions.sqlite3"))
        token_key = b"t" * 32
        wrapping_key = b"w" * 32
        backend = InMemoryAesKeyWrappingBackend(
            backend_id="multiprocess-session-kms",
            key_id="multiprocess-session-key",
            wrapping_key=wrapping_key,
        )
        broker = DurableScopedSessionBroker(
            path,
            token_key,
            {backend.backend_id: backend},
            active_backend_id=backend.backend_id,
        )
        materials = {"scope-1": ScopeKeyMaterial(1, bytearray(b"a" * 32))}
        session_context = broker.open(
            "principal-multiprocess",
            "vault-multiprocess",
            materials,
            envelope_revision=1,
            root_key_version=1,
        )
        materials["scope-1"].dek[:] = b"\x00" * 32
        broker.close_all()
        backend.close()

        results = context_factory.Queue()
        self.queues.append(results)
        worker = context_factory.Process(
            target=_session_logout_worker,
            args=(path, token_key, wrapping_key, session_context, results),
        )
        self.processes.append(worker)
        worker.start()
        self.assertEqual(results.get(timeout=20), "closed")
        worker.join(20)
        self.assertEqual(worker.exitcode, 0)

        restarted_backend = InMemoryAesKeyWrappingBackend(
            backend_id="multiprocess-session-kms",
            key_id="multiprocess-session-key",
            wrapping_key=wrapping_key,
        )
        restarted = DurableScopedSessionBroker(
            path,
            token_key,
            {restarted_backend.backend_id: restarted_backend},
            active_backend_id=restarted_backend.backend_id,
        )
        try:
            with self.assertRaises(SessionUnavailable):
                with restarted.guarded_lease(session_context):
                    pass
        finally:
            restarted.close_all()
            restarted_backend.close()


if __name__ == "__main__":
    unittest.main()
