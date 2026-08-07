from __future__ import annotations

import os
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from authgraph.durable_grants import DurableScopeGrantPolicy
from authgraph.durable_otp import DurableOneTimeCodeBroker
from authgraph.unlock_policy import (
    ScopeGrantConsumer,
    ScopeGrantDenied,
    UnlockProfile,
)


class Clock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class DurableScopeGrantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name, "security.sqlite3")
        self.otp_key = b"o" * 32
        self.grant_key = b"g" * 32
        self.clock = Clock()
        self.profiles = {
            "support": UnlockProfile(
                profile_id="support",
                scope_ids=("scope-orders", "scope-profile"),
                session_ttl_seconds=300,
                allow_one_time_code=True,
            )
        }

    def tearDown(self) -> None:
        self.directory.cleanup()

    def otp(self) -> DurableOneTimeCodeBroker:
        return DurableOneTimeCodeBroker(
            self.path,
            self.otp_key,
            ttl_seconds=600,
            clock=self.clock,
        )

    def policy(
        self,
        *,
        revision: int = 1,
        profiles: object | None = None,
    ) -> DurableScopeGrantPolicy:
        return DurableScopeGrantPolicy(
            self.profiles if profiles is None else profiles,
            self.path,
            self.grant_key,
            policy_revision=revision,
            clock=self.clock,
        )

    def evidence(self) -> tuple[DurableOneTimeCodeBroker, object]:
        otp = self.otp()
        issued = otp.issue(
            "principal-1",
            "support",
            "browser-1",
            authorization_context="vault-1",
            authorization_epoch=8,
        )
        code = bytes(issued.code).decode("ascii")
        issued.clear_code()
        evidence = otp.verify(
            issued.challenge_id,
            code,
            principal_id="principal-1",
            profile_id="support",
            client_binding="browser-1",
        )
        return otp, evidence

    def issue_grant(self) -> object:
        otp, evidence = self.evidence()
        policy = self.policy()
        grant = policy.authorize_one_time_code(
            evidence,
            vault_id="vault-1",
            evidence_consumer=otp,
        )
        otp.close()
        policy.close()
        return grant

    def test_grant_survives_restart_and_is_consumed_once(self) -> None:
        grant = self.issue_grant()
        restarted = self.policy()

        consumed = restarted.consume(grant)
        self.assertIsNot(consumed, grant)
        self.assertEqual(consumed.scope_ids, self.profiles["support"].scope_ids)
        self.assertEqual(consumed.authorization_epoch, 8)
        with self.assertRaises(ScopeGrantDenied):
            restarted.consume(grant)
        restarted.close()

    def test_two_workers_allow_only_one_consumer(self) -> None:
        grant = self.issue_grant()
        workers = (self.policy(), self.policy())
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def consume(worker: DurableScopeGrantPolicy) -> None:
            barrier.wait()
            try:
                worker.consume(grant)
                outcome = "success"
            except ScopeGrantDenied:
                outcome = "denied"
            with lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=consume, args=(worker,))
            for worker in workers
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for worker in workers:
            worker.close()

        self.assertEqual(sorted(outcomes), ["denied", "success"])

    def test_mutated_grant_is_consumed_and_denied(self) -> None:
        grant = self.issue_grant()
        policy = self.policy()
        forged = replace(grant, vault_id="vault-2")

        with self.assertRaises(ScopeGrantDenied):
            policy.consume(forged)
        with self.assertRaises(ScopeGrantDenied):
            policy.consume(grant)
        policy.close()

    def test_policy_revision_or_profile_change_invalidates_grant(self) -> None:
        grant = self.issue_grant()
        changed_revision = self.policy(revision=2)
        with self.assertRaises(ScopeGrantDenied):
            changed_revision.consume(grant)
        changed_revision.close()

        second_grant = self.issue_grant()
        changed_profiles = {
            "support": UnlockProfile(
                profile_id="support",
                scope_ids=("scope-orders",),
                session_ttl_seconds=300,
                allow_one_time_code=True,
            )
        }
        changed = self.policy(profiles=changed_profiles)
        with self.assertRaises(ScopeGrantDenied):
            changed.consume(second_grant)
        changed.close()

    def test_expired_grant_is_denied_after_restart(self) -> None:
        grant = self.issue_grant()
        self.clock.value += 301
        restarted = self.policy()

        with self.assertRaises(ScopeGrantDenied):
            restarted.consume(grant)
        self.assertEqual(restarted.active_count, 0)
        restarted.close()

    def test_database_contains_no_raw_authority_or_capability(self) -> None:
        # Keep this assertion scoped to the grant store.  The OTP broker
        # intentionally persists non-PII opaque binding fields, so sharing its
        # SQLite file would make this byte-level grant-store assertion depend
        # on unrelated rows and WAL checkpoint timing.
        otp, evidence = self.evidence()
        grant_path = Path(self.directory.name, "grants-only.sqlite3")
        policy = DurableScopeGrantPolicy(
            self.profiles,
            grant_path,
            self.grant_key,
            clock=self.clock,
        )
        grant = policy.authorize_one_time_code(
            evidence,
            vault_id="vault-1",
            evidence_consumer=otp,
        )
        otp.close()
        policy.close()
        stored = b"".join(
            path.read_bytes()
            for path in (
                grant_path,
                Path(f"{grant_path}-wal"),
                Path(f"{grant_path}-shm"),
            )
            if path.is_file()
        )
        for forbidden in (
            grant.grant_id,
            grant.principal_id,
            grant.vault_id,
            grant.client_binding,
            grant.evidence_id,
            *grant.scope_ids,
        ):
            self.assertNotIn(forbidden.encode("utf-8"), stored)

    def test_implements_scope_grant_consumer_protocol(self) -> None:
        policy = self.policy()
        self.assertIsInstance(policy, ScopeGrantConsumer)
        policy.close()

    def test_file_creation_race_accepts_secure_regular_winner(self) -> None:
        def win_creation_race(*_args: object) -> None:
            self.path.write_bytes(b"")
            self.path.chmod(0o600)
            raise FileExistsError

        with patch(
            "authgraph.durable_grants.os.open",
            side_effect=win_creation_race,
        ) as open_file:
            policy = self.policy()
        open_file.assert_called_once()
        policy.close()

    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_file_creation_race_rejects_unsafe_winner(self) -> None:
        for winner_kind in ("permissive", "symlink"):
            with self.subTest(winner_kind=winner_kind):
                race_path = Path(
                    self.directory.name,
                    f"{winner_kind}-race.sqlite3",
                )

                def win_creation_race(*_args: object) -> None:
                    if winner_kind == "permissive":
                        race_path.write_bytes(b"")
                        race_path.chmod(0o644)
                    else:
                        target = Path(
                            self.directory.name,
                            "symlink-race-target.sqlite3",
                        )
                        target.write_bytes(b"")
                        target.chmod(0o600)
                        race_path.symlink_to(target)
                    raise FileExistsError

                with patch(
                    "authgraph.durable_grants.os.open",
                    side_effect=win_creation_race,
                ):
                    with self.assertRaises(ScopeGrantDenied):
                        DurableScopeGrantPolicy(
                            self.profiles,
                            race_path,
                            self.grant_key,
                            clock=self.clock,
                        )

    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_rejects_state_in_a_writable_untrusted_directory(self) -> None:
        insecure = Path(self.directory.name, "writable")
        insecure.mkdir(mode=0o700)
        insecure.chmod(0o777)
        try:
            with self.assertRaises(ScopeGrantDenied):
                DurableScopeGrantPolicy(
                    self.profiles,
                    insecure / "grants.sqlite3",
                    self.grant_key,
                    clock=self.clock,
                )
        finally:
            insecure.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
