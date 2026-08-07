from __future__ import annotations

import os
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from authgraph.durable_otp import DurableOneTimeCodeBroker
from authgraph.otp import OneTimeCodeDenied, OneTimeCodeUnavailable
from authgraph.unlock_policy import ScopeGrantPolicy, UnlockProfile


class Clock:
    def __init__(self, value: float = 1_700_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class DurableOneTimeCodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name, "otp.sqlite3")
        self.key = b"d" * 32
        self.clock = Clock()

    def tearDown(self) -> None:
        self.directory.cleanup()

    def broker(self, **overrides: object) -> DurableOneTimeCodeBroker:
        options: dict[str, object] = {
            "ttl_seconds": 600,
            "max_attempts": 3,
            "max_issues_per_window": 5,
            "clock": self.clock,
        }
        options.update(overrides)
        return DurableOneTimeCodeBroker(self.path, self.key, **options)

    @staticmethod
    def code_text(issued: object) -> str:
        return bytes(issued.code).decode("ascii")

    def test_challenge_survives_restart_and_evidence_is_single_use(self) -> None:
        first = self.broker()
        issued = first.issue(
            "principal-1",
            "support",
            "browser-1",
            authorization_context="vault-1",
            authorization_epoch=7,
        )
        code = self.code_text(issued)
        issued.clear_code()
        first.close()

        second = self.broker()
        evidence = second.verify(
            issued.challenge_id,
            code,
            principal_id="principal-1",
            profile_id="support",
            client_binding="browser-1",
        )
        second.close()

        third = self.broker()
        consumed = third.consume_evidence(evidence)
        self.assertIsNot(consumed, evidence)
        self.assertEqual(consumed.authorization_context, "vault-1")
        self.assertEqual(consumed.authorization_epoch, 7)
        with self.assertRaises(OneTimeCodeDenied):
            third.consume_evidence(evidence)
        third.close()

    def test_two_workers_allow_only_one_verification_winner(self) -> None:
        issuer = self.broker()
        issued = issuer.issue(
            "principal-1",
            "support",
            "browser-1",
            authorization_context="vault-1",
        )
        code = self.code_text(issued)
        issued.clear_code()
        issuer.close()

        workers = (self.broker(), self.broker())
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def verify(worker: DurableOneTimeCodeBroker) -> None:
            barrier.wait()
            try:
                worker.verify(
                    issued.challenge_id,
                    code,
                    principal_id="principal-1",
                    profile_id="support",
                    client_binding="browser-1",
                )
                outcome = "success"
            except OneTimeCodeDenied:
                outcome = "denied"
            with lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=verify, args=(worker,))
            for worker in workers
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for worker in workers:
            worker.close()

        self.assertEqual(sorted(outcomes), ["denied", "success"])

    def test_wrong_attempts_and_resend_are_durable(self) -> None:
        first = self.broker()
        issued = first.issue(
            "principal-1",
            "support",
            "browser-1",
            authorization_context="vault-1",
        )
        code = self.code_text(issued)
        first.close()

        second = self.broker()
        for _ in range(2):
            with self.assertRaises(OneTimeCodeDenied):
                second.verify(
                    issued.challenge_id,
                    "000000" if code != "000000" else "111111",
                    principal_id="principal-1",
                    profile_id="support",
                    client_binding="browser-1",
                )
        replacement = second.issue(
            "principal-1",
            "support",
            "browser-1",
            authorization_context="vault-1",
        )
        with self.assertRaises(OneTimeCodeDenied):
            second.verify(
                issued.challenge_id,
                code,
                principal_id="principal-1",
                profile_id="support",
                client_binding="browser-1",
            )
        replacement.clear_code()
        second.close()

    def test_issue_rate_limit_is_shared_between_workers(self) -> None:
        first = self.broker(max_issues_per_window=2)
        second = self.broker(max_issues_per_window=2)
        for worker in (first, second):
            issued = worker.issue(
                "principal-1",
                "support",
                "browser-1",
                authorization_context="vault-1",
            )
            issued.clear_code()
        with self.assertRaises(OneTimeCodeUnavailable):
            first.issue(
                "principal-1",
                "support",
                "browser-1",
                authorization_context="vault-1",
            )
        first.close()
        second.close()

    def test_expiry_uses_persisted_wall_clock_time(self) -> None:
        broker = self.broker(ttl_seconds=60)
        issued = broker.issue(
            "principal-1",
            "support",
            "browser-1",
            authorization_context="vault-1",
        )
        code = self.code_text(issued)
        broker.close()
        self.clock.value += 61

        restarted = self.broker(ttl_seconds=60)
        with self.assertRaises(OneTimeCodeDenied):
            restarted.verify(
                issued.challenge_id,
                code,
                principal_id="principal-1",
                profile_id="support",
                client_binding="browser-1",
            )
        self.assertEqual(restarted.active_count, 0)
        restarted.close()

    def test_evidence_integrates_with_existing_fixed_scope_policy(self) -> None:
        broker = self.broker()
        issued = broker.issue(
            "principal-1",
            "support",
            "browser-1",
            authorization_context="vault-1",
            authorization_epoch=4,
        )
        evidence = broker.verify(
            issued.challenge_id,
            self.code_text(issued),
            principal_id="principal-1",
            profile_id="support",
            client_binding="browser-1",
        )
        policy = ScopeGrantPolicy(
            {
                "support": UnlockProfile(
                    profile_id="support",
                    scope_ids=("scope-1",),
                    session_ttl_seconds=300,
                    allow_one_time_code=True,
                )
            },
            clock=self.clock,
        )

        grant = policy.authorize_one_time_code(
            evidence,
            vault_id="vault-1",
            evidence_consumer=broker,
        )
        self.assertEqual(grant.scope_ids, ("scope-1",))
        self.assertEqual(grant.authorization_epoch, 4)
        broker.close()

    def test_mutated_evidence_is_consumed_and_denied(self) -> None:
        broker = self.broker()
        issued = broker.issue(
            "principal-1",
            "support",
            "browser-1",
            authorization_context="vault-1",
        )
        evidence = broker.verify(
            issued.challenge_id,
            self.code_text(issued),
            principal_id="principal-1",
            profile_id="support",
            client_binding="browser-1",
        )
        forged = replace(evidence, principal_id="principal-2")
        with self.assertRaises(OneTimeCodeDenied):
            broker.consume_evidence(forged)
        with self.assertRaises(OneTimeCodeDenied):
            broker.consume_evidence(evidence)
        broker.close()

    def test_plaintext_code_and_capability_are_not_stored(self) -> None:
        broker = self.broker()
        issued = broker.issue(
            "principal-1",
            "support",
            "browser-1",
            authorization_context="vault-1",
        )
        code = bytes(issued.code)
        evidence = broker.verify(
            issued.challenge_id,
            code,
            principal_id="principal-1",
            profile_id="support",
            client_binding="browser-1",
        )
        broker.close()

        stored = b"".join(
            path.read_bytes()
            for path in Path(self.directory.name).iterdir()
            if path.is_file()
        )
        self.assertNotIn(code, stored)
        self.assertNotIn(evidence.evidence_token.encode("ascii"), stored)
        self.assertNotIn(issued.challenge_id.encode("ascii"), stored)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_rejects_permissive_or_symlinked_state_file(self) -> None:
        permissive = Path(self.directory.name, "permissive.sqlite3")
        permissive.write_bytes(b"")
        permissive.chmod(0o644)
        with self.assertRaises(OneTimeCodeUnavailable):
            DurableOneTimeCodeBroker(permissive, self.key)

        target = Path(self.directory.name, "target.sqlite3")
        target.write_bytes(b"")
        target.chmod(0o600)
        link = Path(self.directory.name, "link.sqlite3")
        link.symlink_to(target)
        with self.assertRaises(OneTimeCodeUnavailable):
            DurableOneTimeCodeBroker(link, self.key)

    def test_file_creation_race_accepts_secure_regular_winner(self) -> None:
        def win_creation_race(*_args: object) -> None:
            self.path.write_bytes(b"")
            self.path.chmod(0o600)
            raise FileExistsError

        with patch(
            "authgraph.durable_otp.os.open",
            side_effect=win_creation_race,
        ) as open_file:
            broker = self.broker()
        open_file.assert_called_once()
        broker.close()

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
                    "authgraph.durable_otp.os.open",
                    side_effect=win_creation_race,
                ):
                    with self.assertRaises(OneTimeCodeUnavailable):
                        DurableOneTimeCodeBroker(race_path, self.key)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_rejects_state_in_a_writable_untrusted_directory(self) -> None:
        insecure = Path(self.directory.name, "writable")
        insecure.mkdir(mode=0o700)
        insecure.chmod(0o777)
        try:
            with self.assertRaises(OneTimeCodeUnavailable):
                DurableOneTimeCodeBroker(insecure / "otp.sqlite3", self.key)
        finally:
            insecure.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
