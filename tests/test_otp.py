from __future__ import annotations

import threading
import unittest
from dataclasses import replace
from unittest.mock import patch

from authgraph.errors import ValidationError
from authgraph.otp import (
    InMemoryOneTimeCodeBroker,
    OneTimeCodeDenied,
    OneTimeCodeUnavailable,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class OneTimeCodeBrokerTests(unittest.TestCase):
    PRINCIPAL = "idp_subject_7f83"
    PROFILE = "order_support"
    CLIENT = "browser_session_a91c"

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.broker = InMemoryOneTimeCodeBroker(
            ttl_seconds=60,
            max_attempts=3,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(self.broker.close)

    def test_code_uses_csprng_and_only_keyed_verifier_is_retained(self) -> None:
        with patch("authgraph.otp.secrets.randbelow", return_value=42) as random:
            issued = self.broker.issue(
                self.PRINCIPAL,
                self.PROFILE,
                self.CLIENT,
            )

        random.assert_called_once_with(1_000_000)
        self.assertEqual(issued.code, bytearray(b"000042"))
        record = next(iter(self.broker._records.values()))
        self.assertFalse(hasattr(record, "code"))
        self.assertEqual(len(record.verifier), 32)
        self.assertNotEqual(record.verifier, bytes(issued.code))
        self.assertNotIn("000042", repr(issued))
        self.assertNotIn(record.verifier.hex(), repr(record))
        self.assertNotIn(record.binding_digest.hex(), repr(record))
        issued.clear_code()
        self.assertEqual(issued.code, bytearray(b"\x00" * 6))

    def test_success_returns_bound_evidence_not_key_material(self) -> None:
        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
            authorization_epoch=7,
        )
        code = bytearray(issued.code)

        evidence = self.broker.verify(
            issued.challenge_id,
            code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding=self.CLIENT,
        )

        self.assertEqual(evidence.principal_id, self.PRINCIPAL)
        self.assertEqual(evidence.profile_id, self.PROFILE)
        self.assertEqual(evidence.client_binding, self.CLIENT)
        self.assertEqual(evidence.challenge_id, issued.challenge_id)
        self.assertEqual(evidence.authorization_epoch, 7)
        self.assertEqual(evidence.verified_at, self.clock.value)
        self.assertEqual(evidence.challenge_expires_at, self.clock.value + 60)
        self.assertFalse(hasattr(evidence, "key"))
        self.assertFalse(hasattr(evidence, "kek"))
        self.assertNotIn(self.CLIENT, repr(evidence))
        self.assertNotIn(issued.challenge_id, repr(evidence))
        issued.clear_code()
        code[:] = b"\x00" * len(code)

    def test_challenge_is_single_use(self) -> None:
        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        code = bytearray(issued.code)
        self.broker.verify(
            issued.challenge_id,
            code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding=self.CLIENT,
        )

        with self.assertRaises(OneTimeCodeDenied):
            self.broker.verify(
                issued.challenge_id,
                code,
                principal_id=self.PRINCIPAL,
                profile_id=self.PROFILE,
                client_binding=self.CLIENT,
            )
        self.assertEqual(self.broker.active_count, 0)

    def test_verified_evidence_returns_trusted_copy_and_is_single_use(
        self,
    ) -> None:
        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        evidence = self.broker.verify(
            issued.challenge_id,
            issued.code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding=self.CLIENT,
        )

        self.assertEqual(self.broker.pending_evidence_count, 1)
        consumed = self.broker.consume_evidence(evidence)
        self.assertIsNot(consumed, evidence)
        self.assertEqual(consumed, evidence)
        self.assertEqual(self.broker.pending_evidence_count, 0)
        with self.assertRaises(OneTimeCodeDenied):
            self.broker.consume_evidence(evidence)

    def test_copied_evidence_fails_closed_and_consumes_original(self) -> None:
        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        evidence = self.broker.verify(
            issued.challenge_id,
            issued.code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding=self.CLIENT,
        )

        with self.assertRaises(OneTimeCodeDenied):
            self.broker.consume_evidence(replace(evidence))
        with self.assertRaises(OneTimeCodeDenied):
            self.broker.consume_evidence(evidence)
        self.assertEqual(self.broker.pending_evidence_count, 0)

    def test_object_setattr_privilege_mutation_fails_closed(self) -> None:
        mutations = (
            ("principal_id", "idp_subject_privileged"),
            ("profile_id", "administrator"),
            ("authorization_context", "other_vault"),
            ("authorization_epoch", 999),
            ("challenge_id", "A" * 43),
        )
        for field_name, replacement_value in mutations:
            with self.subTest(field=field_name):
                issued = self.broker.issue(
                    self.PRINCIPAL,
                    self.PROFILE,
                    self.CLIENT,
                    authorization_context="vault_security_context",
                    authorization_epoch=7,
                )
                evidence = self.broker.verify(
                    issued.challenge_id,
                    issued.code,
                    principal_id=self.PRINCIPAL,
                    profile_id=self.PROFILE,
                    client_binding=self.CLIENT,
                )
                object.__setattr__(
                    evidence,
                    field_name,
                    replacement_value,
                )

                with self.assertRaises(OneTimeCodeDenied):
                    self.broker.consume_evidence(evidence)
                self.assertEqual(self.broker.pending_evidence_count, 0)
                issued.clear_code()

    def test_every_verification_failure_is_generic(self) -> None:
        failures: list[tuple[type[BaseException], str]] = []

        def capture(
            issued_id: str,
            code: object,
            *,
            principal: str = self.PRINCIPAL,
            profile: str = self.PROFILE,
            client: str = self.CLIENT,
        ) -> None:
            try:
                self.broker.verify(
                    issued_id,
                    code,  # type: ignore[arg-type]
                    principal_id=principal,
                    profile_id=profile,
                    client_binding=client,
                )
            except BaseException as exc:
                failures.append((type(exc), str(exc)))

        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        capture(issued.challenge_id, b"999999")

        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        capture(issued.challenge_id, issued.code, client="wrong_client")

        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        capture(issued.challenge_id, b"not-digits")

        capture("not-a-challenge", b"123456")

        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        self.clock.advance(60)
        capture(issued.challenge_id, issued.code)

        self.assertEqual(len(failures), 5)
        self.assertEqual(
            {failure_type for failure_type, _ in failures},
            {OneTimeCodeDenied},
        )
        self.assertEqual(
            {message for _, message in failures},
            {"The one-time-code challenge could not be verified."},
        )

    def test_failed_attempts_exhaust_and_invalidate_challenge(self) -> None:
        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        for _ in range(3):
            with self.assertRaises(OneTimeCodeDenied):
                self.broker.verify(
                    issued.challenge_id,
                    b"000000"
                    if issued.code != bytearray(b"000000")
                    else b"111111",
                    principal_id=self.PRINCIPAL,
                    profile_id=self.PROFILE,
                    client_binding=self.CLIENT,
                )
        self.assertEqual(self.broker.active_count, 0)
        with self.assertRaises(OneTimeCodeDenied):
            self.broker.verify(
                issued.challenge_id,
                issued.code,
                principal_id=self.PRINCIPAL,
                profile_id=self.PROFILE,
                client_binding=self.CLIENT,
            )

    def test_wrong_binding_consumes_an_attempt(self) -> None:
        broker = InMemoryOneTimeCodeBroker(
            ttl_seconds=60,
            max_attempts=1,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close)
        issued = broker.issue(self.PRINCIPAL, self.PROFILE, self.CLIENT)

        with self.assertRaises(OneTimeCodeDenied):
            broker.verify(
                issued.challenge_id,
                issued.code,
                principal_id=self.PRINCIPAL,
                profile_id=self.PROFILE,
                client_binding="other_browser_session",
            )
        with self.assertRaises(OneTimeCodeDenied):
            broker.verify(
                issued.challenge_id,
                issued.code,
                principal_id=self.PRINCIPAL,
                profile_id=self.PROFILE,
                client_binding=self.CLIENT,
            )
        self.assertEqual(broker.active_count, 0)

    def test_resend_invalidates_previous_challenge_for_exact_binding(self) -> None:
        original = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        replacement = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )

        self.assertEqual(self.broker.active_count, 1)
        with self.assertRaises(OneTimeCodeDenied):
            self.broker.verify(
                original.challenge_id,
                original.code,
                principal_id=self.PRINCIPAL,
                profile_id=self.PROFILE,
                client_binding=self.CLIENT,
            )
        self.broker.verify(
            replacement.challenge_id,
            replacement.code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding=self.CLIENT,
        )

    def test_resend_invalidates_already_verified_evidence(self) -> None:
        authorization_context = "vault_security_context"
        original = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
            authorization_context=authorization_context,
        )
        evidence = self.broker.verify(
            original.challenge_id,
            original.code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding=self.CLIENT,
        )
        self.assertEqual(self.broker.pending_evidence_count, 1)

        replacement = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
            authorization_context=authorization_context,
        )

        self.assertEqual(self.broker.pending_evidence_count, 0)
        self.assertEqual(self.broker.active_count, 1)
        with self.assertRaises(OneTimeCodeDenied):
            self.broker.consume_evidence(evidence)
        replacement_evidence = self.broker.verify(
            replacement.challenge_id,
            replacement.code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding=self.CLIENT,
        )
        consumed = self.broker.consume_evidence(replacement_evidence)
        self.assertIsNot(consumed, replacement_evidence)
        self.assertEqual(consumed, replacement_evidence)
        original.clear_code()
        replacement.clear_code()

    def test_different_client_bindings_have_independent_challenges(self) -> None:
        first = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            "browser_session_one",
        )
        second = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            "browser_session_two",
        )

        self.assertEqual(self.broker.active_count, 2)
        self.broker.verify(
            first.challenge_id,
            first.code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding="browser_session_one",
        )
        self.broker.verify(
            second.challenge_id,
            second.code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding="browser_session_two",
        )

    def test_expiry_boundary_and_explicit_cleanup(self) -> None:
        first = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        second = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            "other_client",
        )
        self.clock.advance(59.99)
        self.assertEqual(self.broker.purge_expired(), 0)
        self.clock.advance(0.01)

        self.assertEqual(self.broker.purge_expired(), 2)
        self.assertEqual(self.broker.active_count, 0)
        for issued, client in (
            (first, self.CLIENT),
            (second, "other_client"),
        ):
            with self.assertRaises(OneTimeCodeDenied):
                self.broker.verify(
                    issued.challenge_id,
                    issued.code,
                    principal_id=self.PRINCIPAL,
                    profile_id=self.PROFILE,
                    client_binding=client,
                )

    def test_only_one_concurrent_verification_can_succeed(self) -> None:
        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        barrier = threading.Barrier(3)
        results: list[str] = []
        results_lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            try:
                self.broker.verify(
                    issued.challenge_id,
                    issued.code,
                    principal_id=self.PRINCIPAL,
                    profile_id=self.PROFILE,
                    client_binding=self.CLIENT,
                )
                result = "verified"
            except OneTimeCodeDenied:
                result = "denied"
            with results_lock:
                results.append(result)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertEqual(sorted(results), ["denied", "verified"])

    def test_close_clears_state_and_verifier_key(self) -> None:
        issued = self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            self.CLIENT,
        )
        self.broker.issue(
            self.PRINCIPAL,
            self.PROFILE,
            "other_client",
        )
        verifier_key = self.broker._verifier_key

        self.assertEqual(self.broker.close(), 2)
        self.assertTrue(self.broker.closed)
        self.assertEqual(verifier_key, bytearray(b"\x00" * 32))
        self.assertEqual(self.broker.active_count, 0)
        self.assertEqual(self.broker.close(), 0)
        with self.assertRaises(OneTimeCodeDenied):
            self.broker.verify(
                issued.challenge_id,
                issued.code,
                principal_id=self.PRINCIPAL,
                profile_id=self.PROFILE,
                client_binding=self.CLIENT,
            )
        with self.assertRaises(OneTimeCodeUnavailable):
            self.broker.issue(
                self.PRINCIPAL,
                self.PROFILE,
                self.CLIENT,
            )

    def test_context_manager_closes_broker(self) -> None:
        with InMemoryOneTimeCodeBroker(
            sweep_interval_seconds=None,
            clock=self.clock,
        ) as broker:
            broker.issue(self.PRINCIPAL, self.PROFILE, self.CLIENT)
            self.assertFalse(broker.closed)
        self.assertTrue(broker.closed)
        self.assertEqual(broker.active_count, 0)

    def test_capacity_fails_without_invalidating_existing_challenge(self) -> None:
        broker = InMemoryOneTimeCodeBroker(
            max_active_challenges=1,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close)
        existing = broker.issue(self.PRINCIPAL, self.PROFILE, self.CLIENT)

        with self.assertRaises(OneTimeCodeUnavailable):
            broker.issue(self.PRINCIPAL, self.PROFILE, "other_client")
        self.assertEqual(broker.active_count, 1)
        broker.verify(
            existing.challenge_id,
            existing.code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding=self.CLIENT,
        )

    def test_pending_evidence_counts_toward_capacity(self) -> None:
        broker = InMemoryOneTimeCodeBroker(
            max_active_challenges=1,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(broker.close)
        issued = broker.issue(self.PRINCIPAL, self.PROFILE, self.CLIENT)
        broker.verify(
            issued.challenge_id,
            issued.code,
            principal_id=self.PRINCIPAL,
            profile_id=self.PROFILE,
            client_binding=self.CLIENT,
        )

        with self.assertRaises(OneTimeCodeUnavailable):
            broker.issue(self.PRINCIPAL, self.PROFILE, "other_client")

    def test_configuration_and_issue_bindings_are_validated(self) -> None:
        invalid_configurations = (
            {"code_digits": 5},
            {"code_digits": 11},
            {"ttl_seconds": 0},
            {"max_attempts": 0},
            {"max_active_challenges": 0},
            {"sweep_interval_seconds": float("nan")},
        )
        for configuration in invalid_configurations:
            with self.subTest(configuration=configuration):
                with self.assertRaises(ValidationError):
                    InMemoryOneTimeCodeBroker(**configuration)

        for principal, profile, client in (
            ("", self.PROFILE, self.CLIENT),
            (self.PRINCIPAL, "", self.CLIENT),
            (self.PRINCIPAL, self.PROFILE, ""),
            (self.PRINCIPAL, self.PROFILE, "bad\nclient"),
        ):
            with self.subTest(
                principal=principal,
                profile=profile,
                client=client,
            ):
                with self.assertRaises(ValidationError):
                    self.broker.issue(principal, profile, client)
        with self.assertRaises(ValidationError):
            self.broker.issue(
                self.PRINCIPAL,
                self.PROFILE,
                self.CLIENT,
                authorization_epoch=0,
            )


if __name__ == "__main__":
    unittest.main()
