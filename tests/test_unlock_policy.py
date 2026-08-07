from __future__ import annotations

import threading
import unittest
from contextlib import contextmanager
from dataclasses import replace

from authgraph import (
    CryptoEngine,
    InMemoryGraphRepository,
    KdfParameters,
    RecordNotFound,
    SessionUnavailable,
)
from authgraph.otp import (
    InMemoryOneTimeCodeBroker,
    OneTimeCodeDenied,
    OneTimeCodeEvidence,
)
from authgraph.scoped_service import ScopedAuthGraphService
from authgraph.scoped_sessions import ScopedSessionBroker
from authgraph.unlock_policy import (
    InMemoryScopeKeyProvider,
    ScopeGrantDenied,
    ScopeGrantPolicy,
    UnlockProfile,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class AdvancingReleaseProvider:
    def __init__(
        self,
        provider: InMemoryScopeKeyProvider,
        clock: FakeClock,
        seconds: float,
    ) -> None:
        self.provider = provider
        self.clock = clock
        self.seconds = seconds

    @contextmanager
    def lease_scope_keys(self, grant):
        with self.provider.lease_scope_keys(grant) as released:
            self.clock.advance(self.seconds)
            yield released


class FailingReleaseExitProvider:
    def __init__(self, provider: InMemoryScopeKeyProvider) -> None:
        self.provider = provider

    @contextmanager
    def lease_scope_keys(self, grant):
        with self.provider.lease_scope_keys(grant) as released:
            yield released
        raise RuntimeError("Synthetic provider context-exit failure.")


class OtpScopedUnlockTests(unittest.TestCase):
    PRINCIPAL = "idp|otp-owner"
    PASSPHRASE = bytearray(b"synthetic otp owner passphrase")

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.repository = InMemoryGraphRepository()
        self.crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        self.sessions = ScopedSessionBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(self.sessions.close_all)
        self.service = ScopedAuthGraphService(
            self.repository,
            self.crypto,
            self.sessions,
            clock=self.clock,
        )
        self.vault_id = self.service.create_vault(
            self.PRINCIPAL,
            self.PASSPHRASE,
        )
        self.profile_scope = self.service.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )
        self.orders_scope = self.service.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )
        context = self.service.unlock(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
            (self.profile_scope, self.orders_scope),
        )
        self.profile_entity = self.service.create_entity(
            context,
            self.profile_scope,
            "Profile",
            {"name": "Synthetic Owner"},
        )
        self.order_entity = self.service.create_entity(
            context,
            self.orders_scope,
            "Order",
            {"status": "delayed"},
        )
        self.service.lock(context)

        self.provider = InMemoryScopeKeyProvider()
        self.addCleanup(self.provider.close)
        self.service.enroll_key_release_provider(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
            (self.profile_scope, self.orders_scope),
            self.provider,
        )
        self.profile = UnlockProfile(
            profile_id="order-support",
            scope_ids=(self.orders_scope,),
            session_ttl_seconds=30,
            allow_one_time_code=True,
        )
        self.policy = ScopeGrantPolicy(
            {self.profile.profile_id: self.profile},
            clock=self.clock,
        )
        self.addCleanup(self.policy.close)
        self.otp = InMemoryOneTimeCodeBroker(
            ttl_seconds=60,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(self.otp.close)

    def otp_grant(self):
        evidence = self.otp_evidence("browser-session-1")
        return self.policy.authorize_one_time_code(
            evidence,
            vault_id=self.vault_id,
            evidence_consumer=self.otp,
        )

    def otp_evidence(self, client_binding: str):
        issued = self.otp.issue(
            self.PRINCIPAL,
            self.profile.profile_id,
            client_binding,
            authorization_context=self.vault_id,
            authorization_epoch=self.service.get_authorization_epoch(
                self.PRINCIPAL,
                self.vault_id,
            ),
        )
        try:
            evidence = self.otp.verify(
                issued.challenge_id,
                issued.code,
                principal_id=self.PRINCIPAL,
                profile_id=self.profile.profile_id,
                client_binding=client_binding,
            )
        finally:
            issued.clear_code()
        return evidence

    def test_otp_evidence_releases_only_profile_configured_scope(self) -> None:
        context = self.service.unlock_with_provider(
            self.otp_grant(),
            self.policy,
            self.provider,
        )
        snapshot = self.service.get_vault_snapshot(context)
        self.assertEqual(
            [(entity.kind, entity.properties) for entity in snapshot.entities],
            [("Order", {"status": "delayed"})],
        )
        self.assertEqual(
            self.service.get_entity(context, self.order_entity).kind,
            "Order",
        )
        with self.assertRaises(RecordNotFound):
            self.service.get_entity(context, self.profile_entity)
        self.service.lock(context)

    def test_grant_is_single_use(self) -> None:
        grant = self.otp_grant()
        context = self.service.unlock_with_provider(
            grant,
            self.policy,
            self.provider,
        )
        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                self.provider,
            )
        self.service.lock(context)

    def test_consumed_grant_is_a_separate_trusted_copy(self) -> None:
        grant = self.otp_grant()

        consumed = self.policy.consume(grant)

        self.assertIsNot(consumed, grant)
        self.assertEqual(consumed, grant)

    def test_mutated_grant_fails_closed_and_consumes_original(self) -> None:
        grant = self.otp_grant()
        forged = replace(grant, scope_ids=(self.profile_scope,))
        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                forged,
                self.policy,
                self.provider,
            )
        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                self.provider,
            )

    def test_object_setattr_grant_mutations_fail_closed(self) -> None:
        for field_name in (
            "principal_id",
            "vault_id",
            "scope_ids",
            "authorization_epoch",
        ):
            with self.subTest(field=field_name):
                grant = self.otp_grant()
                replacements = {
                    "principal_id": "idp|privileged-owner",
                    "vault_id": "other-vault",
                    "scope_ids": (self.profile_scope,),
                    "authorization_epoch": grant.authorization_epoch + 1,
                }
                object.__setattr__(
                    grant,
                    field_name,
                    replacements[field_name],
                )

                with self.assertRaises(ScopeGrantDenied):
                    self.policy.consume(grant)
                self.assertEqual(self.policy.active_count, 0)

    def test_exact_copied_grant_is_rejected_and_consumes_original(self) -> None:
        grant = self.otp_grant()
        copied = replace(grant)
        self.assertIsNot(copied, grant)
        self.assertEqual(copied, grant)

        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                copied,
                self.policy,
                self.provider,
            )
        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                self.provider,
            )

    def test_expired_grant_cannot_release_keys(self) -> None:
        grant = self.otp_grant()
        self.clock.advance(31)
        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                self.provider,
            )

    def test_grant_expiring_during_key_release_is_denied(self) -> None:
        grant = self.otp_grant()
        advancing_provider = AdvancingReleaseProvider(
            self.provider,
            self.clock,
            31,
        )

        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                advancing_provider,
            )

    def test_session_open_delay_cannot_extend_absolute_grant_expiry(self) -> None:
        grant = self.otp_grant()
        original_open = self.sessions.open

        def delayed_open(*args, **kwargs):
            self.clock.advance(20)
            return original_open(*args, **kwargs)

        self.sessions.open = delayed_open  # type: ignore[method-assign]
        context = self.service.unlock_with_provider(
            grant,
            self.policy,
            self.provider,
        )
        self.clock.advance(10)

        with self.assertRaises(SessionUnavailable):
            self.service.get_entity(context, self.order_entity)
        self.assertEqual(self.sessions.active_count, 0)
        self.assertEqual(self.sessions.resident_scope_ciphertext_count, 0)

    def test_provider_context_exit_failure_leaves_no_session(self) -> None:
        grant = self.otp_grant()
        failing_provider = FailingReleaseExitProvider(self.provider)

        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                failing_provider,
            )

        self.assertEqual(self.sessions.active_count, 0)
        self.assertEqual(self.sessions.resident_scope_ciphertext_count, 0)

    def test_password_change_invalidates_an_older_grant(self) -> None:
        grant = self.otp_grant()
        new_passphrase = bytearray(
            b"new synthetic passphrase invalidating old grant"
        )
        self.service.change_passphrase(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
            new_passphrase,
        )

        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                self.provider,
            )

    def test_profile_must_explicitly_allow_one_time_code(self) -> None:
        denied_profile = UnlockProfile(
            profile_id="no-code",
            scope_ids=(self.orders_scope,),
            session_ttl_seconds=30,
            allow_one_time_code=False,
        )
        denied_policy = ScopeGrantPolicy(
            {denied_profile.profile_id: denied_profile},
            clock=self.clock,
        )
        self.addCleanup(denied_policy.close)
        issued = self.otp.issue(
            self.PRINCIPAL,
            denied_profile.profile_id,
            "browser-session-2",
            authorization_context=self.vault_id,
        )
        try:
            evidence = self.otp.verify(
                issued.challenge_id,
                issued.code,
                principal_id=self.PRINCIPAL,
                profile_id=denied_profile.profile_id,
                client_binding="browser-session-2",
            )
        finally:
            issued.clear_code()
        with self.assertRaises(ScopeGrantDenied):
            denied_policy.authorize_one_time_code(
                evidence,
                vault_id=self.vault_id,
                evidence_consumer=self.otp,
            )

    def test_constructed_evidence_cannot_mint_a_scope_grant(self) -> None:
        issued = self.otp.issue(
            self.PRINCIPAL,
            self.profile.profile_id,
            "browser-session-1",
            authorization_context=self.vault_id,
        )
        forged = OneTimeCodeEvidence(
            principal_id=self.PRINCIPAL,
            profile_id=self.profile.profile_id,
            client_binding="browser-session-1",
            authorization_context=self.vault_id,
            challenge_id=issued.challenge_id,
            authorization_epoch=self.service.get_authorization_epoch(
                self.PRINCIPAL,
                self.vault_id,
            ),
            verified_at=self.clock.value,
            challenge_expires_at=issued.expires_at,
        )

        with self.assertRaises(ScopeGrantDenied):
            self.policy.authorize_one_time_code(
                forged,
                vault_id=self.vault_id,
                evidence_consumer=self.otp,
            )

    def test_verified_evidence_can_mint_only_one_scope_grant(self) -> None:
        issued = self.otp.issue(
            self.PRINCIPAL,
            self.profile.profile_id,
            "browser-session-1",
            authorization_context=self.vault_id,
        )
        try:
            evidence = self.otp.verify(
                issued.challenge_id,
                issued.code,
                principal_id=self.PRINCIPAL,
                profile_id=self.profile.profile_id,
                client_binding="browser-session-1",
            )
        finally:
            issued.clear_code()

        self.policy.authorize_one_time_code(
            evidence,
            vault_id=self.vault_id,
            evidence_consumer=self.otp,
        )
        with self.assertRaises(ScopeGrantDenied):
            self.policy.authorize_one_time_code(
                evidence,
                vault_id=self.vault_id,
                evidence_consumer=self.otp,
            )

    def test_expired_grant_is_purged_before_capacity_check(self) -> None:
        short_profile = UnlockProfile(
            profile_id=self.profile.profile_id,
            scope_ids=self.profile.scope_ids,
            session_ttl_seconds=1,
            allow_one_time_code=True,
        )
        limited_policy = ScopeGrantPolicy(
            {short_profile.profile_id: short_profile},
            max_active_grants=1,
            clock=self.clock,
        )
        self.addCleanup(limited_policy.close)
        first_evidence = self.otp_evidence("capacity-session-1")
        limited_policy.authorize_one_time_code(
            first_evidence,
            vault_id=self.vault_id,
            evidence_consumer=self.otp,
        )
        self.clock.advance(2)
        second_evidence = self.otp_evidence("capacity-session-2")

        second_grant = limited_policy.authorize_one_time_code(
            second_evidence,
            vault_id=self.vault_id,
            evidence_consumer=self.otp,
        )

        self.assertEqual(limited_policy.active_count, 1)
        self.assertEqual(
            second_grant.client_binding,
            "capacity-session-2",
        )

    def test_capacity_denial_does_not_consume_verified_evidence(self) -> None:
        limited_policy = ScopeGrantPolicy(
            {self.profile.profile_id: self.profile},
            max_active_grants=1,
            clock=self.clock,
        )
        self.addCleanup(limited_policy.close)
        first_evidence = self.otp_evidence("full-capacity-session")
        limited_policy.authorize_one_time_code(
            first_evidence,
            vault_id=self.vault_id,
            evidence_consumer=self.otp,
        )
        retained_evidence = self.otp_evidence("retained-evidence-session")

        with self.assertRaises(ScopeGrantDenied):
            limited_policy.authorize_one_time_code(
                retained_evidence,
                vault_id=self.vault_id,
                evidence_consumer=self.otp,
            )

        self.assertEqual(self.otp.pending_evidence_count, 1)
        consumed = self.otp.consume_evidence(retained_evidence)
        self.assertIsNot(consumed, retained_evidence)
        self.assertEqual(consumed, retained_evidence)
        self.assertEqual(self.otp.pending_evidence_count, 0)

    def test_otp_authorization_context_cannot_target_another_vault(self) -> None:
        other_vault_id = self.service.create_vault(
            self.PRINCIPAL,
            self.PASSPHRASE,
        )
        evidence = self.otp_evidence("wrong-vault-session")

        with self.assertRaises(ScopeGrantDenied):
            self.policy.authorize_one_time_code(
                evidence,
                vault_id=other_vault_id,
                evidence_consumer=self.otp,
            )

        self.assertEqual(self.otp.pending_evidence_count, 0)
        with self.assertRaises(OneTimeCodeDenied):
            self.otp.consume_evidence(evidence)

    def test_provider_slots_survive_password_rewrap_not_key_rotation(
        self,
    ) -> None:
        new_passphrase = bytearray(b"new synthetic otp owner passphrase")
        self.service.change_passphrase(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
            new_passphrase,
        )
        context = self.service.unlock_with_provider(
            self.otp_grant(),
            self.policy,
            self.provider,
        )
        self.assertEqual(
            self.service.get_entity(context, self.order_entity).kind,
            "Order",
        )
        self.service.lock(context)

    def test_closed_provider_cannot_release_keys(self) -> None:
        grant = self.otp_grant()
        self.provider.close()
        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                self.provider,
            )

    def test_provider_close_waits_for_an_inflight_session_open(self) -> None:
        grant = self.otp_grant()
        entered_open = threading.Event()
        continue_open = threading.Event()
        close_finished = threading.Event()
        result = []
        original_open = self.sessions.open

        def blocking_open(*args, **kwargs):
            entered_open.set()
            if not continue_open.wait(timeout=5):
                raise AssertionError("Timed out waiting to continue session open.")
            return original_open(*args, **kwargs)

        self.sessions.open = blocking_open  # type: ignore[method-assign]

        def unlock_worker() -> None:
            try:
                result.append(
                    self.service.unlock_with_provider(
                        grant,
                        self.policy,
                        self.provider,
                    )
                )
            except BaseException as exc:
                result.append(exc)

        def close_worker() -> None:
            self.provider.close()
            close_finished.set()

        unlock_thread = threading.Thread(target=unlock_worker)
        close_thread = threading.Thread(target=close_worker)
        unlock_thread.start()
        self.assertTrue(entered_open.wait(timeout=5))
        close_thread.start()
        close_thread.join(timeout=0.05)
        self.assertFalse(close_finished.is_set())

        continue_open.set()
        unlock_thread.join(timeout=5)
        close_thread.join(timeout=5)
        self.assertFalse(unlock_thread.is_alive())
        self.assertFalse(close_thread.is_alive())
        self.assertTrue(close_finished.is_set())
        self.assertEqual(len(result), 1)
        self.assertNotIsInstance(result[0], BaseException)
        self.service.lock(result[0])

    def test_provider_release_through_session_open_holds_lifecycle_fence(
        self,
    ) -> None:
        grant = self.otp_grant()
        entered_open = threading.Event()
        continue_open = threading.Event()
        transition_finished = threading.Event()
        original_open = self.sessions.open
        unlock_results: list[object] = []
        transition_results: list[object] = []

        def blocking_open(*args, **kwargs):
            entered_open.set()
            if not continue_open.wait(timeout=5):
                raise AssertionError("Timed out waiting to continue session open.")
            return original_open(*args, **kwargs)

        self.sessions.open = blocking_open  # type: ignore[method-assign]

        def unlock_worker() -> None:
            try:
                unlock_results.append(
                    self.service.unlock_with_provider(
                        grant,
                        self.policy,
                        self.provider,
                    )
                )
            except BaseException as exc:
                unlock_results.append(exc)

        def transition_worker() -> None:
            try:
                transition_results.append(
                    self.sessions.begin_management_transition(
                        self.PRINCIPAL,
                        self.vault_id,
                        1,
                    )
                )
            except BaseException as exc:
                transition_results.append(exc)
            finally:
                transition_finished.set()

        unlock_thread = threading.Thread(target=unlock_worker)
        transition_thread = threading.Thread(target=transition_worker)
        unlock_thread.start()
        self.assertTrue(entered_open.wait(timeout=5))
        transition_thread.start()
        self.assertFalse(transition_finished.wait(timeout=0.05))

        continue_open.set()
        unlock_thread.join(timeout=5)
        transition_thread.join(timeout=5)
        self.assertFalse(unlock_thread.is_alive())
        self.assertFalse(transition_thread.is_alive())
        self.assertEqual(len(unlock_results), 1)
        self.assertNotIsInstance(unlock_results[0], BaseException)
        self.assertEqual(len(transition_results), 1)
        self.assertNotIsInstance(transition_results[0], BaseException)
        with self.assertRaises(SessionUnavailable):
            self.service.get_entity(unlock_results[0], self.order_entity)

    def test_provider_enrollment_and_unlock_do_not_invert_locks(self) -> None:
        grant = self.otp_grant()
        entered_open = threading.Event()
        continue_open = threading.Event()
        enrollment_reached_provider = threading.Event()
        original_open = self.sessions.open
        original_enroll = self.provider.enroll_scope_keys
        guard_states: list[bool] = []
        unlock_results: list[object] = []
        enrollment_results: list[object] = []

        def blocking_open(*args, **kwargs):
            entered_open.set()
            if not continue_open.wait(timeout=5):
                raise AssertionError("Timed out waiting to continue session open.")
            return original_open(*args, **kwargs)

        def observed_enroll(**kwargs):
            guard_counts = getattr(
                self.sessions._base._guard_state,
                "counts",
                {},
            )
            guard_is_held = bool(guard_counts)
            guard_states.append(guard_is_held)
            enrollment_reached_provider.set()
            if guard_is_held:
                raise AssertionError(
                    "Provider enrollment was called under the vault guard."
                )
            return original_enroll(**kwargs)

        self.sessions.open = blocking_open  # type: ignore[method-assign]
        self.provider.enroll_scope_keys = observed_enroll  # type: ignore[method-assign]

        def unlock_worker() -> None:
            try:
                unlock_results.append(
                    self.service.unlock_with_provider(
                        grant,
                        self.policy,
                        self.provider,
                    )
                )
            except BaseException as exc:
                unlock_results.append(exc)

        def enrollment_worker() -> None:
            try:
                self.service.enroll_key_release_provider(
                    self.PRINCIPAL,
                    self.vault_id,
                    self.PASSPHRASE,
                    (self.orders_scope,),
                    self.provider,
                )
                enrollment_results.append("enrolled")
            except BaseException as exc:
                enrollment_results.append(exc)

        unlock_thread = threading.Thread(target=unlock_worker, daemon=True)
        enrollment_thread = threading.Thread(
            target=enrollment_worker,
            daemon=True,
        )
        unlock_thread.start()
        self.assertTrue(entered_open.wait(timeout=5))
        enrollment_thread.start()
        self.assertFalse(enrollment_reached_provider.wait(timeout=0.05))
        continue_open.set()
        reached_provider = enrollment_reached_provider.wait(timeout=5)
        unlock_thread.join(timeout=5)
        enrollment_thread.join(timeout=5)

        self.assertTrue(reached_provider)
        self.assertFalse(unlock_thread.is_alive())
        self.assertFalse(enrollment_thread.is_alive())
        self.assertEqual(guard_states, [False])
        self.assertEqual(enrollment_results, ["enrolled"])
        self.assertEqual(len(unlock_results), 1)
        self.assertNotIsInstance(unlock_results[0], BaseException)
        self.service.lock(unlock_results[0])

    def test_provider_scope_revocation_blocks_future_release(self) -> None:
        grant = self.otp_grant()
        slot = self.provider._slots[
            (self.PRINCIPAL, self.vault_id, self.orders_scope)
        ]
        ciphertext = slot.ciphertext

        self.assertEqual(
            self.provider.revoke_scope_keys(
                self.PRINCIPAL,
                self.vault_id,
                (self.orders_scope,),
            ),
            1,
        )

        self.assertEqual(ciphertext, bytearray(len(ciphertext)))
        self.assertEqual(self.provider.enrolled_scope_count, 1)
        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                self.provider,
            )

    def test_provider_vault_revocation_blocks_future_release(self) -> None:
        grant = self.otp_grant()
        ciphertexts = [
            slot.ciphertext
            for slot_key, slot in self.provider._slots.items()
            if slot_key[:2] == (self.PRINCIPAL, self.vault_id)
        ]

        self.assertEqual(
            self.provider.revoke_vault(
                self.PRINCIPAL,
                self.vault_id,
            ),
            2,
        )

        self.assertTrue(
            all(
                ciphertext == bytearray(len(ciphertext))
                for ciphertext in ciphertexts
            )
        )
        self.assertEqual(self.provider.enrolled_scope_count, 0)
        with self.assertRaises(ScopeGrantDenied):
            self.service.unlock_with_provider(
                grant,
                self.policy,
                self.provider,
            )

    def test_otp_and_provider_never_store_plaintext_graph_semantics(self) -> None:
        raw = repr(self.repository.ciphertext_snapshot())
        self.assertNotIn("Synthetic Owner", raw)
        self.assertNotIn("delayed", raw)
        self.assertEqual(self.provider.enrolled_scope_count, 2)
        self.assertNotIn("scope_ids", repr(self.otp_grant()))


if __name__ == "__main__":
    unittest.main()
