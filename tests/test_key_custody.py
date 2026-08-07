from __future__ import annotations

import threading
import unittest
from contextlib import contextmanager
from dataclasses import replace

from authgraph.aws_kms import (
    AWS_KMS_ALGORITHM,
    AWS_KMS_PURPOSE,
    AwsKmsKeyWrappingBackend,
)
from authgraph.errors import ValidationError
from authgraph.key_custody import (
    EnvelopeScopeKeyProvider,
    InMemoryAesKeyWrappingBackend,
    InMemoryKeySlotStore,
    KeyCustodyConflict,
    KeyCustodyUnavailable,
    KeySlotIdentity,
    KeySlotRow,
    KeySlotState,
    KeySlotStore,
    KeyWrappingBackend,
)
from authgraph.scoped_sessions import ScopeKeyMaterial
from authgraph.unlock_policy import (
    ScopeGrantDenied,
    ScopeKeyEnrollmentProvider,
    ScopeKeyReleaseProvider,
    ScopeUnlockGrant,
)

PRINCIPAL = "idp|custody-owner"
VAULT = "v2_custody-vault"
SCOPE_A = "scope_custody-a"
SCOPE_B = "scope_custody-b"


def grant(*scope_ids: str, epoch: int = 3) -> ScopeUnlockGrant:
    return ScopeUnlockGrant(
        principal_id=PRINCIPAL,
        profile_id="custody-profile",
        vault_id=VAULT,
        scope_ids=tuple(scope_ids),
        client_binding="browser-custody",
        authorization_epoch=epoch,
        evidence_provider="unit-test",
        evidence_id="evidence-custody",
        issued_at=100.0,
        expires_at=200.0,
        grant_id="grant-custody",
    )


class FakeAwsKmsClient:
    def __init__(self) -> None:
        self.canonical_key_id = (
            "arn:aws:kms:eu-central-1:111122223333:key/synthetic"
        )
        self.encrypt_calls: list[dict[str, object]] = []
        self.decrypt_calls: list[dict[str, object]] = []
        self.encrypt_plaintext_reference: bytearray | None = None
        self.decrypt_plaintext_reference: bytearray | None = None
        self._plaintext_by_blob: dict[bytes, bytes] = {}
        self._context_by_blob: dict[bytes, object] = {}
        self._counter = 0

    def encrypt(self, **kwargs: object) -> dict[str, object]:
        self.encrypt_calls.append(kwargs)
        plaintext = kwargs["Plaintext"]
        if not isinstance(plaintext, bytearray):
            raise AssertionError("adapter must provide a mutable temporary")
        self.encrypt_plaintext_reference = plaintext
        self._counter += 1
        blob = f"synthetic-kms-blob-{self._counter}".encode("ascii")
        self._plaintext_by_blob[blob] = bytes(plaintext)
        self._context_by_blob[blob] = kwargs["EncryptionContext"]
        return {
            "CiphertextBlob": blob,
            "KeyId": self.canonical_key_id,
            "EncryptionAlgorithm": AWS_KMS_ALGORITHM,
        }

    def decrypt(self, **kwargs: object) -> dict[str, object]:
        self.decrypt_calls.append(kwargs)
        blob = kwargs["CiphertextBlob"]
        if (
            not isinstance(blob, bytes)
            or kwargs["EncryptionContext"] != self._context_by_blob.get(blob)
        ):
            raise RuntimeError("provider detail must not escape")
        plaintext = bytearray(self._plaintext_by_blob[blob])
        self.decrypt_plaintext_reference = plaintext
        return {
            "Plaintext": plaintext,
            "KeyId": kwargs["KeyId"],
            "EncryptionAlgorithm": AWS_KMS_ALGORITHM,
        }


class CallbackWrappingBackend:
    """Test wrapper that changes durable state during a key release."""

    def __init__(self, backend: InMemoryAesKeyWrappingBackend) -> None:
        self.backend = backend
        self.callback = lambda: None
        self.last_plaintext: bytearray | None = None

    @property
    def backend_id(self) -> str:
        return self.backend.backend_id

    def wrap_key(self, plaintext, *, aad):
        return self.backend.wrap_key(plaintext, aad=aad)

    @contextmanager
    def unwrap_key(self, wrapped_key, *, aad):
        with self.backend.unwrap_key(wrapped_key, aad=aad) as plaintext:
            self.last_plaintext = plaintext
            self.callback()
            yield plaintext


class KeyCustodyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = InMemoryKeySlotStore()
        self.old_backend = InMemoryAesKeyWrappingBackend(
            backend_id="test-kek-2025",
            key_id="test-kek-2025",
            wrapping_key=b"o" * 32,
        )
        self.new_backend = InMemoryAesKeyWrappingBackend(
            backend_id="test-kek-2026",
            key_id="test-kek-2026",
            wrapping_key=b"n" * 32,
        )
        self.addCleanup(self.old_backend.close)
        self.addCleanup(self.new_backend.close)
        self.provider = EnvelopeScopeKeyProvider(
            self.store,
            {
                self.old_backend.backend_id: self.old_backend,
                self.new_backend.backend_id: self.new_backend,
            },
            active_backend_id=self.old_backend.backend_id,
        )
        self.key_a = bytearray(b"a" * 32)
        self.key_b = bytearray(b"b" * 32)
        self.addCleanup(self._clear_inputs)

    def _clear_inputs(self) -> None:
        self.key_a[:] = b"\x00" * len(self.key_a)
        self.key_b[:] = b"\x00" * len(self.key_b)

    def enroll_both(self, *, envelope_revision: int = 1) -> None:
        self.provider.enroll_scope_keys(
            principal_id=PRINCIPAL,
            vault_id=VAULT,
            envelope_revision=envelope_revision,
            root_key_version=7,
            scope_keys={
                SCOPE_A: ScopeKeyMaterial(11, self.key_a),
                SCOPE_B: ScopeKeyMaterial(12, self.key_b),
            },
        )

    def rows(self, *scope_ids: str) -> tuple[KeySlotRow, ...]:
        return self.store.get_slots(
            principal_id=PRINCIPAL,
            vault_id=VAULT,
            scope_ids=tuple(scope_ids),
        )

    def test_provider_satisfies_existing_protocols_and_releases_exact_set(
        self,
    ) -> None:
        self.assertIsInstance(self.provider, ScopeKeyEnrollmentProvider)
        self.assertIsInstance(self.provider, ScopeKeyReleaseProvider)
        self.assertIsInstance(self.store, KeySlotStore)
        self.assertIsInstance(self.old_backend, KeyWrappingBackend)

        self.enroll_both()
        rows = self.rows(SCOPE_A, SCOPE_B)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row.state is KeySlotState.ACTIVE for row in rows))
        self.assertTrue(all(row.wrapped_key is not None for row in rows))
        stored_bytes = b"".join(
            row.wrapped_key.ciphertext
            for row in rows
            if row.wrapped_key is not None
        )
        self.assertNotIn(bytes(self.key_a), stored_bytes)
        self.assertNotIn(bytes(self.key_b), stored_bytes)
        self.assertNotIn(PRINCIPAL, repr(rows[0]))
        self.assertNotIn(VAULT, repr(rows[0]))
        self.assertNotIn(SCOPE_A, repr(rows[0]))

        leased_buffer: bytearray | None = None
        with self.provider.lease_scope_keys(grant(SCOPE_B)) as released:
            self.assertEqual(released.root_key_version, 7)
            self.assertEqual(set(released.scope_keys), {SCOPE_B})
            material = released.scope_keys[SCOPE_B]
            self.assertEqual(material.key_version, 12)
            self.assertEqual(material.dek, self.key_b)
            leased_buffer = material.dek
        assert leased_buffer is not None
        self.assertEqual(leased_buffer, bytearray(32))
        self.assertEqual(self.key_b, bytearray(b"b" * 32))

    def test_enrollment_is_idempotent_across_password_rewrap(self) -> None:
        self.enroll_both(envelope_revision=1)
        before = self.rows(SCOPE_A, SCOPE_B)

        self.enroll_both(envelope_revision=2)

        self.assertEqual(self.rows(SCOPE_A, SCOPE_B), before)
        self.assertEqual(
            [row.enrolled_envelope_revision for row in before],
            [1, 1],
        )
        with self.provider.lease_scope_keys(
            grant(SCOPE_A, SCOPE_B, epoch=2)
        ) as released:
            self.assertEqual(released.scope_keys[SCOPE_A].dek, self.key_a)
            self.assertEqual(released.scope_keys[SCOPE_B].dek, self.key_b)

    def test_enrollment_rejects_changed_key_version_root_or_plaintext(
        self,
    ) -> None:
        self.enroll_both()
        changed = bytearray(b"x" * 32)
        self.addCleanup(
            lambda: changed.__setitem__(slice(None), b"\x00" * len(changed))
        )
        cases = (
            (7, ScopeKeyMaterial(11, changed)),
            (7, ScopeKeyMaterial(99, self.key_a)),
            (8, ScopeKeyMaterial(11, self.key_a)),
        )
        for root_version, material in cases:
            with self.subTest(root_version=root_version, key=material.key_version):
                with self.assertRaises(KeyCustodyConflict):
                    self.provider.enroll_scope_keys(
                        principal_id=PRINCIPAL,
                        vault_id=VAULT,
                        envelope_revision=1,
                        root_key_version=root_version,
                        scope_keys={SCOPE_A: material},
                    )

    def test_concurrent_exact_enrollment_has_one_stable_slot(self) -> None:
        start = threading.Barrier(8)
        errors: list[BaseException] = []

        def worker() -> None:
            try:
                start.wait(timeout=5)
                self.provider.enroll_scope_keys(
                    principal_id=PRINCIPAL,
                    vault_id=VAULT,
                    envelope_revision=1,
                    root_key_version=7,
                    scope_keys={SCOPE_A: ScopeKeyMaterial(11, self.key_a)},
                )
            except BaseException as exc:  # collected for the main test thread
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        (row,) = self.rows(SCOPE_A)
        self.assertEqual(row.slot_version, 1)
        self.assertEqual(row.state, KeySlotState.ACTIVE)

    def test_revocation_creates_ciphertext_free_permanent_tombstones(self) -> None:
        self.enroll_both()
        missing_scope = "scope_never-enrolled"

        self.assertEqual(
            self.provider.revoke_scope_keys(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, missing_scope),
            ),
            2,
        )
        rows = self.rows(SCOPE_A, missing_scope)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row.state is KeySlotState.REVOKED for row in rows))
        self.assertTrue(all(row.wrapped_key is None for row in rows))
        self.assertEqual(
            self.provider.revoke_scope_keys(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, missing_scope),
            ),
            0,
        )
        with self.assertRaises(ScopeGrantDenied):
            with self.provider.lease_scope_keys(grant(SCOPE_A)):
                pass
        with self.assertRaises(KeyCustodyConflict):
            self.provider.enroll_scope_keys(
                principal_id=PRINCIPAL,
                vault_id=VAULT,
                envelope_revision=2,
                root_key_version=7,
                scope_keys={SCOPE_A: ScopeKeyMaterial(11, self.key_a)},
            )

    def test_ciphertext_swap_fails_aad_authentication_and_clears_partial_lease(
        self,
    ) -> None:
        self.enroll_both()
        row_a, row_b = self.rows(SCOPE_A, SCOPE_B)
        assert row_a.wrapped_key is not None
        assert row_b.wrapped_key is not None
        swapped_a = replace(
            row_a,
            slot_version=row_a.slot_version + 1,
            wrapped_key=row_b.wrapped_key,
        )
        swapped_b = replace(
            row_b,
            slot_version=row_b.slot_version + 1,
            wrapped_key=row_a.wrapped_key,
        )
        self.assertTrue(
            self.store.compare_and_swap_slots(
                expected_versions={
                    row_a.identity: row_a.slot_version,
                    row_b.identity: row_b.slot_version,
                },
                replacement_rows=(swapped_a, swapped_b),
            )
        )

        with self.assertRaises(ScopeGrantDenied):
            with self.provider.lease_scope_keys(grant(SCOPE_A, SCOPE_B)):
                pass

    def test_release_rechecks_slot_snapshot_after_backend_unwrap(self) -> None:
        callback_backend = CallbackWrappingBackend(self.old_backend)
        provider = EnvelopeScopeKeyProvider(
            self.store,
            {callback_backend.backend_id: callback_backend},
            active_backend_id=callback_backend.backend_id,
        )
        provider.enroll_scope_keys(
            principal_id=PRINCIPAL,
            vault_id=VAULT,
            envelope_revision=1,
            root_key_version=7,
            scope_keys={SCOPE_A: ScopeKeyMaterial(11, self.key_a)},
        )
        callback_backend.callback = lambda: provider.revoke_scope_keys(
            PRINCIPAL,
            VAULT,
            (SCOPE_A,),
        )

        with self.assertRaises(ScopeGrantDenied):
            with provider.lease_scope_keys(grant(SCOPE_A)):
                pass
        assert callback_backend.last_plaintext is not None
        self.assertEqual(callback_backend.last_plaintext, bytearray(32))

    def test_provider_key_rewrap_is_atomic_versioned_and_idempotent(self) -> None:
        self.enroll_both()
        before = self.rows(SCOPE_A, SCOPE_B)

        self.assertEqual(
            self.provider.rewrap_provider_key(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, SCOPE_B),
                destination_backend_id=self.new_backend.backend_id,
            ),
            2,
        )
        after = self.rows(SCOPE_A, SCOPE_B)
        self.assertEqual(
            [row.slot_version for row in after],
            [row.slot_version + 1 for row in before],
        )
        self.assertTrue(
            all(
                row.wrapped_key is not None
                and row.wrapped_key.backend_id == self.new_backend.backend_id
                for row in after
            )
        )
        self.old_backend.close()
        with self.provider.lease_scope_keys(
            grant(SCOPE_A, SCOPE_B)
        ) as released:
            self.assertEqual(released.scope_keys[SCOPE_A].dek, self.key_a)
            self.assertEqual(released.scope_keys[SCOPE_B].dek, self.key_b)
        self.assertEqual(
            self.provider.rewrap_provider_key(
                PRINCIPAL,
                VAULT,
                (SCOPE_A, SCOPE_B),
                destination_backend_id=self.new_backend.backend_id,
            ),
            0,
        )
        self.assertEqual(self.rows(SCOPE_A, SCOPE_B), after)

    def test_store_compare_and_swap_is_all_or_nothing(self) -> None:
        identity_a = KeySlotIdentity(PRINCIPAL, VAULT, SCOPE_A)
        identity_b = KeySlotIdentity(PRINCIPAL, VAULT, SCOPE_B)
        tombstone_a = KeySlotRow(
            identity=identity_a,
            slot_version=1,
            state=KeySlotState.REVOKED,
            enrolled_envelope_revision=None,
            root_key_version=None,
            scope_key_version=None,
            wrapped_key=None,
        )
        tombstone_b = replace(tombstone_a, identity=identity_b)
        self.assertTrue(
            self.store.compare_and_swap_slots(
                expected_versions={identity_a: None, identity_b: None},
                replacement_rows=(tombstone_a, tombstone_b),
            )
        )
        replacement_a = replace(tombstone_a, slot_version=2)
        replacement_b = replace(tombstone_b, slot_version=2)
        self.assertFalse(
            self.store.compare_and_swap_slots(
                expected_versions={identity_a: 1, identity_b: 2},
                replacement_rows=(replacement_a, replacement_b),
            )
        )
        self.assertEqual(self.rows(SCOPE_A, SCOPE_B), (tombstone_a, tombstone_b))
        with self.assertRaisesRegex(
            ValidationError,
            "must advance its revision",
        ):
            self.store.compare_and_swap_slots(
                expected_versions={identity_a: 1},
                replacement_rows=(
                    replace(
                        tombstone_a,
                        enrolled_envelope_revision=1,
                        root_key_version=7,
                        scope_key_version=11,
                    ),
                ),
            )

    def test_store_snapshots_cannot_mutate_owned_rows_by_reference(self) -> None:
        self.enroll_both()
        (exposed,) = self.rows(SCOPE_A)
        original = self.rows(SCOPE_A)[0]
        object.__setattr__(exposed, "state", KeySlotState.REVOKED)
        object.__setattr__(exposed, "wrapped_key", None)
        object.__setattr__(exposed.identity, "scope_id", "scope_mutated")

        (stored,) = self.rows(SCOPE_A)
        self.assertEqual(stored, original)
        self.assertEqual(stored.state, KeySlotState.ACTIVE)
        self.assertIsNotNone(stored.wrapped_key)

    def test_release_preserves_exception_from_lease_consumer(self) -> None:
        self.enroll_both()
        leased: bytearray | None = None
        with self.assertRaisesRegex(RuntimeError, "caller failure"):
            with self.provider.lease_scope_keys(grant(SCOPE_A)) as released:
                leased = released.scope_keys[SCOPE_A].dek
                raise RuntimeError("caller failure")
        assert leased is not None
        self.assertEqual(leased, bytearray(32))


class AwsKmsBackendTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = FakeAwsKmsClient()
        self.backend = AwsKmsKeyWrappingBackend(
            self.client,
            key_id="alias/authgraph-test",
            backend_id="aws-kms-test-2026",
        )

    def test_injected_client_wraps_with_hashed_context_and_zeroizes_buffers(
        self,
    ) -> None:
        key = bytearray(b"k" * 32)
        aad = b"slot-aad-containing-idp|private-owner-and-vault"

        wrapped = self.backend.wrap_key(key, aad=aad)

        self.assertEqual(wrapped.backend_id, "aws-kms-test-2026")
        self.assertEqual(wrapped.key_id, self.client.canonical_key_id)
        self.assertEqual(wrapped.algorithm, AWS_KMS_ALGORITHM)
        self.assertEqual(key, bytearray(b"k" * 32))
        assert self.client.encrypt_plaintext_reference is not None
        self.assertEqual(self.client.encrypt_plaintext_reference, bytearray(32))
        call = self.client.encrypt_calls[0]
        context = call["EncryptionContext"]
        self.assertIsInstance(context, dict)
        assert isinstance(context, dict)
        self.assertEqual(context["authgraph-purpose"], AWS_KMS_PURPOSE)
        self.assertNotIn("private-owner", repr(context))
        self.assertNotIn("vault", repr(context))
        self.assertEqual(call["EncryptionAlgorithm"], AWS_KMS_ALGORITHM)

        leased: bytearray | None = None
        with self.backend.unwrap_key(wrapped, aad=aad) as plaintext:
            self.assertEqual(plaintext, key)
            leased = plaintext
            assert self.client.decrypt_plaintext_reference is not None
            self.assertEqual(
                self.client.decrypt_plaintext_reference,
                bytearray(32),
            )
        assert leased is not None
        self.assertEqual(leased, bytearray(32))

    def test_wrong_aad_and_provider_errors_are_generic(self) -> None:
        wrapped = self.backend.wrap_key(b"z" * 32, aad=b"correct-aad")
        with self.assertRaises(KeyCustodyUnavailable) as caught:
            with self.backend.unwrap_key(wrapped, aad=b"wrong-aad"):
                pass
        self.assertNotIn("provider detail", str(caught.exception))

        class FailingClient:
            def encrypt(self, **kwargs: object) -> object:
                raise RuntimeError("secret infrastructure identifier")

            def decrypt(self, **kwargs: object) -> object:
                raise RuntimeError("secret infrastructure identifier")

        failing = AwsKmsKeyWrappingBackend(
            FailingClient(),
            key_id="alias/failing",
        )
        with self.assertRaises(KeyCustodyUnavailable) as failed:
            failing.wrap_key(b"z" * 32, aad=b"valid-aad")
        self.assertNotIn("infrastructure", str(failed.exception))

    def test_aws_backend_integrates_with_envelope_provider(self) -> None:
        store = InMemoryKeySlotStore()
        provider = EnvelopeScopeKeyProvider(
            store,
            {self.backend.backend_id: self.backend},
            active_backend_id=self.backend.backend_id,
        )
        key = bytearray(b"w" * 32)
        try:
            provider.enroll_scope_keys(
                principal_id=PRINCIPAL,
                vault_id=VAULT,
                envelope_revision=1,
                root_key_version=4,
                scope_keys={SCOPE_A: ScopeKeyMaterial(9, key)},
            )
            with provider.lease_scope_keys(grant(SCOPE_A)) as released:
                self.assertEqual(released.root_key_version, 4)
                self.assertEqual(released.scope_keys[SCOPE_A].key_version, 9)
                self.assertEqual(released.scope_keys[SCOPE_A].dek, key)
        finally:
            key[:] = b"\x00" * len(key)


if __name__ == "__main__":
    unittest.main()
