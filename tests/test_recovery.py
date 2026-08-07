from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from authgraph.key_custody import (
    EnvelopeScopeKeyProvider,
    InMemoryAesKeyWrappingBackend,
    KeyCustodyConflict,
    KeyCustodyUnavailable,
    RecoveryRewrapResult,
    WrappedKeyBlob,
)
from authgraph.recovery import MirroredKeyWrappingBackend
from authgraph.scoped_sessions import ScopeKeyMaterial
from authgraph.sqlite_key_slots import SqliteKeySlotStore
from authgraph.unlock_policy import ScopeGrantDenied, ScopeUnlockGrant


def backend(backend_id: str, value: bytes) -> InMemoryAesKeyWrappingBackend:
    return InMemoryAesKeyWrappingBackend(
        backend_id=backend_id,
        key_id=f"{backend_id}-key",
        wrapping_key=value,
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
    def unwrap_key(self, wrapped_key: WrappedKeyBlob, *, aad: bytes):
        self.unwrap_calls += 1
        with self.delegate.unwrap_key(wrapped_key, aad=aad) as plaintext:
            yield plaintext


def grant() -> ScopeUnlockGrant:
    return ScopeUnlockGrant(
        principal_id="principal-1",
        profile_id="support",
        vault_id="vault-1",
        scope_ids=("scope-1",),
        client_binding="browser-1",
        authorization_epoch=1,
        evidence_provider="one_time_code",
        evidence_id="evidence-1",
        issued_at=1.0,
        expires_at=9999999999.0,
        grant_id="grant-1",
    )


class RecoveryWrappingTests(unittest.TestCase):
    def test_ordinary_unwrap_is_primary_only_and_recovery_is_explicit(self) -> None:
        primary = backend("primary-v1", b"p" * 32)
        recovery_delegate = backend("recovery-v1", b"r" * 32)
        recovery = CountingBackend(recovery_delegate)
        mirrored = MirroredKeyWrappingBackend(
            primary,
            recovery,
            backend_id="mirror-v1",
        )
        plaintext = bytearray(b"d" * 32)
        wrapped = mirrored.wrap_key(plaintext, aad=b"bound-aad")
        plaintext[:] = b"\x00" * len(plaintext)
        primary.close()

        with self.assertRaises(KeyCustodyUnavailable):
            with mirrored.unwrap_key(wrapped, aad=b"bound-aad"):
                pass
        self.assertEqual(recovery.unwrap_calls, 0)

        with mirrored.unwrap_key_for_recovery(
            wrapped,
            aad=b"bound-aad",
        ) as recovered:
            self.assertEqual(recovered.dek, b"d" * 32)
            self.assertEqual(recovered.provenance.backend_id, "recovery-v1")
        self.assertEqual(recovery.unwrap_calls, 1)
        recovery_delegate.close()

    def test_primary_and_recovery_paths_do_not_cross_invoke(self) -> None:
        primary = backend("primary-v1", b"p" * 32)
        recovery_delegate = backend("recovery-v1", b"r" * 32)

        class WrongRecoveryBackend:
            backend_id = "wrong-recovery"

            def wrap_key(self, plaintext: object, *, aad: bytes) -> WrappedKeyBlob:
                wrapped = recovery_delegate.wrap_key(b"z" * 32, aad=aad)
                return WrappedKeyBlob(
                    backend_id=self.backend_id,
                    key_id=wrapped.key_id,
                    algorithm=wrapped.algorithm,
                    ciphertext=wrapped.ciphertext,
                )

            @contextmanager
            def unwrap_key(self, wrapped_key: WrappedKeyBlob, *, aad: bytes):
                rewritten = WrappedKeyBlob(
                    backend_id=recovery_delegate.backend_id,
                    key_id=wrapped_key.key_id,
                    algorithm=wrapped_key.algorithm,
                    ciphertext=wrapped_key.ciphertext,
                )
                with recovery_delegate.unwrap_key(rewritten, aad=aad) as value:
                    yield value

        wrong = WrongRecoveryBackend()
        mirrored = MirroredKeyWrappingBackend(
            primary,
            wrong,
            backend_id="mirror-v1",
        )
        wrapped = mirrored.wrap_key(b"d" * 32, aad=b"bound-aad")

        with mirrored.unwrap_key(wrapped, aad=b"bound-aad") as plaintext:
            self.assertEqual(plaintext, b"d" * 32)
        with mirrored.unwrap_key_for_recovery(
            wrapped,
            aad=b"bound-aad",
        ) as recovered:
            self.assertEqual(recovered.dek, b"z" * 32)
        primary.close()
        recovery_delegate.close()

    def test_recovery_can_rewrap_slots_to_fresh_primary_generation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SqliteKeySlotStore(Path(directory, "slots.sqlite3"))
            old_primary = backend("primary-v1", b"p" * 32)
            old_recovery_delegate = backend("recovery-v1", b"r" * 32)
            old_recovery = CountingBackend(old_recovery_delegate)
            old_mirror = MirroredKeyWrappingBackend(
                old_primary,
                old_recovery,
                backend_id="mirror-v1",
            )
            new_primary = backend("primary-v2", b"q" * 32)
            new_recovery = backend("recovery-v2", b"s" * 32)
            new_mirror = MirroredKeyWrappingBackend(
                new_primary,
                new_recovery,
                backend_id="mirror-v2",
            )
            provider = EnvelopeScopeKeyProvider(
                store,
                {
                    old_mirror.backend_id: old_mirror,
                    new_mirror.backend_id: new_mirror,
                },
                active_backend_id=old_mirror.backend_id,
            )
            material = {
                "scope-1": ScopeKeyMaterial(1, bytearray(b"d" * 32))
            }
            provider.enroll_scope_keys(
                principal_id="principal-1",
                vault_id="vault-1",
                envelope_revision=1,
                root_key_version=1,
                scope_keys=material,
            )
            material["scope-1"].dek[:] = b"\x00" * 32

            old_primary.close()
            with self.assertRaises(KeyCustodyConflict):
                provider.recover_provider_key(
                    "principal-1",
                    "vault-1",
                    ("scope-1",),
                    destination_backend_id=old_mirror.backend_id,
                )
            self.assertEqual(old_recovery.unwrap_calls, 0)
            with self.assertRaises(ScopeGrantDenied):
                with provider.lease_scope_keys(grant()):
                    pass
            self.assertEqual(old_recovery.unwrap_calls, 0)
            with self.assertRaises(KeyCustodyUnavailable):
                provider.rewrap_provider_key(
                    "principal-1",
                    "vault-1",
                    ("scope-1",),
                    destination_backend_id=new_mirror.backend_id,
                )
            self.assertEqual(old_recovery.unwrap_calls, 0)

            result = provider.recover_provider_key(
                "principal-1",
                "vault-1",
                ("scope-1",),
                destination_backend_id=new_mirror.backend_id,
            )
            self.assertIsInstance(result, RecoveryRewrapResult)
            self.assertEqual(result.changed_count, 1)
            self.assertEqual(result.sources[0].backend_id, "recovery-v1")
            self.assertEqual(old_recovery.unwrap_calls, 1)
            old_recovery_delegate.close()
            with provider.lease_scope_keys(grant()) as released:
                self.assertEqual(released.scope_keys["scope-1"].dek, b"d" * 32)
            new_primary.close()
            new_recovery.close()


if __name__ == "__main__":
    unittest.main()
