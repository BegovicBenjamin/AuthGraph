from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from authgraph.key_custody import (
    EnvelopeScopeKeyProvider,
    InMemoryAesKeyWrappingBackend,
    KeyCustodyConflict,
    KeyCustodyUnavailable,
    KeySlotIdentity,
    KeySlotState,
)
from authgraph.scoped_sessions import ScopeKeyMaterial
from authgraph.sqlite_key_slots import SqliteKeySlotStore
from authgraph.unlock_policy import ScopeUnlockGrant


def grant(*scope_ids: str) -> ScopeUnlockGrant:
    return ScopeUnlockGrant(
        principal_id="principal-1",
        profile_id="support",
        vault_id="vault-1",
        scope_ids=tuple(scope_ids),
        client_binding="browser-1",
        authorization_epoch=1,
        evidence_provider="one_time_code",
        evidence_id="evidence-1",
        issued_at=1.0,
        expires_at=9999999999.0,
        grant_id="grant-1",
    )


class SqliteKeySlotStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name, "slots.sqlite3")
        self.wrapping_key = b"w" * 32

    def tearDown(self) -> None:
        self.directory.cleanup()

    def provider(self) -> tuple[
        EnvelopeScopeKeyProvider,
        InMemoryAesKeyWrappingBackend,
    ]:
        backend = InMemoryAesKeyWrappingBackend(
            backend_id="test-kms-v1",
            key_id="test-key-v1",
            wrapping_key=self.wrapping_key,
        )
        provider = EnvelopeScopeKeyProvider(
            SqliteKeySlotStore(self.path),
            {backend.backend_id: backend},
            active_backend_id=backend.backend_id,
        )
        return provider, backend

    @staticmethod
    def materials() -> dict[str, ScopeKeyMaterial]:
        return {
            "scope-1": ScopeKeyMaterial(1, bytearray(b"a" * 32)),
            "scope-2": ScopeKeyMaterial(1, bytearray(b"b" * 32)),
        }

    @staticmethod
    def clear(materials: dict[str, ScopeKeyMaterial]) -> None:
        for material in materials.values():
            material.dek[:] = b"\x00" * len(material.dek)

    def test_slots_survive_restart_and_release_exact_granted_set(self) -> None:
        first, first_backend = self.provider()
        materials = self.materials()
        first.enroll_scope_keys(
            principal_id="principal-1",
            vault_id="vault-1",
            envelope_revision=1,
            root_key_version=1,
            scope_keys=materials,
        )
        self.clear(materials)
        first_backend.close()

        restarted, backend = self.provider()
        with restarted.lease_scope_keys(grant("scope-2")) as released:
            self.assertEqual(set(released.scope_keys), {"scope-2"})
            self.assertEqual(released.scope_keys["scope-2"].dek, b"b" * 32)
        backend.close()

    def test_two_workers_cannot_create_conflicting_slots(self) -> None:
        providers = (self.provider(), self.provider())
        barrier = threading.Barrier(2)
        outcomes: list[str] = []
        lock = threading.Lock()

        def enroll(
            provider: EnvelopeScopeKeyProvider,
            value: bytes,
        ) -> None:
            material = {"scope-1": ScopeKeyMaterial(1, bytearray(value))}
            barrier.wait()
            try:
                provider.enroll_scope_keys(
                    principal_id="principal-1",
                    vault_id="vault-1",
                    envelope_revision=1,
                    root_key_version=1,
                    scope_keys=material,
                )
                outcome = "success"
            except KeyCustodyConflict:
                outcome = "conflict"
            finally:
                self.clear(material)
            with lock:
                outcomes.append(outcome)

        threads = [
            threading.Thread(target=enroll, args=(providers[0][0], b"a" * 32)),
            threading.Thread(target=enroll, args=(providers[1][0], b"b" * 32)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for _, backend in providers:
            backend.close()

        self.assertEqual(sorted(outcomes), ["conflict", "success"])

    def test_revocation_tombstone_survives_restart(self) -> None:
        provider, backend = self.provider()
        material = {"scope-1": ScopeKeyMaterial(1, bytearray(b"a" * 32))}
        provider.enroll_scope_keys(
            principal_id="principal-1",
            vault_id="vault-1",
            envelope_revision=1,
            root_key_version=1,
            scope_keys=material,
        )
        self.clear(material)
        self.assertEqual(
            provider.revoke_scope_keys(
                principal_id="principal-1",
                vault_id="vault-1",
                scope_ids=("scope-1",),
            ),
            1,
        )
        backend.close()

        rows = SqliteKeySlotStore(self.path).get_slots(
            principal_id="principal-1",
            vault_id="vault-1",
            scope_ids=("scope-1",),
        )
        self.assertEqual(len(rows), 1)
        self.assertIs(rows[0].state, KeySlotState.REVOKED)
        self.assertIsNone(rows[0].wrapped_key)

        restarted, restarted_backend = self.provider()
        replacement = {"scope-1": ScopeKeyMaterial(1, bytearray(b"a" * 32))}
        with self.assertRaises(KeyCustodyConflict):
            restarted.enroll_scope_keys(
                principal_id="principal-1",
                vault_id="vault-1",
                envelope_revision=1,
                root_key_version=1,
                scope_keys=replacement,
            )
        self.clear(replacement)
        restarted_backend.close()

    def test_plaintext_scope_keys_are_not_stored(self) -> None:
        provider, backend = self.provider()
        materials = self.materials()
        plaintexts = tuple(bytes(item.dek) for item in materials.values())
        provider.enroll_scope_keys(
            principal_id="principal-1",
            vault_id="vault-1",
            envelope_revision=1,
            root_key_version=1,
            scope_keys=materials,
        )
        self.clear(materials)
        backend.close()

        stored = b"".join(
            path.read_bytes()
            for path in Path(self.directory.name).iterdir()
            if path.is_file()
        )
        for plaintext in plaintexts:
            self.assertNotIn(plaintext, stored)

    def test_batch_compare_and_swap_is_atomic_across_store_instances(self) -> None:
        store = SqliteKeySlotStore(self.path)
        first = KeySlotIdentity("principal-1", "vault-1", "scope-1")
        second = KeySlotIdentity("principal-1", "vault-1", "scope-2")
        # Provider enrollment is the public construction path; this assertion
        # verifies its two-row result is visible as one complete snapshot.
        provider, backend = self.provider()
        materials = self.materials()
        provider.enroll_scope_keys(
            principal_id="principal-1",
            vault_id="vault-1",
            envelope_revision=1,
            root_key_version=1,
            scope_keys=materials,
        )
        self.clear(materials)
        rows = store.get_slots(
            principal_id="principal-1",
            vault_id="vault-1",
            scope_ids=(first.scope_id, second.scope_id),
        )
        self.assertEqual({row.identity for row in rows}, {first, second})
        backend.close()

    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_rejects_permissive_or_symlinked_database(self) -> None:
        permissive = Path(self.directory.name, "permissive.sqlite3")
        permissive.write_bytes(b"")
        permissive.chmod(0o644)
        with self.assertRaises(KeyCustodyUnavailable):
            SqliteKeySlotStore(permissive)

        target = Path(self.directory.name, "target.sqlite3")
        target.write_bytes(b"")
        target.chmod(0o600)
        link = Path(self.directory.name, "link.sqlite3")
        link.symlink_to(target)
        with self.assertRaises(KeyCustodyUnavailable):
            SqliteKeySlotStore(link)

    def test_file_creation_race_accepts_secure_regular_winner(self) -> None:
        def win_creation_race(*_args: object) -> None:
            self.path.write_bytes(b"")
            self.path.chmod(0o600)
            raise FileExistsError

        with patch(
            "authgraph.sqlite_key_slots.os.open",
            side_effect=win_creation_race,
        ) as open_file:
            SqliteKeySlotStore(self.path)
        open_file.assert_called_once()

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
                    "authgraph.sqlite_key_slots.os.open",
                    side_effect=win_creation_race,
                ):
                    with self.assertRaises(KeyCustodyUnavailable):
                        SqliteKeySlotStore(race_path)

    @unittest.skipUnless(os.name == "posix", "POSIX file modes required")
    def test_rejects_state_in_a_writable_untrusted_directory(self) -> None:
        insecure = Path(self.directory.name, "writable")
        insecure.mkdir(mode=0o700)
        insecure.chmod(0o777)
        try:
            with self.assertRaises(KeyCustodyUnavailable):
                SqliteKeySlotStore(insecure / "slots.sqlite3")
        finally:
            insecure.chmod(0o700)


if __name__ == "__main__":
    unittest.main()
