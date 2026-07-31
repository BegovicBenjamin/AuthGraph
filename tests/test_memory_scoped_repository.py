from __future__ import annotations

import unittest
from dataclasses import replace

from authgraph.errors import IntegrityViolation
from authgraph.memory_repository import InMemoryGraphRepository
from authgraph.models import (
    EncryptedEntityRow,
    EncryptedPayload,
    KdfParameters,
    KeyEnvelope,
    ProtectionScopeRow,
    ScopeKeyEnvelope,
    ScopedEncryptedEntityRow,
    ScopedEncryptedRelationshipRow,
    VaultRow,
)


def vault_envelope(
    *,
    version: int,
    revision: int = 1,
    key_version: int = 1,
) -> KeyEnvelope:
    return KeyEnvelope(
        version=version,
        envelope_revision=revision,
        key_version=key_version,
        wrapping_algorithm="AES-256-GCM",
        kdf=KdfParameters(),
        salt=b"s" * 16,
        nonce=b"n" * 12,
        wrapped_dek=b"w" * 48,
    )


def scope_row(
    vault_id: str,
    scope_id: str,
    *,
    root_key_version: int = 1,
    scope_key_version: int = 1,
) -> ProtectionScopeRow:
    return ProtectionScopeRow(
        vault_id=vault_id,
        scope_id=scope_id,
        envelope=ScopeKeyEnvelope(
            version=1,
            root_key_version=root_key_version,
            scope_key_version=scope_key_version,
            algorithm="AES-256-GCM",
            nonce=b"q" * 12,
            wrapped_scope_dek=b"k" * 48,
        ),
    )


def scoped_payload(
    *,
    version: int = 2,
    key_version: int = 1,
    nonce: bytes = b"p" * 12,
) -> EncryptedPayload:
    return EncryptedPayload(
        version=version,
        key_version=key_version,
        algorithm="AES-256-GCM",
        nonce=nonce,
        ciphertext=b"c" * 32,
    )


class InMemoryScopedRepositoryConsistencyTests(unittest.TestCase):
    PRINCIPAL = "idp_subject_memory"
    OTHER_PRINCIPAL = "idp_subject_memory_other"
    VAULT = "v2_memory_vault"
    OTHER_VAULT = "v2_memory_vault_other"
    SCOPE = "scope_orders"

    def setUp(self) -> None:
        self.repository = InMemoryGraphRepository()

    def create_vault(
        self,
        *,
        principal_id: str = PRINCIPAL,
        vault_id: str = VAULT,
        version: int = 2,
    ) -> None:
        self.assertTrue(
            self.repository.create_vault(
                VaultRow(
                    principal_id=principal_id,
                    vault_id=vault_id,
                    envelope=vault_envelope(version=version),
                )
            )
        )

    def put_scope(
        self,
        *,
        principal_id: str = PRINCIPAL,
        vault_id: str = VAULT,
        scope_id: str = SCOPE,
        revision: int = 1,
    ) -> ProtectionScopeRow:
        row = scope_row(vault_id, scope_id)
        self.assertTrue(
            self.repository.put_protection_scope(
                principal_id,
                vault_id,
                revision,
                row,
            )
        )
        return row

    def test_scoped_operations_require_v2_without_breaking_v1(self) -> None:
        self.create_vault(version=1)
        self.assertFalse(
            self.repository.put_protection_scope(
                self.PRINCIPAL,
                self.VAULT,
                1,
                scope_row(self.VAULT, self.SCOPE),
            )
        )
        self.assertIsNone(
            self.repository.get_protection_scopes(
                self.PRINCIPAL,
                self.VAULT,
                1,
                (self.SCOPE,),
            )
        )

        legacy_row = EncryptedEntityRow(
            vault_id=self.VAULT,
            entity_id="legacy_entity",
            payload=scoped_payload(version=1),
        )
        self.assertTrue(
            self.repository.put_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                legacy_row,
            )
        )
        self.assertEqual(
            self.repository.get_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                legacy_row.entity_id,
            ),
            legacy_row,
        )
        self.assertTrue(
            self.repository.replace_envelope(
                self.PRINCIPAL,
                self.VAULT,
                1,
                vault_envelope(version=1, revision=2),
            )
        )

    def test_v2_rewrap_must_preserve_root_key_version(self) -> None:
        self.create_vault()
        self.assertFalse(
            self.repository.replace_envelope(
                self.PRINCIPAL,
                self.VAULT,
                1,
                vault_envelope(
                    version=2,
                    revision=2,
                    key_version=2,
                ),
            )
        )
        current = self.repository.get_vault(
            self.PRINCIPAL,
            self.VAULT,
        )
        self.assertIsNotNone(current)
        assert current is not None
        self.assertEqual(
            current.envelope.key_version,
            1,
        )
        self.assertTrue(
            self.repository.replace_envelope(
                self.PRINCIPAL,
                self.VAULT,
                1,
                vault_envelope(version=2, revision=2),
            )
        )
        self.assertTrue(
            self.repository.put_protection_scope(
                self.PRINCIPAL,
                self.VAULT,
                2,
                scope_row(self.VAULT, self.SCOPE),
            )
        )

    def test_scoped_writes_validate_root_and_payload_key_versions(self) -> None:
        self.create_vault()
        self.assertFalse(
            self.repository.put_protection_scope(
                self.PRINCIPAL,
                self.VAULT,
                1,
                scope_row(
                    self.VAULT,
                    "scope_wrong_root",
                    root_key_version=2,
                ),
            )
        )
        malformed_scope = replace(
            scope_row(self.VAULT, "scope_bad_envelope"),
            envelope=replace(
                scope_row(
                    self.VAULT,
                    "scope_bad_envelope",
                ).envelope,
                nonce=b"short",
            ),
        )
        self.assertFalse(
            self.repository.put_protection_scope(
                self.PRINCIPAL,
                self.VAULT,
                1,
                malformed_scope,
            )
        )
        self.put_scope()

        wrong_key_entity = ScopedEncryptedEntityRow(
            vault_id=self.VAULT,
            scope_id=self.SCOPE,
            entity_id="scoped_wrong_key",
            payload=scoped_payload(key_version=2),
        )
        legacy_payload_entity = replace(
            wrong_key_entity,
            entity_id="scoped_wrong_version",
            payload=scoped_payload(version=1),
        )
        self.assertFalse(
            self.repository.put_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                wrong_key_entity,
            )
        )
        self.assertFalse(
            self.repository.put_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                legacy_payload_entity,
            )
        )

        source = replace(
            wrong_key_entity,
            entity_id="scoped_source",
            payload=scoped_payload(),
        )
        target = replace(source, entity_id="scoped_target")
        for row in (source, target):
            self.assertTrue(
                self.repository.put_scoped_entity(
                    self.PRINCIPAL,
                    self.VAULT,
                    1,
                    row,
                )
            )
        relationship = ScopedEncryptedRelationshipRow(
            vault_id=self.VAULT,
            scope_id=self.SCOPE,
            relationship_id="scoped_link",
            from_entity_id=source.entity_id,
            to_entity_id=target.entity_id,
            payload=scoped_payload(key_version=2),
        )
        self.assertFalse(
            self.repository.put_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                1,
                (self.SCOPE,),
                relationship,
            )
        )
        self.assertTrue(
            self.repository.put_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                1,
                (self.SCOPE,),
                replace(relationship, payload=scoped_payload()),
            )
        )

    def test_scoped_ids_are_globally_unique_like_neo4j(self) -> None:
        self.create_vault()
        self.create_vault(
            principal_id=self.OTHER_PRINCIPAL,
            vault_id=self.OTHER_VAULT,
        )
        self.put_scope()
        self.assertFalse(
            self.repository.put_protection_scope(
                self.OTHER_PRINCIPAL,
                self.OTHER_VAULT,
                1,
                scope_row(self.OTHER_VAULT, self.SCOPE),
            )
        )

        other_scope = "scope_other"
        self.put_scope(
            principal_id=self.OTHER_PRINCIPAL,
            vault_id=self.OTHER_VAULT,
            scope_id=other_scope,
        )
        first = ScopedEncryptedEntityRow(
            vault_id=self.VAULT,
            scope_id=self.SCOPE,
            entity_id="globally_unique_entity",
            payload=scoped_payload(),
        )
        second = replace(
            first,
            vault_id=self.OTHER_VAULT,
            scope_id=other_scope,
        )
        self.assertTrue(
            self.repository.put_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                first,
            )
        )
        self.assertFalse(
            self.repository.put_scoped_entity(
                self.OTHER_PRINCIPAL,
                self.OTHER_VAULT,
                1,
                second,
            )
        )

        endpoint_rows = (
            (
                self.PRINCIPAL,
                self.VAULT,
                ScopedEncryptedEntityRow(
                    vault_id=self.VAULT,
                    scope_id=self.SCOPE,
                    entity_id="first_source",
                    payload=scoped_payload(),
                ),
            ),
            (
                self.PRINCIPAL,
                self.VAULT,
                ScopedEncryptedEntityRow(
                    vault_id=self.VAULT,
                    scope_id=self.SCOPE,
                    entity_id="first_target",
                    payload=scoped_payload(),
                ),
            ),
            (
                self.OTHER_PRINCIPAL,
                self.OTHER_VAULT,
                ScopedEncryptedEntityRow(
                    vault_id=self.OTHER_VAULT,
                    scope_id=other_scope,
                    entity_id="second_source",
                    payload=scoped_payload(),
                ),
            ),
            (
                self.OTHER_PRINCIPAL,
                self.OTHER_VAULT,
                ScopedEncryptedEntityRow(
                    vault_id=self.OTHER_VAULT,
                    scope_id=other_scope,
                    entity_id="second_target",
                    payload=scoped_payload(),
                ),
            ),
        )
        for principal_id, vault_id, row in endpoint_rows:
            self.assertTrue(
                self.repository.put_scoped_entity(
                    principal_id,
                    vault_id,
                    1,
                    row,
                )
            )

        first_relationship = ScopedEncryptedRelationshipRow(
            vault_id=self.VAULT,
            scope_id=self.SCOPE,
            relationship_id="globally_unique_relationship",
            from_entity_id="first_source",
            to_entity_id="first_target",
            payload=scoped_payload(),
        )
        second_relationship = replace(
            first_relationship,
            vault_id=self.OTHER_VAULT,
            scope_id=other_scope,
            from_entity_id="second_source",
            to_entity_id="second_target",
        )
        self.assertTrue(
            self.repository.put_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                1,
                (self.SCOPE,),
                first_relationship,
            )
        )
        self.assertFalse(
            self.repository.put_scoped_relationship(
                self.OTHER_PRINCIPAL,
                self.OTHER_VAULT,
                1,
                (other_scope,),
                second_relationship,
            )
        )

    def test_visible_malformed_scoped_payload_fails_closed(self) -> None:
        self.create_vault()
        self.put_scope()
        row = ScopedEncryptedEntityRow(
            vault_id=self.VAULT,
            scope_id=self.SCOPE,
            entity_id="scoped_entity",
            payload=scoped_payload(),
        )
        self.assertTrue(
            self.repository.put_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                row,
            )
        )
        self.repository._scoped_entities[
            (self.VAULT, row.entity_id)
        ] = replace(
            row,
            payload=replace(row.payload, key_version=2),
        )

        with self.assertRaises(IntegrityViolation):
            self.repository.get_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                (self.SCOPE,),
                row.entity_id,
            )
        with self.assertRaises(IntegrityViolation):
            self.repository.get_scoped_vault_snapshot(
                self.PRINCIPAL,
                self.VAULT,
                1,
                (self.SCOPE,),
                entity_limit=10,
                relationship_limit=10,
            )


if __name__ == "__main__":
    unittest.main()
