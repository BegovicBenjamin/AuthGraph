"""Ciphertext-only Neo4j adapter for AuthGraph v2 protection scopes.

The adapter uses separate labels and relationship types from the legacy
single-key records.  Every scoped operation is a fixed, parameterized query
rooted at one owned ``AGVault``.  Scope grants are opaque identifiers supplied
by the trusted server-side session, never semantic names or model arguments.
"""

from __future__ import annotations

import unicodedata
from typing import Any

from .errors import IntegrityViolation
from .models import (
    EncryptedPayload,
    KeyEnvelope,
    ProtectionScopeRow,
    ScopeKeyEnvelope,
    ScopedEncryptedEntityRow,
    ScopedEncryptedRelationshipRow,
    ScopedEncryptedVaultSnapshotRow,
    VaultRow,
)
from .neo4j_repository import IncompleteCommit, Neo4jGraphRepository
from .scoped_crypto import (
    SCOPE_DEK_CIPHERTEXT_BYTES,
    SCOPE_ENVELOPE_VERSION,
    SCOPE_WRAPPING_ALGORITHM,
)
from .scoped_service import SCOPED_PAYLOAD_VERSION
from .scoped_sessions import MAX_SCOPES_PER_SESSION


MAX_OPAQUE_ID_CHARS = 256
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
SCOPED_PAYLOAD_ALGORITHM = "AES-256-GCM"


class Neo4jScopedGraphRepository(Neo4jGraphRepository):
    """Neo4j implementation of the v2 scoped repository operations."""

    # V2 and V1 deliberately share the AGVault envelope shape.  These
    # overrides make the format distinction explicit at the storage boundary.
    _CREATE_VAULT = """
    OPTIONAL MATCH (existing:AGVault {vault_id: $vault_id})
    WITH existing
    WHERE existing IS NULL AND $envelope_version = 2
    CREATE (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: $envelope_version,
        envelope_revision: $envelope_revision,
        key_version: $key_version,
        wrapping_algorithm: $wrapping_algorithm,
        kdf_algorithm: $kdf_algorithm,
        kdf_memory_cost_kib: $kdf_memory_cost_kib,
        kdf_iterations: $kdf_iterations,
        kdf_lanes: $kdf_lanes,
        kdf_output_length: $kdf_output_length,
        envelope_salt: $envelope_salt,
        envelope_nonce: $envelope_nonce,
        wrapped_dek: $wrapped_dek
    })
    RETURN count(vault) AS created
    """

    _GET_VAULT = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: 2
    })
    RETURN
        vault.envelope_version AS envelope_version,
        vault.envelope_revision AS envelope_revision,
        vault.key_version AS key_version,
        vault.wrapping_algorithm AS wrapping_algorithm,
        vault.kdf_algorithm AS kdf_algorithm,
        vault.kdf_memory_cost_kib AS kdf_memory_cost_kib,
        vault.kdf_iterations AS kdf_iterations,
        vault.kdf_lanes AS kdf_lanes,
        vault.kdf_output_length AS kdf_output_length,
        vault.envelope_salt AS envelope_salt,
        vault.envelope_nonce AS envelope_nonce,
        vault.wrapped_dek AS wrapped_dek
    LIMIT 1
    """

    _REPLACE_ENVELOPE = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: 2
    })
    SET vault._authgraph_lock = true
    REMOVE vault._authgraph_lock
    WITH vault
    WHERE
        vault.envelope_revision = $expected_revision
        AND $envelope_version = 2
        AND vault.key_version = $key_version
    SET
        vault.envelope_version = $envelope_version,
        vault.envelope_revision = $envelope_revision,
        vault.key_version = $key_version,
        vault.wrapping_algorithm = $wrapping_algorithm,
        vault.kdf_algorithm = $kdf_algorithm,
        vault.kdf_memory_cost_kib = $kdf_memory_cost_kib,
        vault.kdf_iterations = $kdf_iterations,
        vault.kdf_lanes = $kdf_lanes,
        vault.kdf_output_length = $kdf_output_length,
        vault.envelope_salt = $envelope_salt,
        vault.envelope_nonce = $envelope_nonce,
        vault.wrapped_dek = $wrapped_dek
    RETURN count(vault) AS updated
    """

    _PUT_PROTECTION_SCOPE = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: 2
    })
    SET vault._authgraph_lock = true
    REMOVE vault._authgraph_lock
    WITH vault
    WHERE
        vault.envelope_revision = $envelope_revision
        AND vault.key_version = $root_key_version
        AND NOT EXISTS {
            MATCH (:AGProtectionScope {scope_id: $scope_id})
        }
    CREATE (scope:AGProtectionScope {
        vault_id: $vault_id,
        scope_id: $scope_id,
        scope_envelope_version: $scope_envelope_version,
        root_key_version: $root_key_version,
        scope_key_version: $scope_key_version,
        wrapping_algorithm: $scope_wrapping_algorithm,
        envelope_nonce: $scope_envelope_nonce,
        wrapped_scope_dek: $wrapped_scope_dek
    })
    CREATE (vault)-[:AG_HAS_SCOPE]->(scope)
    RETURN count(scope) AS created
    """

    _GET_PROTECTION_SCOPES = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: 2,
        envelope_revision: $envelope_revision
    })
    RETURN COLLECT {
        MATCH (vault)-[:AG_HAS_SCOPE]->(scope:AGProtectionScope {
            vault_id: $vault_id
        })
        WHERE
            scope.scope_id IN $scope_ids
            AND scope.root_key_version = vault.key_version
        WITH scope
        ORDER BY scope.scope_id
        RETURN {
            vault_id: scope.vault_id,
            scope_id: scope.scope_id,
            scope_envelope_version: scope.scope_envelope_version,
            root_key_version: scope.root_key_version,
            scope_key_version: scope.scope_key_version,
            scope_wrapping_algorithm: scope.wrapping_algorithm,
            scope_envelope_nonce: scope.envelope_nonce,
            wrapped_scope_dek: scope.wrapped_scope_dek
        } AS scope_row
    } AS scopes
    """

    _PUT_SCOPED_ENTITY = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: 2
    })
    SET vault._authgraph_lock = true
    REMOVE vault._authgraph_lock
    WITH vault
    WHERE vault.envelope_revision = $envelope_revision
    MATCH (vault)-[:AG_HAS_SCOPE]->(scope:AGProtectionScope {
        vault_id: $vault_id,
        scope_id: $scope_id
    })
    WHERE
        scope.scope_key_version = $key_version
        AND scope.root_key_version = vault.key_version
        AND NOT EXISTS {
            MATCH (:AGScopedEntity {entity_id: $entity_id})
        }
    CREATE (entity:AGScopedEntity {
        vault_id: $vault_id,
        scope_id: $scope_id,
        entity_id: $entity_id,
        payload_version: $payload_version,
        key_version: $key_version,
        algorithm: $algorithm,
        nonce: $nonce,
        ciphertext: $ciphertext
    })
    CREATE (scope)-[:AG_PROTECTS]->(entity)
    RETURN count(entity) AS created
    """

    _GET_SCOPED_ENTITY = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: 2,
        envelope_revision: $envelope_revision
    })-[:AG_HAS_SCOPE]->(scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(entity:AGScopedEntity {
        vault_id: $vault_id,
        entity_id: $entity_id
    })
    WHERE
        scope.scope_id IN $allowed_scope_ids
        AND scope.root_key_version = vault.key_version
        AND entity.scope_id = scope.scope_id
    RETURN
        entity.vault_id AS vault_id,
        entity.scope_id AS scope_id,
        entity.entity_id AS entity_id,
        scope.scope_key_version AS protection_scope_key_version,
        entity.payload_version AS payload_version,
        entity.key_version AS key_version,
        entity.algorithm AS algorithm,
        entity.nonce AS nonce,
        entity.ciphertext AS ciphertext
    LIMIT 1
    """

    _PUT_SCOPED_RELATIONSHIP = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: 2
    })
    SET vault._authgraph_lock = true
    REMOVE vault._authgraph_lock
    WITH vault
    WHERE vault.envelope_revision = $envelope_revision
    MATCH (vault)-[:AG_HAS_SCOPE]->(
        relationship_scope:AGProtectionScope {
            vault_id: $vault_id,
            scope_id: $scope_id
        }
    )
    WHERE
        relationship_scope.scope_id IN $allowed_scope_ids
        AND relationship_scope.scope_key_version = $key_version
        AND relationship_scope.root_key_version = vault.key_version
    MATCH (vault)-[:AG_HAS_SCOPE]->(source_scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(source:AGScopedEntity {
        vault_id: $vault_id,
        entity_id: $from_entity_id
    })
    WHERE
        source_scope.scope_id IN $allowed_scope_ids
        AND source_scope.root_key_version = vault.key_version
        AND source.scope_id = source_scope.scope_id
    MATCH (vault)-[:AG_HAS_SCOPE]->(target_scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(target:AGScopedEntity {
        vault_id: $vault_id,
        entity_id: $to_entity_id
    })
    WHERE
        target_scope.scope_id IN $allowed_scope_ids
        AND target_scope.root_key_version = vault.key_version
        AND target.scope_id = target_scope.scope_id
        AND NOT EXISTS {
            MATCH ()-[existing:AG_SCOPED_LINK {
                relationship_id: $relationship_id
            }]->()
        }
    CREATE (source)-[link:AG_SCOPED_LINK {
        vault_id: $vault_id,
        scope_id: $scope_id,
        relationship_id: $relationship_id,
        payload_version: $payload_version,
        key_version: $key_version,
        algorithm: $algorithm,
        nonce: $nonce,
        ciphertext: $ciphertext
    }]->(target)
    RETURN count(link) AS created
    """

    _GET_SCOPED_RELATIONSHIP = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: 2,
        envelope_revision: $envelope_revision
    })-[:AG_HAS_SCOPE]->(
        relationship_scope:AGProtectionScope {
            vault_id: $vault_id
        }
    )
    MATCH (vault)-[:AG_HAS_SCOPE]->(source_scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(source:AGScopedEntity {
        vault_id: $vault_id,
        entity_id: $from_entity_id
    })
    MATCH (vault)-[:AG_HAS_SCOPE]->(target_scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(target:AGScopedEntity {
        vault_id: $vault_id,
        entity_id: $to_entity_id
    })
    MATCH (source)-[link:AG_SCOPED_LINK {
        vault_id: $vault_id,
        relationship_id: $relationship_id
    }]->(target)
    WHERE
        relationship_scope.scope_id = link.scope_id
        AND relationship_scope.scope_id IN $allowed_scope_ids
        AND relationship_scope.root_key_version = vault.key_version
        AND source_scope.scope_id IN $allowed_scope_ids
        AND source_scope.root_key_version = vault.key_version
        AND target_scope.scope_id IN $allowed_scope_ids
        AND target_scope.root_key_version = vault.key_version
        AND source.scope_id = source_scope.scope_id
        AND target.scope_id = target_scope.scope_id
    RETURN
        link.vault_id AS vault_id,
        link.scope_id AS scope_id,
        link.relationship_id AS relationship_id,
        source.entity_id AS from_entity_id,
        source_scope.scope_id AS from_scope_id,
        target.entity_id AS to_entity_id,
        target_scope.scope_id AS to_scope_id,
        relationship_scope.scope_key_version
            AS protection_scope_key_version,
        link.payload_version AS payload_version,
        link.key_version AS key_version,
        link.algorithm AS algorithm,
        link.nonce AS nonce,
        link.ciphertext AS ciphertext
    LIMIT 1
    """

    _GET_SCOPED_VAULT_SNAPSHOT = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_version: 2
    })
    SET vault._authgraph_lock = true
    REMOVE vault._authgraph_lock
    WITH vault
    WHERE vault.envelope_revision = $envelope_revision
    RETURN
        COLLECT {
            MATCH (vault)-[:AG_HAS_SCOPE]->(scope:AGProtectionScope {
                vault_id: $vault_id
            })-[:AG_PROTECTS]->(entity:AGScopedEntity {
                vault_id: $vault_id
            })
            WHERE
                scope.scope_id IN $allowed_scope_ids
                AND scope.root_key_version = vault.key_version
                AND entity.scope_id = scope.scope_id
            WITH scope, entity
            ORDER BY entity.entity_id
            LIMIT $entity_fetch_limit
            RETURN {
                vault_id: entity.vault_id,
                scope_id: entity.scope_id,
                entity_id: entity.entity_id,
                protection_scope_key_version: scope.scope_key_version,
                payload_version: entity.payload_version,
                key_version: entity.key_version,
                algorithm: entity.algorithm,
                nonce: entity.nonce,
                ciphertext: entity.ciphertext
            } AS entity_row
        } AS entities,
        COLLECT {
            MATCH (vault)-[:AG_HAS_SCOPE]->(
                relationship_scope:AGProtectionScope {
                    vault_id: $vault_id
                }
            )
            MATCH (vault)-[:AG_HAS_SCOPE]->(source_scope:AGProtectionScope {
                vault_id: $vault_id
            })-[:AG_PROTECTS]->(source:AGScopedEntity {
                vault_id: $vault_id
            })
            MATCH (source)-[link:AG_SCOPED_LINK {
                vault_id: $vault_id
            }]->(target:AGScopedEntity {
                vault_id: $vault_id
            })
            MATCH (vault)-[:AG_HAS_SCOPE]->(target_scope:AGProtectionScope {
                vault_id: $vault_id
            })-[:AG_PROTECTS]->(target)
            WHERE
                relationship_scope.scope_id = link.scope_id
                AND relationship_scope.scope_id IN $allowed_scope_ids
                AND relationship_scope.root_key_version = vault.key_version
                AND source_scope.scope_id IN $allowed_scope_ids
                AND source_scope.root_key_version = vault.key_version
                AND target_scope.scope_id IN $allowed_scope_ids
                AND target_scope.root_key_version = vault.key_version
                AND source.scope_id = source_scope.scope_id
                AND target.scope_id = target_scope.scope_id
            WITH
                relationship_scope,
                source_scope,
                source,
                link,
                target,
                target_scope
            ORDER BY link.relationship_id
            LIMIT $relationship_fetch_limit
            RETURN {
                vault_id: link.vault_id,
                scope_id: link.scope_id,
                relationship_id: link.relationship_id,
                from_entity_id: source.entity_id,
                from_scope_id: source_scope.scope_id,
                to_entity_id: target.entity_id,
                to_scope_id: target_scope.scope_id,
                protection_scope_key_version:
                    relationship_scope.scope_key_version,
                payload_version: link.payload_version,
                key_version: link.key_version,
                algorithm: link.algorithm,
                nonce: link.nonce,
                ciphertext: link.ciphertext
            } AS relationship_row
        } AS relationships
    """

    @staticmethod
    def _opaque_text(record: Any, name: str) -> str:
        value = Neo4jGraphRepository._record_text(record, name)
        if (
            not value
            or len(value) > MAX_OPAQUE_ID_CHARS
            or any(unicodedata.category(char).startswith("C") for char in value)
        ):
            raise IntegrityViolation()
        return value

    @staticmethod
    def _valid_scope_ids(scope_ids: object) -> bool:
        return (
            isinstance(scope_ids, tuple)
            and 0 < len(scope_ids) <= MAX_SCOPES_PER_SESSION
            and all(
                isinstance(scope_id, str)
                and scope_id
                and len(scope_id) <= MAX_OPAQUE_ID_CHARS
                and not any(
                    unicodedata.category(char).startswith("C")
                    for char in scope_id
                )
                for scope_id in scope_ids
            )
            and len(set(scope_ids)) == len(scope_ids)
        )

    @staticmethod
    def _scope_envelope_parameters(
        envelope: ScopeKeyEnvelope,
    ) -> dict[str, object]:
        return {
            "scope_envelope_version": envelope.version,
            "root_key_version": envelope.root_key_version,
            "scope_key_version": envelope.scope_key_version,
            "scope_wrapping_algorithm": envelope.algorithm,
            "scope_envelope_nonce": envelope.nonce,
            "wrapped_scope_dek": envelope.wrapped_scope_dek,
        }

    @staticmethod
    def _valid_scope_envelope(envelope: object) -> bool:
        return (
            isinstance(envelope, ScopeKeyEnvelope)
            and type(envelope.version) is int
            and envelope.version == SCOPE_ENVELOPE_VERSION
            and type(envelope.root_key_version) is int
            and envelope.root_key_version > 0
            and type(envelope.scope_key_version) is int
            and envelope.scope_key_version > 0
            and envelope.algorithm == SCOPE_WRAPPING_ALGORITHM
            and isinstance(envelope.nonce, bytes)
            and len(envelope.nonce) == AES_GCM_NONCE_BYTES
            and isinstance(envelope.wrapped_scope_dek, bytes)
            and len(envelope.wrapped_scope_dek)
            == SCOPE_DEK_CIPHERTEXT_BYTES
        )

    @staticmethod
    def _valid_scoped_payload(payload: object) -> bool:
        return (
            isinstance(payload, EncryptedPayload)
            and type(payload.version) is int
            and payload.version == SCOPED_PAYLOAD_VERSION
            and type(payload.key_version) is int
            and payload.key_version > 0
            and payload.algorithm == SCOPED_PAYLOAD_ALGORITHM
            and isinstance(payload.nonce, bytes)
            and len(payload.nonce) == AES_GCM_NONCE_BYTES
            and isinstance(payload.ciphertext, bytes)
            and len(payload.ciphertext) >= AES_GCM_TAG_BYTES
        )

    def _scope_from_record(self, record: Any) -> ProtectionScopeRow:
        envelope = ScopeKeyEnvelope(
            version=self._record_integer(record, "scope_envelope_version"),
            root_key_version=self._record_integer(
                record,
                "root_key_version",
            ),
            scope_key_version=self._record_integer(
                record,
                "scope_key_version",
            ),
            algorithm=self._record_text(
                record,
                "scope_wrapping_algorithm",
            ),
            nonce=self._record_bytes(record, "scope_envelope_nonce"),
            wrapped_scope_dek=self._record_bytes(
                record,
                "wrapped_scope_dek",
            ),
        )
        if not self._valid_scope_envelope(envelope):
            raise IntegrityViolation()
        return ProtectionScopeRow(
            vault_id=self._opaque_text(record, "vault_id"),
            scope_id=self._opaque_text(record, "scope_id"),
            envelope=envelope,
        )

    def _scoped_entity_from_record(
        self,
        record: Any,
    ) -> ScopedEncryptedEntityRow:
        payload = self._payload_from_record(record)
        expected_key_version = self._record_integer(
            record,
            "protection_scope_key_version",
        )
        if (
            not self._valid_scoped_payload(payload)
            or payload.key_version != expected_key_version
        ):
            raise IntegrityViolation()
        return ScopedEncryptedEntityRow(
            vault_id=self._opaque_text(record, "vault_id"),
            scope_id=self._opaque_text(record, "scope_id"),
            entity_id=self._opaque_text(record, "entity_id"),
            payload=payload,
        )

    def _scoped_relationship_from_record(
        self,
        record: Any,
    ) -> tuple[ScopedEncryptedRelationshipRow, str, str]:
        payload = self._payload_from_record(record)
        expected_key_version = self._record_integer(
            record,
            "protection_scope_key_version",
        )
        if (
            not self._valid_scoped_payload(payload)
            or payload.key_version != expected_key_version
        ):
            raise IntegrityViolation()
        row = ScopedEncryptedRelationshipRow(
            vault_id=self._opaque_text(record, "vault_id"),
            scope_id=self._opaque_text(record, "scope_id"),
            relationship_id=self._opaque_text(record, "relationship_id"),
            from_entity_id=self._opaque_text(record, "from_entity_id"),
            to_entity_id=self._opaque_text(record, "to_entity_id"),
            payload=payload,
        )
        return (
            row,
            self._opaque_text(record, "from_scope_id"),
            self._opaque_text(record, "to_scope_id"),
        )

    def create_vault(self, row: VaultRow) -> bool:
        if (
            not isinstance(row, VaultRow)
            or not isinstance(row.envelope, KeyEnvelope)
            or type(row.envelope.version) is not int
            or row.envelope.version != 2
        ):
            return False
        return super().create_vault(row)

    def get_vault(self, principal_id: str, vault_id: str) -> VaultRow | None:
        row = super().get_vault(principal_id, vault_id)
        if row is not None and row.envelope.version != 2:
            raise IntegrityViolation()
        return row

    def replace_envelope(
        self,
        principal_id: str,
        vault_id: str,
        expected_revision: int,
        envelope: KeyEnvelope,
    ) -> bool:
        if (
            not isinstance(envelope, KeyEnvelope)
            or type(envelope.version) is not int
            or envelope.version != 2
        ):
            return False
        return super().replace_envelope(
            principal_id,
            vault_id,
            expected_revision,
            envelope,
        )

    def put_protection_scope(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: ProtectionScopeRow,
    ) -> bool:
        if (
            not isinstance(row, ProtectionScopeRow)
            or row.vault_id != vault_id
            or not self._valid_scope_ids((row.scope_id,))
            or not self._valid_scope_envelope(row.envelope)
        ):
            return False
        parameters = {
            "principal_id": principal_id,
            "vault_id": vault_id,
            "envelope_revision": envelope_revision,
            "scope_id": row.scope_id,
            **self._scope_envelope_parameters(row.envelope),
        }
        try:
            first = self._first(
                self._execute(
                    self._PUT_PROTECTION_SCOPE,
                    **parameters,
                )
            )
        except IncompleteCommit:
            existing = self.get_protection_scopes(
                principal_id,
                vault_id,
                envelope_revision,
                (row.scope_id,),
            )
            if existing == (row,):
                return True
            raise
        if first is not None and self._record_integer(first, "created") == 1:
            return True
        return (
            self.get_protection_scopes(
                principal_id,
                vault_id,
                envelope_revision,
                (row.scope_id,),
            )
            == (row,)
        )

    def get_protection_scopes(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        scope_ids: tuple[str, ...],
    ) -> tuple[ProtectionScopeRow, ...] | None:
        if not self._valid_scope_ids(scope_ids):
            return None
        first = self._first(
            self._execute(
                self._GET_PROTECTION_SCOPES,
                principal_id=principal_id,
                vault_id=vault_id,
                envelope_revision=envelope_revision,
                scope_ids=list(scope_ids),
            )
        )
        if first is None:
            return None
        rows = tuple(
            self._scope_from_record(record)
            for record in self._record_list(first, "scopes")
        )
        row_scope_ids = tuple(row.scope_id for row in rows)
        if (
            len(set(row_scope_ids)) != len(row_scope_ids)
            or any(
                row.vault_id != vault_id or row.scope_id not in scope_ids
                for row in rows
            )
        ):
            raise IntegrityViolation()
        return rows

    def put_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: ScopedEncryptedEntityRow,
    ) -> bool:
        if (
            not isinstance(row, ScopedEncryptedEntityRow)
            or row.vault_id != vault_id
            or not self._valid_scope_ids((row.scope_id,))
            or not self._valid_scoped_payload(row.payload)
        ):
            return False
        try:
            first = self._first(
                self._execute(
                    self._PUT_SCOPED_ENTITY,
                    principal_id=principal_id,
                    vault_id=vault_id,
                    envelope_revision=envelope_revision,
                    scope_id=row.scope_id,
                    entity_id=row.entity_id,
                    **self._payload_parameters(row.payload),
                )
            )
        except IncompleteCommit:
            existing = self.get_scoped_entity(
                principal_id,
                vault_id,
                envelope_revision,
                (row.scope_id,),
                row.entity_id,
            )
            if existing == row:
                return True
            raise
        if first is not None and self._record_integer(first, "created") == 1:
            return True
        return (
            self.get_scoped_entity(
                principal_id,
                vault_id,
                envelope_revision,
                (row.scope_id,),
                row.entity_id,
            )
            == row
        )

    def get_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_id: str,
    ) -> ScopedEncryptedEntityRow | None:
        if not self._valid_scope_ids(allowed_scope_ids):
            return None
        first = self._first(
            self._execute(
                self._GET_SCOPED_ENTITY,
                principal_id=principal_id,
                vault_id=vault_id,
                envelope_revision=envelope_revision,
                allowed_scope_ids=list(allowed_scope_ids),
                entity_id=entity_id,
            )
        )
        if first is None:
            return None
        row = self._scoped_entity_from_record(first)
        if (
            row.vault_id != vault_id
            or row.entity_id != entity_id
            or row.scope_id not in allowed_scope_ids
        ):
            raise IntegrityViolation()
        return row

    def put_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        row: ScopedEncryptedRelationshipRow,
    ) -> bool:
        if (
            not isinstance(row, ScopedEncryptedRelationshipRow)
            or row.vault_id != vault_id
            or not self._valid_scope_ids(allowed_scope_ids)
            or row.scope_id not in allowed_scope_ids
            or not self._valid_scoped_payload(row.payload)
        ):
            return False
        parameters = {
            "principal_id": principal_id,
            "vault_id": vault_id,
            "envelope_revision": envelope_revision,
            "allowed_scope_ids": list(allowed_scope_ids),
            "scope_id": row.scope_id,
            "relationship_id": row.relationship_id,
            "from_entity_id": row.from_entity_id,
            "to_entity_id": row.to_entity_id,
            **self._payload_parameters(row.payload),
        }
        try:
            first = self._first(
                self._execute(
                    self._PUT_SCOPED_RELATIONSHIP,
                    **parameters,
                )
            )
        except IncompleteCommit:
            existing = self._get_scoped_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                row.relationship_id,
                row.from_entity_id,
                row.to_entity_id,
            )
            if existing == row:
                return True
            raise
        if first is not None and self._record_integer(first, "created") == 1:
            return True
        return (
            self._get_scoped_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                row.relationship_id,
                row.from_entity_id,
                row.to_entity_id,
            )
            == row
        )

    def _get_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        relationship_id: str,
        from_entity_id: str,
        to_entity_id: str,
    ) -> ScopedEncryptedRelationshipRow | None:
        if not self._valid_scope_ids(allowed_scope_ids):
            return None
        first = self._first(
            self._execute(
                self._GET_SCOPED_RELATIONSHIP,
                principal_id=principal_id,
                vault_id=vault_id,
                envelope_revision=envelope_revision,
                allowed_scope_ids=list(allowed_scope_ids),
                relationship_id=relationship_id,
                from_entity_id=from_entity_id,
                to_entity_id=to_entity_id,
            )
        )
        if first is None:
            return None
        row, from_scope_id, to_scope_id = (
            self._scoped_relationship_from_record(first)
        )
        if (
            row.vault_id != vault_id
            or row.relationship_id != relationship_id
            or row.from_entity_id != from_entity_id
            or row.to_entity_id != to_entity_id
            or row.scope_id not in allowed_scope_ids
            or from_scope_id not in allowed_scope_ids
            or to_scope_id not in allowed_scope_ids
        ):
            raise IntegrityViolation()
        return row

    def get_scoped_vault_snapshot(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        *,
        entity_limit: int,
        relationship_limit: int,
    ) -> ScopedEncryptedVaultSnapshotRow | None:
        if (
            type(entity_limit) is not int
            or entity_limit <= 0
            or type(relationship_limit) is not int
            or relationship_limit <= 0
        ):
            raise ValueError("Snapshot repository limits must be positive integers.")
        if not self._valid_scope_ids(allowed_scope_ids):
            return None
        first = self._first(
            self._execute(
                self._GET_SCOPED_VAULT_SNAPSHOT,
                principal_id=principal_id,
                vault_id=vault_id,
                envelope_revision=envelope_revision,
                allowed_scope_ids=list(allowed_scope_ids),
                entity_fetch_limit=entity_limit + 1,
                relationship_fetch_limit=relationship_limit + 1,
            )
        )
        if first is None:
            return None

        entities = tuple(
            self._scoped_entity_from_record(record)
            for record in self._record_list(first, "entities")
        )
        relationship_results = tuple(
            self._scoped_relationship_from_record(record)
            for record in self._record_list(first, "relationships")
        )
        relationships = tuple(result[0] for result in relationship_results)
        entity_ids = tuple(row.entity_id for row in entities)
        relationship_ids = tuple(
            row.relationship_id for row in relationships
        )
        if (
            len(set(entity_ids)) != len(entity_ids)
            or len(set(relationship_ids)) != len(relationship_ids)
            or any(
                row.vault_id != vault_id
                or row.scope_id not in allowed_scope_ids
                for row in entities
            )
            or any(
                row.vault_id != vault_id
                or row.scope_id not in allowed_scope_ids
                or from_scope_id not in allowed_scope_ids
                or to_scope_id not in allowed_scope_ids
                for row, from_scope_id, to_scope_id in relationship_results
            )
        ):
            raise IntegrityViolation()
        return ScopedEncryptedVaultSnapshotRow(
            entities=entities,
            relationships=relationships,
        )
