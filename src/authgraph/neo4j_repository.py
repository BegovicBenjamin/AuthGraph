"""Ciphertext-only Neo4j repository.

The adapter deliberately exposes only fixed, parameterized, vault-scoped
operations. It never receives passphrases, KEKs, DEKs, decrypted owner data,
or arbitrary Cypher from callers.

The Neo4j Python driver is injected so importing this module does not open a
connection or read configuration.
"""

from __future__ import annotations

from typing import Any, Iterable

from .errors import IntegrityViolation
from .models import (
    EncryptedEntityRow,
    EncryptedNeighborhoodRow,
    EncryptedPayload,
    EncryptedRelationshipRow,
    EncryptedVaultSnapshotRow,
    KdfParameters,
    KeyEnvelope,
    VaultRow,
)

try:
    from neo4j.exceptions import IncompleteCommit
except ImportError:  # Unit tests do not require the optional runtime driver.
    class IncompleteCommit(Exception):
        """Fallback type used only when the Neo4j driver is not installed."""


class Neo4jGraphRepository:
    """Neo4j implementation of AuthGraph's complete-mediation boundary."""

    _CREATE_VAULT = """
    OPTIONAL MATCH (existing:AGVault {vault_id: $vault_id})
    WITH existing
    WHERE existing IS NULL
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
        principal_id: $principal_id
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
        principal_id: $principal_id
    })
    SET vault._authgraph_lock = true
    REMOVE vault._authgraph_lock
    WITH vault
    WHERE vault.envelope_revision = $expected_revision
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

    _PUT_ENTITY = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id
    })
    SET vault._authgraph_lock = true
    REMOVE vault._authgraph_lock
    WITH vault
    WHERE
        vault.envelope_revision = $envelope_revision
        AND NOT EXISTS {
        MATCH (:AGEntity {entity_id: $entity_id})
    }
    CREATE (entity:AGEntity {
        vault_id: $vault_id,
        entity_id: $entity_id,
        payload_version: $payload_version,
        key_version: $key_version,
        algorithm: $algorithm,
        nonce: $nonce,
        ciphertext: $ciphertext
    })
    CREATE (vault)-[:AG_OWNS]->(entity)
    RETURN count(entity) AS created
    """

    _GET_ENTITY = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_revision: $envelope_revision
    })-[:AG_OWNS]->(entity:AGEntity {
        vault_id: $vault_id,
        entity_id: $entity_id
    })
    RETURN
        entity.payload_version AS payload_version,
        entity.key_version AS key_version,
        entity.algorithm AS algorithm,
        entity.nonce AS nonce,
        entity.ciphertext AS ciphertext
    LIMIT 1
    """

    _PUT_RELATIONSHIP = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id
    })
    SET vault._authgraph_lock = true
    REMOVE vault._authgraph_lock
    WITH vault
    WHERE vault.envelope_revision = $envelope_revision
    MATCH (vault)-[:AG_OWNS]->(source:AGEntity {
        vault_id: $vault_id,
        entity_id: $from_entity_id
    })
    MATCH (vault)-[:AG_OWNS]->(target:AGEntity {
        vault_id: $vault_id,
        entity_id: $to_entity_id
    })
    WHERE NOT EXISTS {
        MATCH ()-[existing:AG_LINK {
            relationship_id: $relationship_id
        }]->()
    }
    CREATE (source)-[link:AG_LINK {
        vault_id: $vault_id,
        relationship_id: $relationship_id,
        payload_version: $payload_version,
        key_version: $key_version,
        algorithm: $algorithm,
        nonce: $nonce,
        ciphertext: $ciphertext
    }]->(target)
    RETURN count(link) AS created
    """

    _GET_NEIGHBORS = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_revision: $envelope_revision
    })-[:AG_OWNS]->(center:AGEntity {
        vault_id: $vault_id,
        entity_id: $entity_id
    })
    MATCH (center)-[link:AG_LINK]-(neighbor:AGEntity {
        vault_id: $vault_id
    })
    WHERE
        link.vault_id = $vault_id
        AND EXISTS {
            MATCH (vault)-[:AG_OWNS]->(neighbor)
        }
    RETURN
        neighbor.entity_id AS neighbor_entity_id,
        neighbor.payload_version AS neighbor_payload_version,
        neighbor.key_version AS neighbor_key_version,
        neighbor.algorithm AS neighbor_algorithm,
        neighbor.nonce AS neighbor_nonce,
        neighbor.ciphertext AS neighbor_ciphertext,
        link.relationship_id AS relationship_id,
        link.payload_version AS relationship_payload_version,
        link.key_version AS relationship_key_version,
        link.algorithm AS relationship_algorithm,
        link.nonce AS relationship_nonce,
        link.ciphertext AS relationship_ciphertext,
        startNode(link).entity_id AS from_entity_id,
        endNode(link).entity_id AS to_entity_id
    LIMIT $limit
    """

    _GET_RELATIONSHIP = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id,
        envelope_revision: $envelope_revision
    })-[:AG_OWNS]->(source:AGEntity {
        vault_id: $vault_id,
        entity_id: $from_entity_id
    })
    MATCH (vault)-[:AG_OWNS]->(target:AGEntity {
        vault_id: $vault_id,
        entity_id: $to_entity_id
    })
    MATCH (source)-[link:AG_LINK {
        vault_id: $vault_id,
        relationship_id: $relationship_id
    }]->(target)
    RETURN
        link.payload_version AS payload_version,
        link.key_version AS key_version,
        link.algorithm AS algorithm,
        link.nonce AS nonce,
        link.ciphertext AS ciphertext
    LIMIT 1
    """

    _GET_VAULT_SNAPSHOT = """
    MATCH (vault:AGVault {
        vault_id: $vault_id,
        principal_id: $principal_id
    })
    SET vault._authgraph_lock = true
    REMOVE vault._authgraph_lock
    WITH vault
    WHERE vault.envelope_revision = $envelope_revision
    RETURN
        COLLECT {
            MATCH (vault)-[:AG_OWNS]->(entity:AGEntity {
                vault_id: $vault_id
            })
            WITH entity
            LIMIT $entity_fetch_limit
            RETURN {
                entity_id: entity.entity_id,
                payload_version: entity.payload_version,
                key_version: entity.key_version,
                algorithm: entity.algorithm,
                nonce: entity.nonce,
                ciphertext: entity.ciphertext
            } AS entity_row
        } AS entities,
        COLLECT {
            MATCH (vault)-[:AG_OWNS]->(source:AGEntity {
                vault_id: $vault_id
            })-[link:AG_LINK {
                vault_id: $vault_id
            }]->(target:AGEntity {
                vault_id: $vault_id
            })
            WHERE EXISTS {
                MATCH (vault)-[:AG_OWNS]->(target)
            }
            WITH source, link, target
            LIMIT $relationship_fetch_limit
            RETURN {
                relationship_id: link.relationship_id,
                from_entity_id: source.entity_id,
                to_entity_id: target.entity_id,
                payload_version: link.payload_version,
                key_version: link.key_version,
                algorithm: link.algorithm,
                nonce: link.nonce,
                ciphertext: link.ciphertext
            } AS relationship_row
        } AS relationships
    """

    def __init__(self, driver: Any, *, database: str) -> None:
        if not database:
            raise ValueError("An explicit Neo4j database name is required.")
        if getattr(driver, "encrypted", None) is not True:
            raise ValueError(
                "AuthGraph requires a Neo4j driver with encrypted transport."
            )
        self._driver = driver
        self._database = database

    def _execute(self, query: str, **parameters: object) -> list[Any]:
        result = self._driver.execute_query(
            query,
            parameters_=parameters,
            database_=self._database,
        )
        records = getattr(result, "records", None)
        if records is not None:
            return list(records)
        # Neo4j 5.x EagerResult supports tuple unpacking.
        return list(result[0])

    @staticmethod
    def _first(records: Iterable[Any]) -> Any | None:
        return next(iter(records), None)

    @staticmethod
    def _record_integer(record: Any, name: str) -> int:
        try:
            value = record[name]
        except (KeyError, TypeError, IndexError):
            raise IntegrityViolation() from None
        if type(value) is not int:
            raise IntegrityViolation()
        return value

    @staticmethod
    def _record_text(record: Any, name: str) -> str:
        try:
            value = record[name]
        except (KeyError, TypeError, IndexError):
            raise IntegrityViolation() from None
        if not isinstance(value, str):
            raise IntegrityViolation()
        return value

    @staticmethod
    def _record_bytes(record: Any, name: str) -> bytes:
        try:
            value = record[name]
        except (KeyError, TypeError, IndexError):
            raise IntegrityViolation() from None
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise IntegrityViolation()
        return bytes(value)

    @staticmethod
    def _record_list(record: Any, name: str) -> list[Any]:
        try:
            value = record[name]
        except (KeyError, TypeError, IndexError):
            raise IntegrityViolation() from None
        if not isinstance(value, list):
            raise IntegrityViolation()
        return value

    @staticmethod
    def _envelope_parameters(envelope: KeyEnvelope) -> dict[str, object]:
        return {
            "envelope_version": envelope.version,
            "envelope_revision": envelope.envelope_revision,
            "key_version": envelope.key_version,
            "wrapping_algorithm": envelope.wrapping_algorithm,
            "kdf_algorithm": envelope.kdf.algorithm,
            "kdf_memory_cost_kib": envelope.kdf.memory_cost_kib,
            "kdf_iterations": envelope.kdf.iterations,
            "kdf_lanes": envelope.kdf.lanes,
            "kdf_output_length": envelope.kdf.output_length,
            "envelope_salt": envelope.salt,
            "envelope_nonce": envelope.nonce,
            "wrapped_dek": envelope.wrapped_dek,
        }

    @staticmethod
    def _payload_parameters(payload: EncryptedPayload) -> dict[str, object]:
        return {
            "payload_version": payload.version,
            "key_version": payload.key_version,
            "algorithm": payload.algorithm,
            "nonce": payload.nonce,
            "ciphertext": payload.ciphertext,
        }

    @staticmethod
    def _payload_from_record(record: Any, prefix: str = "") -> EncryptedPayload:
        return EncryptedPayload(
            version=Neo4jGraphRepository._record_integer(
                record, f"{prefix}payload_version"
            ),
            key_version=Neo4jGraphRepository._record_integer(
                record, f"{prefix}key_version"
            ),
            algorithm=Neo4jGraphRepository._record_text(
                record, f"{prefix}algorithm"
            ),
            nonce=Neo4jGraphRepository._record_bytes(
                record, f"{prefix}nonce"
            ),
            ciphertext=Neo4jGraphRepository._record_bytes(
                record, f"{prefix}ciphertext"
            ),
        )

    def create_vault(self, row: VaultRow) -> bool:
        try:
            records = self._execute(
                self._CREATE_VAULT,
                vault_id=row.vault_id,
                principal_id=row.principal_id,
                **self._envelope_parameters(row.envelope),
            )
        except IncompleteCommit:
            if self.get_vault(row.principal_id, row.vault_id) == row:
                return True
            raise
        first = self._first(records)
        if first is not None and self._record_integer(first, "created") == 1:
            return True
        # execute_query() can retry a committed transaction. Treat the exact
        # already-persisted row as success instead of allocating a second ID.
        return self.get_vault(row.principal_id, row.vault_id) == row

    def get_vault(self, principal_id: str, vault_id: str) -> VaultRow | None:
        first = self._first(
            self._execute(
                self._GET_VAULT,
                principal_id=principal_id,
                vault_id=vault_id,
            )
        )
        if first is None:
            return None
        return VaultRow(
            principal_id=principal_id,
            vault_id=vault_id,
            envelope=KeyEnvelope(
                version=self._record_integer(first, "envelope_version"),
                envelope_revision=self._record_integer(
                    first, "envelope_revision"
                ),
                key_version=self._record_integer(first, "key_version"),
                wrapping_algorithm=self._record_text(
                    first, "wrapping_algorithm"
                ),
                kdf=KdfParameters(
                    algorithm=self._record_text(first, "kdf_algorithm"),
                    memory_cost_kib=self._record_integer(
                        first, "kdf_memory_cost_kib"
                    ),
                    iterations=self._record_integer(first, "kdf_iterations"),
                    lanes=self._record_integer(first, "kdf_lanes"),
                    output_length=self._record_integer(
                        first, "kdf_output_length"
                    ),
                ),
                salt=self._record_bytes(first, "envelope_salt"),
                nonce=self._record_bytes(first, "envelope_nonce"),
                wrapped_dek=self._record_bytes(first, "wrapped_dek"),
            ),
        )

    def replace_envelope(
        self,
        principal_id: str,
        vault_id: str,
        expected_revision: int,
        envelope: KeyEnvelope,
    ) -> bool:
        if (
            type(expected_revision) is not int
            or expected_revision <= 0
            or envelope.envelope_revision != expected_revision + 1
        ):
            return False
        try:
            first = self._first(
                self._execute(
                    self._REPLACE_ENVELOPE,
                    principal_id=principal_id,
                    vault_id=vault_id,
                    expected_revision=expected_revision,
                    **self._envelope_parameters(envelope),
                )
            )
        except IncompleteCommit:
            current = self.get_vault(principal_id, vault_id)
            if current is not None and current.envelope == envelope:
                return True
            raise
        if first is not None and self._record_integer(first, "updated") == 1:
            return True
        # A retry after an ambiguous successful commit observes the new
        # revision and updates zero rows. Exact comparison makes that retry
        # idempotent without accepting a competing envelope.
        current = self.get_vault(principal_id, vault_id)
        return current is not None and current.envelope == envelope

    def put_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: EncryptedEntityRow,
    ) -> bool:
        if row.vault_id != vault_id:
            return False
        try:
            first = self._first(
                self._execute(
                    self._PUT_ENTITY,
                    principal_id=principal_id,
                    vault_id=vault_id,
                    envelope_revision=envelope_revision,
                    entity_id=row.entity_id,
                    **self._payload_parameters(row.payload),
                )
            )
        except IncompleteCommit:
            existing = self.get_entity(
                principal_id,
                vault_id,
                envelope_revision,
                row.entity_id,
            )
            if existing == row:
                return True
            raise
        if first is not None and self._record_integer(first, "created") == 1:
            return True
        existing = self.get_entity(
            principal_id,
            vault_id,
            envelope_revision,
            row.entity_id,
        )
        return existing == row

    def get_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        entity_id: str,
    ) -> EncryptedEntityRow | None:
        first = self._first(
            self._execute(
                self._GET_ENTITY,
                principal_id=principal_id,
                vault_id=vault_id,
                envelope_revision=envelope_revision,
                entity_id=entity_id,
            )
        )
        if first is None:
            return None
        return EncryptedEntityRow(
            vault_id=vault_id,
            entity_id=entity_id,
            payload=self._payload_from_record(first),
        )

    def put_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: EncryptedRelationshipRow,
    ) -> bool:
        if row.vault_id != vault_id:
            return False
        try:
            first = self._first(
                self._execute(
                    self._PUT_RELATIONSHIP,
                    principal_id=principal_id,
                    vault_id=vault_id,
                    envelope_revision=envelope_revision,
                    relationship_id=row.relationship_id,
                    from_entity_id=row.from_entity_id,
                    to_entity_id=row.to_entity_id,
                    **self._payload_parameters(row.payload),
                )
            )
        except IncompleteCommit:
            existing = self._get_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                row.relationship_id,
                row.from_entity_id,
                row.to_entity_id,
            )
            if existing == row:
                return True
            raise
        if first is not None and self._record_integer(first, "created") == 1:
            return True
        existing = self._get_relationship(
            principal_id,
            vault_id,
            envelope_revision,
            row.relationship_id,
            row.from_entity_id,
            row.to_entity_id,
        )
        return existing == row

    def _get_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        relationship_id: str,
        from_entity_id: str,
        to_entity_id: str,
    ) -> EncryptedRelationshipRow | None:
        first = self._first(
            self._execute(
                self._GET_RELATIONSHIP,
                principal_id=principal_id,
                vault_id=vault_id,
                envelope_revision=envelope_revision,
                relationship_id=relationship_id,
                from_entity_id=from_entity_id,
                to_entity_id=to_entity_id,
            )
        )
        if first is None:
            return None
        return EncryptedRelationshipRow(
            vault_id=vault_id,
            relationship_id=relationship_id,
            from_entity_id=from_entity_id,
            to_entity_id=to_entity_id,
            payload=self._payload_from_record(first),
        )

    def get_neighborhood(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        entity_id: str,
        *,
        limit: int,
    ) -> EncryptedNeighborhoodRow | None:
        center = self.get_entity(
            principal_id,
            vault_id,
            envelope_revision,
            entity_id,
        )
        if center is None:
            return None
        records = self._execute(
            self._GET_NEIGHBORS,
            principal_id=principal_id,
            vault_id=vault_id,
            envelope_revision=envelope_revision,
            entity_id=entity_id,
            limit=limit,
        )
        neighbors: dict[str, EncryptedEntityRow] = {}
        relationships: dict[str, EncryptedRelationshipRow] = {}
        for record in records:
            neighbor_id = self._record_text(record, "neighbor_entity_id")
            relationship_id = self._record_text(record, "relationship_id")
            neighbors[neighbor_id] = EncryptedEntityRow(
                vault_id=vault_id,
                entity_id=neighbor_id,
                payload=self._payload_from_record(record, "neighbor_"),
            )
            relationships[relationship_id] = EncryptedRelationshipRow(
                vault_id=vault_id,
                relationship_id=relationship_id,
                from_entity_id=self._record_text(record, "from_entity_id"),
                to_entity_id=self._record_text(record, "to_entity_id"),
                payload=self._payload_from_record(record, "relationship_"),
            )
        return EncryptedNeighborhoodRow(
            center=center,
            neighbors=tuple(neighbors.values()),
            relationships=tuple(relationships.values()),
        )

    def get_vault_snapshot(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        *,
        entity_limit: int,
        relationship_limit: int,
    ) -> EncryptedVaultSnapshotRow | None:
        """Fetch bounded ciphertext for one complete owner-vault snapshot."""

        if (
            type(entity_limit) is not int
            or entity_limit <= 0
            or type(relationship_limit) is not int
            or relationship_limit <= 0
        ):
            raise ValueError("Snapshot repository limits must be positive integers.")
        first = self._first(
            self._execute(
                self._GET_VAULT_SNAPSHOT,
                principal_id=principal_id,
                vault_id=vault_id,
                envelope_revision=envelope_revision,
                entity_fetch_limit=entity_limit + 1,
                relationship_fetch_limit=relationship_limit + 1,
            )
        )
        if first is None:
            return None
        entities = tuple(
            EncryptedEntityRow(
                vault_id=vault_id,
                entity_id=self._record_text(record, "entity_id"),
                payload=self._payload_from_record(record),
            )
            for record in self._record_list(first, "entities")
        )
        relationships = tuple(
            EncryptedRelationshipRow(
                vault_id=vault_id,
                relationship_id=self._record_text(
                    record,
                    "relationship_id",
                ),
                from_entity_id=self._record_text(
                    record,
                    "from_entity_id",
                ),
                to_entity_id=self._record_text(
                    record,
                    "to_entity_id",
                ),
                payload=self._payload_from_record(record),
            )
            for record in self._record_list(first, "relationships")
        )
        return EncryptedVaultSnapshotRow(
            entities=entities,
            relationships=relationships,
        )
