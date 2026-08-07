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
    ScopedEncryptedEntityRow,
    ScopedEncryptedRelationshipRow,
    ScopedEncryptedVaultSnapshotRow,
    ScopeKeyEnvelope,
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
        record_revision: $record_revision,
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
        coalesce(entity.record_revision, 1) AS record_revision,
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
        record_revision: $record_revision,
        payload_version: $payload_version,
        key_version: $key_version,
        algorithm: $algorithm,
        nonce: $nonce,
        ciphertext: $ciphertext
    }]->(target)
    RETURN count(link) AS created
    """

    _PUT_SCOPED_ENTITY_RELATIONSHIP_BUNDLE = """
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
        AND relationship_scope.root_key_version = vault.key_version
        AND relationship_scope.scope_key_version
            = $relationship_key_version
        AND $relationship_record_revision = 1
        AND all(candidate IN $entity_rows WHERE
            candidate.scope_id = relationship_scope.scope_id
            AND candidate.key_version
                = relationship_scope.scope_key_version
            AND candidate.record_revision = 1
            AND NOT EXISTS {
                MATCH (:AGScopedEntity {
                    entity_id: candidate.entity_id
                })
            }
        )
        AND NOT EXISTS {
            MATCH ()-[existing:AG_SCOPED_LINK {
                relationship_id: $relationship_id
            }]->()
        }
        AND (
            $from_entity_id IN [
                candidate IN $entity_rows | candidate.entity_id
            ]
            OR EXISTS {
                MATCH (vault)-[:AG_HAS_SCOPE]->(
                    existing_source_scope:AGProtectionScope {
                        vault_id: $vault_id
                    }
                )-[:AG_PROTECTS]->(existing_source:AGScopedEntity {
                    vault_id: $vault_id,
                    entity_id: $from_entity_id
                })
                WHERE
                    existing_source_scope.scope_id IN $allowed_scope_ids
                    AND existing_source_scope.root_key_version
                        = vault.key_version
                    AND existing_source.scope_id
                        = existing_source_scope.scope_id
            }
        )
        AND (
            $to_entity_id IN [
                candidate IN $entity_rows | candidate.entity_id
            ]
            OR EXISTS {
                MATCH (vault)-[:AG_HAS_SCOPE]->(
                    existing_target_scope:AGProtectionScope {
                        vault_id: $vault_id
                    }
                )-[:AG_PROTECTS]->(existing_target:AGScopedEntity {
                    vault_id: $vault_id,
                    entity_id: $to_entity_id
                })
                WHERE
                    existing_target_scope.scope_id IN $allowed_scope_ids
                    AND existing_target_scope.root_key_version
                        = vault.key_version
                    AND existing_target.scope_id
                        = existing_target_scope.scope_id
            }
        )
    FOREACH (candidate IN $entity_rows |
        CREATE (entity:AGScopedEntity {
            vault_id: $vault_id,
            scope_id: candidate.scope_id,
            entity_id: candidate.entity_id,
            record_revision: candidate.record_revision,
            payload_version: candidate.payload_version,
            key_version: candidate.key_version,
            algorithm: candidate.algorithm,
            nonce: candidate.nonce,
            ciphertext: candidate.ciphertext
        })
        CREATE (relationship_scope)-[:AG_PROTECTS]->(entity)
    )
    WITH vault, relationship_scope
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
    CREATE (source)-[link:AG_SCOPED_LINK {
        vault_id: $vault_id,
        scope_id: $scope_id,
        relationship_id: $relationship_id,
        record_revision: $relationship_record_revision,
        payload_version: $relationship_payload_version,
        key_version: $relationship_key_version,
        algorithm: $relationship_algorithm,
        nonce: $relationship_nonce,
        ciphertext: $relationship_ciphertext
    }]->(target)
    RETURN
        size($entity_rows) AS created_entities,
        count(link) AS created_relationships
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
    })-[:AG_PROTECTS]->(source:AGScopedEntity {vault_id: $vault_id})
    MATCH (vault)-[:AG_HAS_SCOPE]->(target_scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(target:AGScopedEntity {vault_id: $vault_id})
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
        coalesce(link.record_revision, 1) AS record_revision,
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

    _REPLACE_SCOPED_ENTITY = """
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
    })-[:AG_PROTECTS]->(entity:AGScopedEntity {
        vault_id: $vault_id,
        entity_id: $entity_id
    })
    WHERE
        scope.scope_id IN $allowed_scope_ids
        AND scope.root_key_version = vault.key_version
        AND scope.scope_key_version = $key_version
        AND entity.scope_id = scope.scope_id
        AND coalesce(entity.record_revision, 1)
            = $expected_record_revision
        AND $record_revision = $expected_record_revision + 1
    SET
        entity.record_revision = $record_revision,
        entity.payload_version = $payload_version,
        entity.key_version = $key_version,
        entity.algorithm = $algorithm,
        entity.nonce = $nonce,
        entity.ciphertext = $ciphertext
    RETURN count(entity) AS updated
    """

    _REPLACE_SCOPED_RELATIONSHIP = """
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
        AND relationship_scope.scope_key_version = $key_version
        AND source_scope.scope_id IN $allowed_scope_ids
        AND source_scope.root_key_version = vault.key_version
        AND target_scope.scope_id IN $allowed_scope_ids
        AND target_scope.root_key_version = vault.key_version
        AND source.scope_id = source_scope.scope_id
        AND target.scope_id = target_scope.scope_id
        AND coalesce(link.record_revision, 1)
            = $expected_record_revision
        AND $record_revision = $expected_record_revision + 1
    SET
        link.record_revision = $record_revision,
        link.payload_version = $payload_version,
        link.key_version = $key_version,
        link.algorithm = $algorithm,
        link.nonce = $nonce,
        link.ciphertext = $ciphertext
    RETURN count(link) AS updated
    """

    _DELETE_SCOPED_ENTITY = """
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
        vault_id: $vault_id
    })-[protects:AG_PROTECTS]->(entity:AGScopedEntity {
        vault_id: $vault_id,
        entity_id: $entity_id
    })
    WHERE
        scope.scope_id IN $allowed_scope_ids
        AND scope.root_key_version = vault.key_version
        AND entity.scope_id = scope.scope_id
        AND coalesce(entity.record_revision, 1)
            = $expected_record_revision
        AND NOT EXISTS {
            MATCH (entity)-[:AG_SCOPED_LINK]-()
        }
    DELETE protects, entity
    RETURN 1 AS deleted
    """

    _DELETE_SCOPED_RELATIONSHIP = """
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
        relationship_scope:AGProtectionScope {vault_id: $vault_id}
    )
    MATCH (vault)-[:AG_HAS_SCOPE]->(source_scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(source:AGScopedEntity {vault_id: $vault_id})
    MATCH (vault)-[:AG_HAS_SCOPE]->(target_scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(target:AGScopedEntity {vault_id: $vault_id})
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
        AND coalesce(link.record_revision, 1)
            = $expected_record_revision
    DELETE link
    RETURN 1 AS deleted
    """

    _DELETE_SCOPED_RELATIONSHIP_BUNDLE = """
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
        relationship_scope:AGProtectionScope {vault_id: $vault_id}
    )
    MATCH (vault)-[:AG_HAS_SCOPE]->(source_scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(source:AGScopedEntity {vault_id: $vault_id})
    MATCH (vault)-[:AG_HAS_SCOPE]->(target_scope:AGProtectionScope {
        vault_id: $vault_id
    })-[:AG_PROTECTS]->(target:AGScopedEntity {vault_id: $vault_id})
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
        AND coalesce(link.record_revision, 1)
            = $expected_record_revision
    WITH relationship_scope, source, target, link
    MATCH (relationship_scope)-[protects:AG_PROTECTS]->(
        helper:AGScopedEntity {vault_id: $vault_id}
    )
    WHERE
        helper.entity_id IN $helper_entity_ids
        AND helper.scope_id = relationship_scope.scope_id
        AND helper.entity_id IN [source.entity_id, target.entity_id]
    WITH
        link,
        collect(DISTINCT helper) AS helpers,
        collect(DISTINCT protects) AS protections
    WHERE
        size(helpers) = size($helper_entity_ids)
        AND size(protections) = size($helper_entity_ids)
        AND all(helper IN helpers WHERE NOT EXISTS {
            MATCH (helper)-[other:AG_SCOPED_LINK]-()
            WHERE other.relationship_id <> $relationship_id
        })
    DELETE link
    FOREACH (protection IN protections | DELETE protection)
    FOREACH (helper IN helpers | DELETE helper)
    RETURN 1 AS deleted, size(helpers) AS helpers_deleted
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
                record_revision: coalesce(entity.record_revision, 1),
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
                record_revision: coalesce(link.record_revision, 1),
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

    _GET_SCOPED_TARGETED_SNAPSHOT = """
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
                AND (
                    entity.entity_id IN $entity_ids
                    OR EXISTS {
                        MATCH (entity)-[selected:AG_SCOPED_LINK {
                            vault_id: $vault_id
                        }]-(other:AGScopedEntity {
                            vault_id: $vault_id
                        })
                        MATCH (vault)-[:AG_HAS_SCOPE]->(
                            selected_scope:AGProtectionScope {
                                vault_id: $vault_id
                            }
                        )
                        MATCH (vault)-[:AG_HAS_SCOPE]->(
                            other_scope:AGProtectionScope {
                                vault_id: $vault_id
                            }
                        )-[:AG_PROTECTS]->(other)
                        WHERE
                            selected.relationship_id
                                IN $relationship_ids
                            AND selected.scope_id
                                = selected_scope.scope_id
                            AND selected_scope.scope_id
                                IN $allowed_scope_ids
                            AND selected_scope.root_key_version
                                = vault.key_version
                            AND other.scope_id = other_scope.scope_id
                            AND other_scope.scope_id
                                IN $allowed_scope_ids
                            AND other_scope.root_key_version
                                = vault.key_version
                    }
                )
            WITH scope, entity
            ORDER BY entity.entity_id
            LIMIT $entity_fetch_limit
            RETURN {
                vault_id: entity.vault_id,
                scope_id: entity.scope_id,
                entity_id: entity.entity_id,
                record_revision: coalesce(entity.record_revision, 1),
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
                link.relationship_id IN $relationship_ids
                AND relationship_scope.scope_id = link.scope_id
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
                record_revision: coalesce(link.record_revision, 1),
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
    def _valid_target_ids(values: object, *, maximum: int) -> bool:
        if not isinstance(values, tuple) or len(values) > maximum:
            return False
        try:
            return (
                all(
                isinstance(value, str)
                and value
                and len(value) <= MAX_OPAQUE_ID_CHARS
                and not any(
                    unicodedata.category(char).startswith("C")
                    for char in value
                )
                    for value in values
                )
                and len(set(values)) == len(values)
            )
        except TypeError:
            return False

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

    @staticmethod
    def _valid_record_revision(value: object) -> bool:
        return type(value) is int and value > 0

    @staticmethod
    def _record_revision(record: Any) -> int:
        """Decode a revision, treating pre-CRUD rows as revision one."""

        try:
            value = record["record_revision"]
        except (KeyError, TypeError, IndexError):
            value = 1
        if not Neo4jScopedGraphRepository._valid_record_revision(value):
            raise IntegrityViolation()
        return value

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
            record_revision=self._record_revision(record),
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
            record_revision=self._record_revision(record),
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
            or row.record_revision != 1
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
                    record_revision=row.record_revision,
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
            or row.record_revision != 1
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
            "record_revision": row.record_revision,
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
            existing = self.get_scoped_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                row.relationship_id,
            )
            if existing == row:
                return True
            raise
        if first is not None and self._record_integer(first, "created") == 1:
            return True
        return (
            self.get_scoped_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                row.relationship_id,
            )
            == row
        )

    def put_scoped_entity_relationship_bundle(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_rows: tuple[ScopedEncryptedEntityRow, ...],
        relationship_row: ScopedEncryptedRelationshipRow,
    ) -> bool:
        if (
            not isinstance(entity_rows, tuple)
            or any(
                not isinstance(row, ScopedEncryptedEntityRow)
                for row in entity_rows
            )
            or not isinstance(
                relationship_row,
                ScopedEncryptedRelationshipRow,
            )
        ):
            return False
        entity_ids = tuple(row.entity_id for row in entity_rows)
        endpoint_ids = {
            relationship_row.from_entity_id,
            relationship_row.to_entity_id,
        }
        if (
            not self._valid_scope_ids(allowed_scope_ids)
            or not 1 <= len(entity_rows) <= 2
            or len(entity_ids) != len(set(entity_ids))
            or not set(entity_ids).issubset(endpoint_ids)
            or relationship_row.vault_id != vault_id
            or relationship_row.scope_id not in allowed_scope_ids
            or relationship_row.record_revision != 1
            or not self._valid_scoped_payload(relationship_row.payload)
            or any(
                not isinstance(row, ScopedEncryptedEntityRow)
                or row.vault_id != vault_id
                or row.scope_id != relationship_row.scope_id
                or row.record_revision != 1
                or not self._valid_scoped_payload(row.payload)
                or row.payload.key_version
                != relationship_row.payload.key_version
                for row in entity_rows
            )
        ):
            return False

        entity_parameters = [
            {
                "scope_id": row.scope_id,
                "entity_id": row.entity_id,
                "record_revision": row.record_revision,
                **self._payload_parameters(row.payload),
            }
            for row in entity_rows
        ]
        relationship_payload = self._payload_parameters(
            relationship_row.payload
        )
        parameters = {
            "principal_id": principal_id,
            "vault_id": vault_id,
            "envelope_revision": envelope_revision,
            "allowed_scope_ids": list(allowed_scope_ids),
            "scope_id": relationship_row.scope_id,
            "entity_rows": entity_parameters,
            "relationship_id": relationship_row.relationship_id,
            "from_entity_id": relationship_row.from_entity_id,
            "to_entity_id": relationship_row.to_entity_id,
            "relationship_record_revision": (
                relationship_row.record_revision
            ),
            "relationship_payload_version": relationship_payload[
                "payload_version"
            ],
            "relationship_key_version": relationship_payload[
                "key_version"
            ],
            "relationship_algorithm": relationship_payload["algorithm"],
            "relationship_nonce": relationship_payload["nonce"],
            "relationship_ciphertext": relationship_payload["ciphertext"],
        }
        try:
            first = self._first(
                self._execute(
                    self._PUT_SCOPED_ENTITY_RELATIONSHIP_BUNDLE,
                    **parameters,
                )
            )
        except IncompleteCommit:
            if self._scoped_bundle_is_exact(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                entity_rows,
                relationship_row,
            ):
                return True
            raise
        if (
            first is not None
            and self._record_integer(first, "created_entities")
            == len(entity_rows)
            and self._record_integer(first, "created_relationships") == 1
        ):
            return True
        return self._scoped_bundle_is_exact(
            principal_id,
            vault_id,
            envelope_revision,
            allowed_scope_ids,
            entity_rows,
            relationship_row,
        )

    def _scoped_bundle_is_exact(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_rows: tuple[ScopedEncryptedEntityRow, ...],
        relationship_row: ScopedEncryptedRelationshipRow,
    ) -> bool:
        for row in entity_rows:
            if (
                self.get_scoped_entity(
                    principal_id,
                    vault_id,
                    envelope_revision,
                    allowed_scope_ids,
                    row.entity_id,
                )
                != row
            ):
                return False
        return (
            self.get_scoped_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                relationship_row.relationship_id,
            )
            == relationship_row
        )

    def get_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        relationship_id: str,
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
            or row.scope_id not in allowed_scope_ids
            or from_scope_id not in allowed_scope_ids
            or to_scope_id not in allowed_scope_ids
        ):
            raise IntegrityViolation()
        return row

    def replace_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        expected_record_revision: int,
        row: ScopedEncryptedEntityRow,
    ) -> bool:
        if (
            not isinstance(row, ScopedEncryptedEntityRow)
            or row.vault_id != vault_id
            or not self._valid_scope_ids(allowed_scope_ids)
            or row.scope_id not in allowed_scope_ids
            or not self._valid_scoped_payload(row.payload)
            or not self._valid_record_revision(expected_record_revision)
            or row.record_revision != expected_record_revision + 1
        ):
            return False
        parameters = {
            "principal_id": principal_id,
            "vault_id": vault_id,
            "envelope_revision": envelope_revision,
            "allowed_scope_ids": list(allowed_scope_ids),
            "expected_record_revision": expected_record_revision,
            "record_revision": row.record_revision,
            "scope_id": row.scope_id,
            "entity_id": row.entity_id,
            **self._payload_parameters(row.payload),
        }
        try:
            first = self._first(
                self._execute(self._REPLACE_SCOPED_ENTITY, **parameters)
            )
        except IncompleteCommit:
            existing = self.get_scoped_entity(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                row.entity_id,
            )
            if existing == row:
                return True
            raise
        if first is not None and self._record_integer(first, "updated") == 1:
            return True
        return (
            self.get_scoped_entity(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                row.entity_id,
            )
            == row
        )

    def replace_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        expected_record_revision: int,
        row: ScopedEncryptedRelationshipRow,
    ) -> bool:
        if (
            not isinstance(row, ScopedEncryptedRelationshipRow)
            or row.vault_id != vault_id
            or not self._valid_scope_ids(allowed_scope_ids)
            or row.scope_id not in allowed_scope_ids
            or not self._valid_scoped_payload(row.payload)
            or not self._valid_record_revision(expected_record_revision)
            or row.record_revision != expected_record_revision + 1
        ):
            return False
        parameters = {
            "principal_id": principal_id,
            "vault_id": vault_id,
            "envelope_revision": envelope_revision,
            "allowed_scope_ids": list(allowed_scope_ids),
            "expected_record_revision": expected_record_revision,
            "record_revision": row.record_revision,
            "scope_id": row.scope_id,
            "relationship_id": row.relationship_id,
            "from_entity_id": row.from_entity_id,
            "to_entity_id": row.to_entity_id,
            **self._payload_parameters(row.payload),
        }
        try:
            first = self._first(
                self._execute(
                    self._REPLACE_SCOPED_RELATIONSHIP,
                    **parameters,
                )
            )
        except IncompleteCommit:
            existing = self.get_scoped_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                row.relationship_id,
            )
            if existing == row:
                return True
            raise
        if first is not None and self._record_integer(first, "updated") == 1:
            return True
        return (
            self.get_scoped_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                row.relationship_id,
            )
            == row
        )

    def delete_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_id: str,
        expected_record_revision: int,
    ) -> bool:
        if (
            not self._valid_scope_ids(allowed_scope_ids)
            or not self._valid_record_revision(expected_record_revision)
        ):
            return False
        parameters = {
            "principal_id": principal_id,
            "vault_id": vault_id,
            "envelope_revision": envelope_revision,
            "allowed_scope_ids": list(allowed_scope_ids),
            "entity_id": entity_id,
            "expected_record_revision": expected_record_revision,
        }
        try:
            first = self._first(
                self._execute(self._DELETE_SCOPED_ENTITY, **parameters)
            )
        except IncompleteCommit:
            if (
                self.get_scoped_entity(
                    principal_id,
                    vault_id,
                    envelope_revision,
                    allowed_scope_ids,
                    entity_id,
                )
                is None
            ):
                return True
            raise
        return (
            first is not None
            and self._record_integer(first, "deleted") == 1
        )

    def delete_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        relationship_id: str,
        expected_record_revision: int,
    ) -> bool:
        if (
            not self._valid_scope_ids(allowed_scope_ids)
            or not self._valid_record_revision(expected_record_revision)
        ):
            return False
        parameters = {
            "principal_id": principal_id,
            "vault_id": vault_id,
            "envelope_revision": envelope_revision,
            "allowed_scope_ids": list(allowed_scope_ids),
            "relationship_id": relationship_id,
            "expected_record_revision": expected_record_revision,
        }
        try:
            first = self._first(
                self._execute(
                    self._DELETE_SCOPED_RELATIONSHIP,
                    **parameters,
                )
            )
        except IncompleteCommit:
            if (
                self.get_scoped_relationship(
                    principal_id,
                    vault_id,
                    envelope_revision,
                    allowed_scope_ids,
                    relationship_id,
                )
                is None
            ):
                return True
            raise
        return (
            first is not None
            and self._record_integer(first, "deleted") == 1
        )

    def delete_scoped_relationship_bundle(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        relationship_id: str,
        expected_record_revision: int,
        helper_entity_ids: tuple[str, ...],
    ) -> bool:
        if (
            not self._valid_scope_ids(allowed_scope_ids)
            or not self._valid_scope_ids((relationship_id,))
            or not self._valid_record_revision(expected_record_revision)
            or not isinstance(helper_entity_ids, tuple)
            or not 1 <= len(helper_entity_ids) <= 2
            or not self._valid_scope_ids(helper_entity_ids)
        ):
            return False
        parameters = {
            "principal_id": principal_id,
            "vault_id": vault_id,
            "envelope_revision": envelope_revision,
            "allowed_scope_ids": list(allowed_scope_ids),
            "relationship_id": relationship_id,
            "expected_record_revision": expected_record_revision,
            "helper_entity_ids": list(helper_entity_ids),
        }

        def bundle_is_absent() -> bool:
            relationship_absent = (
                self.get_scoped_relationship(
                    principal_id,
                    vault_id,
                    envelope_revision,
                    allowed_scope_ids,
                    relationship_id,
                )
                is None
            )
            helpers_absent = all(
                self.get_scoped_entity(
                    principal_id,
                    vault_id,
                    envelope_revision,
                    allowed_scope_ids,
                    helper_entity_id,
                )
                is None
                for helper_entity_id in helper_entity_ids
            )
            return relationship_absent and helpers_absent

        try:
            first = self._first(
                self._execute(
                    self._DELETE_SCOPED_RELATIONSHIP_BUNDLE,
                    **parameters,
                )
            )
        except IncompleteCommit:
            if bundle_is_absent():
                return True
            raise
        if first is not None:
            return (
                self._record_integer(first, "deleted") == 1
                and self._record_integer(first, "helpers_deleted")
                == len(helper_entity_ids)
            )
        return False

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

    def get_scoped_targeted_snapshot(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_ids: tuple[str, ...],
        relationship_ids: tuple[str, ...],
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
            raise ValueError("Targeted repository limits must be positive integers.")
        if (
            not self._valid_scope_ids(allowed_scope_ids)
            or not self._valid_target_ids(
                entity_ids,
                maximum=entity_limit,
            )
            or not self._valid_target_ids(
                relationship_ids,
                maximum=relationship_limit,
            )
        ):
            return None
        first = self._first(
            self._execute(
                self._GET_SCOPED_TARGETED_SNAPSHOT,
                principal_id=principal_id,
                vault_id=vault_id,
                envelope_revision=envelope_revision,
                allowed_scope_ids=list(allowed_scope_ids),
                entity_ids=list(entity_ids),
                relationship_ids=list(relationship_ids),
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
        returned_entity_ids = tuple(row.entity_id for row in entities)
        returned_relationship_ids = tuple(
            row.relationship_id for row in relationships
        )
        endpoint_ids = {
            endpoint_id
            for row in relationships
            for endpoint_id in (row.from_entity_id, row.to_entity_id)
        }
        allowed_entity_ids = set(entity_ids) | endpoint_ids
        if (
            len(set(returned_entity_ids)) != len(returned_entity_ids)
            or len(set(returned_relationship_ids))
            != len(returned_relationship_ids)
            or not set(returned_entity_ids).issubset(allowed_entity_ids)
            or not set(returned_relationship_ids).issubset(
                relationship_ids
            )
            or not endpoint_ids.issubset(returned_entity_ids)
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
