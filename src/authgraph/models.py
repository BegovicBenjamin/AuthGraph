"""Small immutable data structures shared by AuthGraph components."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class KdfParameters:
    """Versioned Argon2id parameters stored alongside a wrapped key."""

    algorithm: str = "argon2id"
    memory_cost_kib: int = 64 * 1024
    iterations: int = 3
    lanes: int = 1
    output_length: int = 32

    @classmethod
    def insecure_for_testing(cls) -> KdfParameters:
        """Return deliberately weak, fast parameters for unit tests only."""

        return cls(memory_cost_kib=1024, iterations=1, lanes=1)


@dataclass(frozen=True, slots=True)
class KeyEnvelope:
    """A random vault DEK wrapped by a passphrase-derived KEK."""

    version: int
    envelope_revision: int
    key_version: int
    wrapping_algorithm: str
    kdf: KdfParameters
    salt: bytes
    nonce: bytes
    wrapped_dek: bytes


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    """An authenticated ciphertext stored as a Neo4j property."""

    version: int
    key_version: int
    algorithm: str
    nonce: bytes
    ciphertext: bytes


@dataclass(frozen=True, slots=True)
class VaultRow:
    """Opaque vault metadata. ``principal_id`` must be an IdP identifier, not PII."""

    principal_id: str
    vault_id: str
    envelope: KeyEnvelope


@dataclass(frozen=True, slots=True)
class EncryptedEntityRow:
    vault_id: str
    entity_id: str
    payload: EncryptedPayload


@dataclass(frozen=True, slots=True)
class EncryptedRelationshipRow:
    vault_id: str
    relationship_id: str
    from_entity_id: str
    to_entity_id: str
    payload: EncryptedPayload


@dataclass(frozen=True, slots=True)
class EncryptedNeighborhoodRow:
    center: EncryptedEntityRow
    neighbors: tuple[EncryptedEntityRow, ...]
    relationships: tuple[EncryptedRelationshipRow, ...]


@dataclass(frozen=True, slots=True)
class EncryptedVaultSnapshotRow:
    """A bounded ciphertext snapshot fetched under one vault revision."""

    entities: tuple[EncryptedEntityRow, ...]
    relationships: tuple[EncryptedRelationshipRow, ...]


@dataclass(frozen=True, slots=True)
class ScopeKeyEnvelope:
    """One random protection-scope DEK wrapped by the vault root DEK."""

    version: int
    root_key_version: int
    scope_key_version: int
    algorithm: str
    nonce: bytes
    wrapped_scope_dek: bytes


@dataclass(frozen=True, slots=True)
class ProtectionScopeRow:
    """Opaque protection scope stored under one owner vault."""

    vault_id: str
    scope_id: str
    envelope: ScopeKeyEnvelope


@dataclass(frozen=True, slots=True)
class ScopedEncryptedEntityRow:
    vault_id: str
    scope_id: str
    entity_id: str
    payload: EncryptedPayload
    record_revision: int = 1


@dataclass(frozen=True, slots=True)
class ScopedEncryptedRelationshipRow:
    vault_id: str
    scope_id: str
    relationship_id: str
    from_entity_id: str
    to_entity_id: str
    payload: EncryptedPayload
    record_revision: int = 1


@dataclass(frozen=True, slots=True)
class ScopedEncryptedVaultSnapshotRow:
    """A bounded ciphertext snapshot from only session-granted scopes."""

    entities: tuple[ScopedEncryptedEntityRow, ...]
    relationships: tuple[ScopedEncryptedRelationshipRow, ...]


class ProtectionLevel(StrEnum):
    """Application-layer storage choice for a graph record.

    ``PUBLIC`` bypasses AuthGraph application encryption. Its semantic kind
    and properties are plaintext to Neo4j readers and database backups.
    """

    PRIVATE = "private"
    PUBLIC = "public"


class LockedDisclosure(StrEnum):
    """What a locked graph view may reveal about its private overlay."""

    HIDDEN = "hidden"
    GENERIC_BADGE = "generic_badge"


@dataclass(frozen=True, slots=True)
class GraphPolicy:
    """Defaults and allowed overrides for one layered knowledge graph.

    ``PRIVATE`` is deliberately the default for both entities and
    relationships. A generic badge, when enabled, is policy-driven and does
    not reveal whether the encrypted overlay contains any records.
    """

    default_entity_protection: ProtectionLevel = ProtectionLevel.PRIVATE
    default_relationship_protection: ProtectionLevel = ProtectionLevel.PRIVATE
    allow_public_overrides: bool = False
    locked_disclosure: LockedDisclosure = LockedDisclosure.HIDDEN


@dataclass(frozen=True, slots=True)
class PublicEntityRow:
    """Plaintext application-layer data in a named public graph."""

    graph_id: str
    entity_id: str
    kind: str
    properties: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class PublicRelationshipRow:
    """A plaintext relationship whose endpoints are both public."""

    graph_id: str
    relationship_id: str
    from_entity_id: str
    to_entity_id: str
    kind: str
    properties: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class PublicGraphSnapshotRow:
    """A bounded public graph snapshot."""

    entities: tuple[PublicEntityRow, ...]
    relationships: tuple[PublicRelationshipRow, ...]


@dataclass(frozen=True, slots=True)
class Entity:
    entity_id: str
    kind: str
    properties: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Relationship:
    relationship_id: str
    from_entity_id: str
    to_entity_id: str
    kind: str
    properties: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Neighborhood:
    center: Entity
    neighbors: tuple[Entity, ...]
    relationships: tuple[Relationship, ...]


@dataclass(frozen=True, slots=True)
class VaultSnapshot:
    """Decrypted vault contents that callers must treat as highly sensitive."""

    entities: tuple[Entity, ...]
    relationships: tuple[Relationship, ...]


@dataclass(frozen=True, slots=True)
class ScopedEntity:
    """Decrypted entity plus its opaque cryptographic protection scope."""

    entity_id: str
    scope_id: str
    kind: str
    properties: Mapping[str, Any]
    record_revision: int = 1


@dataclass(frozen=True, slots=True)
class ScopedRelationship:
    """Decrypted relationship plus its own protection scope."""

    relationship_id: str
    scope_id: str
    from_entity_id: str
    to_entity_id: str
    kind: str
    properties: Mapping[str, Any]
    record_revision: int = 1


@dataclass(frozen=True, slots=True)
class ScopedVaultSnapshot:
    """Plaintext from only the scopes granted to one secure session."""

    entities: tuple[ScopedEntity, ...]
    relationships: tuple[ScopedRelationship, ...]


@dataclass(frozen=True, slots=True)
class GraphEntityRef:
    """A typed reference used when building a layered graph."""

    graph_id: str
    entity_id: str
    protection: ProtectionLevel


@dataclass(frozen=True, slots=True)
class GraphRelationshipRef:
    """A typed reference to a layered graph relationship."""

    graph_id: str
    relationship_id: str
    protection: ProtectionLevel


@dataclass(frozen=True, slots=True)
class LayeredEntity:
    entity_id: str
    kind: str
    properties: Mapping[str, Any]
    protection: ProtectionLevel


@dataclass(frozen=True, slots=True)
class LayeredRelationship:
    relationship_id: str
    from_entity_id: str
    to_entity_id: str
    kind: str
    properties: Mapping[str, Any]
    protection: ProtectionLevel


@dataclass(frozen=True, slots=True)
class LayeredGraphView:
    """Public base graph, optionally composed with one unlocked private overlay."""

    graph_id: str
    entities: tuple[LayeredEntity, ...]
    relationships: tuple[LayeredRelationship, ...]
    private_overlay_included: bool
    locked_disclosure: LockedDisclosure


@dataclass(frozen=True, slots=True)
class AccessContext:
    """A bearer capability bound to an already authenticated principal.

    Its token is excluded from ``repr`` so routine debugging does not expose it.
    A web adapter should keep this token in a Secure, HttpOnly cookie and must
    never place it in an LLM prompt or tool arguments.
    """

    principal_id: str
    session_token: str = field(repr=False)
