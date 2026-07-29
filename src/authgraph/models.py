"""Small immutable data structures shared by AuthGraph components."""

from __future__ import annotations

from dataclasses import dataclass, field
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
class AccessContext:
    """A bearer capability bound to an already authenticated principal.

    Its token is excluded from ``repr`` so routine debugging does not expose it.
    A web adapter should keep this token in a Secure, HttpOnly cookie and must
    never place it in an LLM prompt or tool arguments.
    """

    principal_id: str
    session_token: str = field(repr=False)
