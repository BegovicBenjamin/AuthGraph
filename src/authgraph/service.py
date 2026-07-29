"""Trusted AuthGraph broker.

Only this service receives transient vault keys. Repositories see ciphertext,
and a future AI integration should receive only explicitly selected plaintext
results—not a password, session token, DEK, database credential, or raw Cypher.
"""

from __future__ import annotations

import secrets
import unicodedata
from collections.abc import Mapping
from typing import Any

from .crypto import CryptoEngine, clear_bytearray
from .errors import (
    ConflictError,
    IntegrityViolation,
    RecordNotFound,
    UnlockDenied,
    ValidationError,
)
from .models import (
    AccessContext,
    EncryptedEntityRow,
    EncryptedRelationshipRow,
    Entity,
    Neighborhood,
    Relationship,
    VaultSnapshot,
    VaultRow,
)
from .repository import GraphRepository
from .sessions import InMemorySessionBroker, SessionLease


MAX_ID_CHARS = 256
MAX_KIND_CHARS = 128
MAX_NEIGHBORHOOD_SIZE = 100
MAX_VAULT_SNAPSHOT_ENTITIES = 100
MAX_VAULT_SNAPSHOT_RELATIONSHIPS = 200
MAX_VAULT_SNAPSHOT_CIPHERTEXT_BYTES = 256 * 1024


def _validate_opaque_id(value: str, description: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_ID_CHARS
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ValidationError(description)


def _validate_opaque_principal_id(principal_id: str) -> None:
    _validate_opaque_id(
        principal_id,
        "principal_id must be a non-PII, opaque identity-provider identifier.",
    )


def _validate_opaque_vault_id(vault_id: str) -> None:
    _validate_opaque_id(vault_id, "Invalid opaque vault identifier.")


def _validate_opaque_object_id(object_id: str) -> None:
    _validate_opaque_id(object_id, "Invalid opaque graph object identifier.")


def _validate_kind(kind: str) -> None:
    if (
        not isinstance(kind, str)
        or not kind
        or len(kind) > MAX_KIND_CHARS
        or any(unicodedata.category(char).startswith("C") for char in kind)
    ):
        raise ValidationError("Entity and relationship kinds must be short text.")


def _copy_properties(properties: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(properties, Mapping):
        raise ValidationError("Properties must be supplied as a JSON object.")
    return dict(properties)


def _entity_aad(vault_id: str, entity_id: str) -> tuple[object, ...]:
    return ("entity", 1, vault_id, entity_id)


def _relationship_aad(
    vault_id: str,
    relationship_id: str,
    from_entity_id: str,
    to_entity_id: str,
) -> tuple[object, ...]:
    return (
        "relationship",
        1,
        vault_id,
        relationship_id,
        from_entity_id,
        to_entity_id,
    )


class AuthGraphService:
    """Owner-vault security API with no arbitrary graph access."""

    def __init__(
        self,
        repository: GraphRepository,
        crypto: CryptoEngine,
        sessions: InMemorySessionBroker,
    ) -> None:
        self._repository = repository
        self._crypto = crypto
        self._sessions = sessions

    def create_vault(
        self,
        principal_id: str,
        passphrase: bytes | bytearray | memoryview,
    ) -> str:
        """Create an empty encrypted vault owned by one authenticated principal."""

        _validate_opaque_principal_id(principal_id)
        for _ in range(3):
            vault_id = secrets.token_urlsafe(24)
            envelope, dek = self._crypto.provision_vault(
                principal_id,
                vault_id,
                passphrase,
            )
            try:
                created = self._repository.create_vault(
                    VaultRow(
                        principal_id=principal_id,
                        vault_id=vault_id,
                        envelope=envelope,
                    )
                )
            finally:
                clear_bytearray(dek)
            if created:
                return vault_id
        raise ConflictError("Could not allocate a unique opaque vault identifier.")

    def unlock(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
        *,
        ttl_seconds: int | None = None,
    ) -> AccessContext:
        """Unlock a vault into a short-lived session without retaining password."""

        try:
            _validate_opaque_principal_id(principal_id)
            _validate_opaque_vault_id(vault_id)
        except ValidationError:
            self._crypto.burn_failed_unlock(passphrase)
            raise UnlockDenied() from None
        with self._sessions.vault_guard(principal_id, vault_id):
            row = self._repository.get_vault(principal_id, vault_id)
            if row is None:
                self._crypto.burn_failed_unlock(passphrase)
                raise UnlockDenied()
            dek = self._crypto.unwrap_dek(
                principal_id,
                vault_id,
                passphrase,
                row.envelope,
            )
            try:
                return self._sessions.open(
                    principal_id,
                    vault_id,
                    dek,
                    envelope_revision=row.envelope.envelope_revision,
                    key_version=row.envelope.key_version,
                    ttl_seconds=ttl_seconds,
                )
            finally:
                clear_bytearray(dek)

    def lock(self, context: AccessContext) -> None:
        self._sessions.close(context)

    def change_passphrase(
        self,
        principal_id: str,
        vault_id: str,
        current_passphrase: bytes | bytearray | memoryview,
        new_passphrase: bytes | bytearray | memoryview,
    ) -> None:
        """Re-wrap the same DEK and revoke every existing session for the vault."""

        try:
            _validate_opaque_principal_id(principal_id)
            _validate_opaque_vault_id(vault_id)
        except ValidationError:
            self._crypto.burn_failed_unlock(current_passphrase)
            raise UnlockDenied() from None
        with self._sessions.vault_guard(principal_id, vault_id):
            row = self._repository.get_vault(principal_id, vault_id)
            if row is None:
                self._crypto.burn_failed_unlock(current_passphrase)
                raise UnlockDenied()
            dek = self._crypto.unwrap_dek(
                principal_id,
                vault_id,
                current_passphrase,
                row.envelope,
            )
            try:
                next_revision = row.envelope.envelope_revision + 1
                envelope = self._crypto.wrap_dek(
                    principal_id,
                    vault_id,
                    new_passphrase,
                    dek,
                    envelope_revision=next_revision,
                    key_version=row.envelope.key_version,
                )
                # Reserve/register only after validating the new passphrase,
                # but before the database commit, so broker capacity cannot
                # fail after changing the password.
                self._sessions.advance_envelope_revision(
                    principal_id,
                    vault_id,
                    row.envelope.envelope_revision,
                )
                try:
                    if not self._repository.replace_envelope(
                        principal_id,
                        vault_id,
                        row.envelope.envelope_revision,
                        envelope,
                    ):
                        raise UnlockDenied()
                    self._sessions.advance_envelope_revision(
                        principal_id,
                        vault_id,
                        next_revision,
                    )
                except Exception:
                    # The database commit may be unknown, or another worker may
                    # have won the CAS. Conservatively remove every local DEK
                    # session instead of retaining an ambiguously stale key.
                    self._sessions.revoke_vault(principal_id, vault_id)
                    raise
            finally:
                clear_bytearray(dek)

    def create_entity(
        self,
        context: AccessContext,
        kind: str,
        properties: Mapping[str, Any],
    ) -> str:
        """Encrypt an entity's semantic kind and all of its properties."""

        _validate_kind(kind)
        entity_properties = _copy_properties(properties)
        with self._sessions.guarded_lease(context) as lease:
            for _ in range(3):
                entity_id = secrets.token_urlsafe(24)
                encrypted = self._crypto.encrypt_json(
                    lease.dek,
                    {"kind": kind, "properties": entity_properties},
                    aad_parts=_entity_aad(lease.vault_id, entity_id),
                    key_version=lease.key_version,
                )
                created = self._repository.put_entity(
                    lease.principal_id,
                    lease.vault_id,
                    lease.envelope_revision,
                    EncryptedEntityRow(
                        vault_id=lease.vault_id,
                        entity_id=entity_id,
                        payload=encrypted,
                    ),
                )
                if created:
                    return entity_id
        raise ConflictError("Could not allocate a unique opaque entity identifier.")

    def get_entity(self, context: AccessContext, entity_id: str) -> Entity:
        _validate_opaque_object_id(entity_id)
        with self._sessions.guarded_lease(context) as lease:
            row = self._repository.get_entity(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                entity_id,
            )
            if row is None:
                raise RecordNotFound()
            return self._decrypt_entity(lease, row)

    def connect(
        self,
        context: AccessContext,
        from_entity_id: str,
        to_entity_id: str,
        kind: str,
        properties: Mapping[str, Any] | None = None,
    ) -> str:
        """Create a generic Neo4j edge with encrypted relationship semantics."""

        _validate_opaque_object_id(from_entity_id)
        _validate_opaque_object_id(to_entity_id)
        _validate_kind(kind)
        relationship_properties = (
            {} if properties is None else _copy_properties(properties)
        )
        with self._sessions.guarded_lease(context) as lease:
            for _ in range(3):
                relationship_id = secrets.token_urlsafe(24)
                encrypted = self._crypto.encrypt_json(
                    lease.dek,
                    {"kind": kind, "properties": relationship_properties},
                    aad_parts=_relationship_aad(
                        lease.vault_id,
                        relationship_id,
                        from_entity_id,
                        to_entity_id,
                    ),
                    key_version=lease.key_version,
                )
                created = self._repository.put_relationship(
                    lease.principal_id,
                    lease.vault_id,
                    lease.envelope_revision,
                    EncryptedRelationshipRow(
                        vault_id=lease.vault_id,
                        relationship_id=relationship_id,
                        from_entity_id=from_entity_id,
                        to_entity_id=to_entity_id,
                        payload=encrypted,
                    ),
                )
                if created:
                    return relationship_id
                # A collision is extraordinarily unlikely. An absent endpoint or
                # cross-vault ID must not reveal which object was unavailable.
                if (
                    self._repository.get_entity(
                        lease.principal_id,
                        lease.vault_id,
                        lease.envelope_revision,
                        from_entity_id,
                    )
                    is None
                    or self._repository.get_entity(
                        lease.principal_id,
                        lease.vault_id,
                        lease.envelope_revision,
                        to_entity_id,
                    )
                    is None
                ):
                    raise RecordNotFound()
        raise ConflictError(
            "Could not allocate a unique opaque relationship identifier."
        )

    def get_neighborhood(
        self,
        context: AccessContext,
        entity_id: str,
        *,
        limit: int = 25,
    ) -> Neighborhood:
        """Decrypt one bounded, owner-scoped neighborhood in trusted memory."""

        _validate_opaque_object_id(entity_id)
        if (
            type(limit) is not int
            or limit <= 0
            or limit > MAX_NEIGHBORHOOD_SIZE
        ):
            raise ValidationError(
                f"Neighborhood limit must be between 1 and "
                f"{MAX_NEIGHBORHOOD_SIZE}."
            )
        with self._sessions.guarded_lease(context) as lease:
            encrypted = self._repository.get_neighborhood(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                entity_id,
                limit=limit,
            )
            if encrypted is None:
                raise RecordNotFound()
            allowed_entity_ids = {
                encrypted.center.entity_id,
                *(row.entity_id for row in encrypted.neighbors),
            }
            if (
                encrypted.center.vault_id != lease.vault_id
                or any(
                    row.vault_id != lease.vault_id
                    for row in encrypted.neighbors
                )
                or any(
                    row.vault_id != lease.vault_id
                    or row.from_entity_id not in allowed_entity_ids
                    or row.to_entity_id not in allowed_entity_ids
                    or encrypted.center.entity_id
                    not in (row.from_entity_id, row.to_entity_id)
                    for row in encrypted.relationships
                )
            ):
                raise IntegrityViolation()
            center = self._decrypt_entity(lease, encrypted.center)
            neighbors = tuple(
                self._decrypt_entity(lease, row)
                for row in encrypted.neighbors
            )
            relationships = tuple(
                self._decrypt_relationship(lease, row)
                for row in encrypted.relationships
            )
            return Neighborhood(
                center=center,
                neighbors=neighbors,
                relationships=relationships,
            )

    def get_vault_snapshot(
        self,
        context: AccessContext,
        *,
        entity_limit: int = MAX_VAULT_SNAPSHOT_ENTITIES,
        relationship_limit: int = MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
    ) -> VaultSnapshot:
        """Decrypt one bounded, complete vault snapshot in trusted memory.

        This deliberately high-exposure operation is intended for explicit
        full-vault workflows. The caller owns the returned plaintext and must
        not persist or log it.
        """

        if (
            type(entity_limit) is not int
            or entity_limit <= 0
            or entity_limit > MAX_VAULT_SNAPSHOT_ENTITIES
            or type(relationship_limit) is not int
            or relationship_limit <= 0
            or relationship_limit > MAX_VAULT_SNAPSHOT_RELATIONSHIPS
        ):
            raise ValidationError(
                "Vault snapshot limits exceed the supported safety bounds."
            )
        with self._sessions.guarded_lease(context) as lease:
            encrypted = self._repository.get_vault_snapshot(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                entity_limit=entity_limit,
                relationship_limit=relationship_limit,
            )
            if encrypted is None:
                raise RecordNotFound()
            if (
                len(encrypted.entities) > entity_limit
                or len(encrypted.relationships) > relationship_limit
            ):
                raise ValidationError(
                    "The complete vault does not fit within snapshot limits."
                )
            try:
                ciphertext_bytes = sum(
                    len(row.payload.ciphertext)
                    for row in (
                        *encrypted.entities,
                        *encrypted.relationships,
                    )
                )
                for row in encrypted.entities:
                    _validate_opaque_object_id(row.entity_id)
                for row in encrypted.relationships:
                    _validate_opaque_object_id(row.relationship_id)
                    _validate_opaque_object_id(row.from_entity_id)
                    _validate_opaque_object_id(row.to_entity_id)
            except (
                AttributeError,
                OverflowError,
                TypeError,
                ValidationError,
            ):
                raise IntegrityViolation() from None
            if ciphertext_bytes > MAX_VAULT_SNAPSHOT_CIPHERTEXT_BYTES:
                raise ValidationError(
                    "The complete vault does not fit within snapshot limits."
                )
            entity_ids = {row.entity_id for row in encrypted.entities}
            relationship_ids = {
                row.relationship_id for row in encrypted.relationships
            }
            if (
                len(entity_ids) != len(encrypted.entities)
                or len(relationship_ids) != len(encrypted.relationships)
                or any(
                    row.vault_id != lease.vault_id
                    or row.from_entity_id not in entity_ids
                    or row.to_entity_id not in entity_ids
                    for row in encrypted.relationships
                )
                or any(
                    row.vault_id != lease.vault_id
                    for row in encrypted.entities
                )
            ):
                raise IntegrityViolation()
            entities = tuple(
                sorted(
                    (
                        self._decrypt_entity(lease, row)
                        for row in encrypted.entities
                    ),
                    key=lambda entity: entity.entity_id,
                )
            )
            relationships = tuple(
                sorted(
                    (
                        self._decrypt_relationship(lease, row)
                        for row in encrypted.relationships
                    ),
                    key=lambda relationship: relationship.relationship_id,
                )
            )
            return VaultSnapshot(
                entities=entities,
                relationships=relationships,
            )

    def _decrypt_entity(
        self,
        lease: SessionLease,
        row: EncryptedEntityRow,
    ) -> Entity:
        if (
            row.vault_id != lease.vault_id
            or row.payload.key_version != lease.key_version
        ):
            raise IntegrityViolation()
        decoded = self._crypto.decrypt_json(
            lease.dek,
            row.payload,
            aad_parts=_entity_aad(lease.vault_id, row.entity_id),
        )
        kind = decoded.get("kind")
        properties = decoded.get("properties")
        if not isinstance(kind, str) or not isinstance(properties, dict):
            raise IntegrityViolation()
        return Entity(
            entity_id=row.entity_id,
            kind=kind,
            properties=properties,
        )

    def _decrypt_relationship(
        self,
        lease: SessionLease,
        row: EncryptedRelationshipRow,
    ) -> Relationship:
        if (
            row.vault_id != lease.vault_id
            or row.payload.key_version != lease.key_version
        ):
            raise IntegrityViolation()
        decoded = self._crypto.decrypt_json(
            lease.dek,
            row.payload,
            aad_parts=_relationship_aad(
                lease.vault_id,
                row.relationship_id,
                row.from_entity_id,
                row.to_entity_id,
            ),
        )
        kind = decoded.get("kind")
        properties = decoded.get("properties")
        if not isinstance(kind, str) or not isinstance(properties, dict):
            raise IntegrityViolation()
        return Relationship(
            relationship_id=row.relationship_id,
            from_entity_id=row.from_entity_id,
            to_entity_id=row.to_entity_id,
            kind=kind,
            properties=properties,
        )
