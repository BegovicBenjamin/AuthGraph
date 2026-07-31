"""Independent protection-scope encryption for AuthGraph v2 vaults."""

from __future__ import annotations

import base64
import hmac
import json
import secrets
import math
import time
import unicodedata
from collections.abc import Mapping
from typing import Any, Callable

from .crypto import CryptoEngine, clear_bytearray
from .errors import (
    AuthorizationDenied,
    ConflictError,
    IntegrityViolation,
    RecordNotFound,
    UnlockDenied,
    ValidationError,
)
from .models import (
    AccessContext,
    ProtectionScopeRow,
    ScopedEncryptedEntityRow,
    ScopedEncryptedRelationshipRow,
    ScopedEntity,
    ScopedRelationship,
    ScopedVaultSnapshot,
    VaultRow,
)
from .repository import ScopedGraphRepository
from .scoped_crypto import (
    generate_scope_dek,
    unwrap_scope_dek,
    wrap_scope_dek,
)
from .scoped_sessions import (
    MAX_SCOPES_PER_SESSION,
    ScopeKeyMaterial,
    ScopedKeyLease,
    ScopedSessionBroker,
    ScopedSessionLease,
)
from .service import (
    MAX_ID_CHARS,
    MAX_KIND_CHARS,
    MAX_VAULT_SNAPSHOT_CIPHERTEXT_BYTES,
    MAX_VAULT_SNAPSHOT_ENTITIES,
    MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
)
from .unlock_policy import (
    ReleasedScopeKeys,
    ScopeGrantDenied,
    ScopeGrantPolicy,
    ScopeKeyEnrollmentProvider,
    ScopeKeyReleaseProvider,
    ScopeUnlockGrant,
)


SCOPED_PAYLOAD_VERSION = 2
MAX_IDEMPOTENCY_KEY_CHARS = 256


def _validate_opaque_id(value: str, message: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_ID_CHARS
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ValidationError(message)


def _validate_principal_id(principal_id: str) -> None:
    _validate_opaque_id(
        principal_id,
        "principal_id must be a non-PII, opaque identity-provider identifier.",
    )


def _validate_vault_id(vault_id: str) -> None:
    _validate_opaque_id(vault_id, "Invalid opaque vault identifier.")


def _validate_scope_id(scope_id: str) -> None:
    _validate_opaque_id(
        scope_id,
        "Invalid opaque protection-scope identifier.",
    )


def _validate_object_id(object_id: str) -> None:
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


def _validate_record_revision(record_revision: int) -> None:
    if type(record_revision) is not int or record_revision <= 0:
        raise ValidationError("Record revision must be a positive integer.")


def _validate_idempotency_key(idempotency_key: str) -> None:
    if (
        not isinstance(idempotency_key, str)
        or not idempotency_key
        or len(idempotency_key) > MAX_IDEMPOTENCY_KEY_CHARS
        or any(
            unicodedata.category(char).startswith("C")
            for char in idempotency_key
        )
    ):
        raise ValidationError("Invalid opaque idempotency key.")


def _idempotent_object_id(
    scope_dek: bytearray,
    *,
    operation: str,
    principal_id: str,
    vault_id: str,
    scope_id: str,
    idempotency_key: str,
) -> str:
    """Derive an unlinkable stable ID without persisting the request key."""

    _validate_idempotency_key(idempotency_key)
    message = json.dumps(
        [
            "authgraph",
            "scoped-idempotency",
            1,
            operation,
            principal_id,
            vault_id,
            scope_id,
            idempotency_key,
        ],
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hmac.digest(scope_dek, message, "sha256")
    encoded = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    prefix = "entity" if operation == "create-entity" else "relationship"
    return f"scoped_{prefix}_{encoded}"


def _semantic_payload(
    kind: str,
    properties: Mapping[str, Any],
    *,
    record_revision: int,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "properties": dict(properties),
        "record_revision": record_revision,
    }


def _entity_aad(
    principal_id: str,
    vault_id: str,
    scope_id: str,
    entity_id: str,
) -> tuple[object, ...]:
    return (
        "scoped-entity",
        SCOPED_PAYLOAD_VERSION,
        principal_id,
        vault_id,
        scope_id,
        entity_id,
    )


def _relationship_aad(
    principal_id: str,
    vault_id: str,
    relationship_scope_id: str,
    relationship_id: str,
    from_entity_id: str,
    from_scope_id: str,
    to_entity_id: str,
    to_scope_id: str,
) -> tuple[object, ...]:
    return (
        "scoped-relationship",
        SCOPED_PAYLOAD_VERSION,
        principal_id,
        vault_id,
        relationship_scope_id,
        relationship_id,
        from_entity_id,
        from_scope_id,
        to_entity_id,
        to_scope_id,
    )


class ScopedAuthGraphService:
    """A v2 vault whose normal sessions contain only granted scope keys.

    Scope IDs are low-level trusted-backend inputs. An application must map a
    verified disclosure policy to those IDs outside model tool arguments.
    """

    def __init__(
        self,
        repository: ScopedGraphRepository,
        crypto: CryptoEngine,
        sessions: ScopedSessionBroker,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable.")
        self._repository = repository
        self._crypto = crypto
        self._sessions = sessions
        self._clock = clock

    def create_vault(
        self,
        principal_id: str,
        passphrase: bytes | bytearray | memoryview,
    ) -> str:
        """Create an empty v2 vault with no protection scopes."""

        _validate_principal_id(principal_id)
        for _ in range(3):
            vault_id = f"v2_{secrets.token_urlsafe(24)}"
            envelope, vault_wrapping_key = (
                self._crypto.provision_scoped_vault(
                    principal_id,
                    vault_id,
                    passphrase,
                )
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
                clear_bytearray(vault_wrapping_key)
            if created:
                return vault_id
        raise ConflictError("Could not allocate a unique opaque vault identifier.")

    def create_protection_scope(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
    ) -> str:
        """Create one independently random scope key under a v2 vault."""

        try:
            _validate_principal_id(principal_id)
            _validate_vault_id(vault_id)
        except ValidationError:
            self._crypto.burn_failed_unlock(passphrase)
            raise UnlockDenied() from None
        with self._sessions.vault_guard(principal_id, vault_id):
            vault = self._repository.get_vault(principal_id, vault_id)
            if vault is None:
                self._crypto.burn_failed_unlock(passphrase)
                raise UnlockDenied()
            vault_wrapping_key = self._crypto.unwrap_scoped_vault_key(
                principal_id,
                vault_id,
                passphrase,
                vault.envelope,
            )
            try:
                for _ in range(3):
                    scope_id = f"scope_{secrets.token_urlsafe(24)}"
                    scope_dek = generate_scope_dek()
                    try:
                        envelope = wrap_scope_dek(
                            vault_wrapping_key,
                            scope_dek,
                            principal_id=principal_id,
                            vault_id=vault_id,
                            scope_id=scope_id,
                            root_key_version=vault.envelope.key_version,
                        )
                    finally:
                        clear_bytearray(scope_dek)
                    if self._repository.put_protection_scope(
                        principal_id,
                        vault_id,
                        vault.envelope.envelope_revision,
                        ProtectionScopeRow(
                            vault_id=vault_id,
                            scope_id=scope_id,
                            envelope=envelope,
                        ),
                    ):
                        return scope_id
            finally:
                clear_bytearray(vault_wrapping_key)
        raise ConflictError(
            "Could not allocate a unique protection-scope identifier."
        )

    @staticmethod
    def _validated_scope_ids(scope_ids: tuple[str, ...]) -> tuple[str, ...]:
        if (
            not isinstance(scope_ids, tuple)
            or not scope_ids
            or len(scope_ids) > MAX_SCOPES_PER_SESSION
        ):
            raise ValidationError("Invalid protection-scope grant.")
        for scope_id in scope_ids:
            _validate_scope_id(scope_id)
        if len(set(scope_ids)) != len(scope_ids):
            raise ValidationError("Invalid protection-scope grant.")
        return scope_ids

    def unlock(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
        scope_ids: tuple[str, ...],
        *,
        ttl_seconds: int | None = None,
    ) -> AccessContext:
        """Unlock exactly the trusted application's requested scope set."""

        try:
            _validate_principal_id(principal_id)
            _validate_vault_id(vault_id)
            requested_scope_ids = self._validated_scope_ids(scope_ids)
        except ValidationError:
            self._crypto.burn_failed_unlock(passphrase)
            raise UnlockDenied() from None
        with self._sessions.vault_guard(principal_id, vault_id):
            vault = self._repository.get_vault(principal_id, vault_id)
            if vault is None:
                self._crypto.burn_failed_unlock(passphrase)
                raise UnlockDenied()
            vault_wrapping_key = self._crypto.unwrap_scoped_vault_key(
                principal_id,
                vault_id,
                passphrase,
                vault.envelope,
            )
            materials: dict[str, ScopeKeyMaterial] = {}
            try:
                rows = self._repository.get_protection_scopes(
                    principal_id,
                    vault_id,
                    vault.envelope.envelope_revision,
                    requested_scope_ids,
                )
                if rows is None:
                    raise UnlockDenied()
                by_scope = {row.scope_id: row for row in rows}
                if (
                    len(rows) != len(by_scope)
                    or set(by_scope) != set(requested_scope_ids)
                    or any(row.vault_id != vault_id for row in rows)
                ):
                    raise UnlockDenied()
                for scope_id in requested_scope_ids:
                    row = by_scope[scope_id]
                    scope_dek = unwrap_scope_dek(
                        vault_wrapping_key,
                        row.envelope,
                        principal_id=principal_id,
                        vault_id=vault_id,
                        scope_id=scope_id,
                        expected_root_key_version=vault.envelope.key_version,
                    )
                    materials[scope_id] = ScopeKeyMaterial(
                        key_version=row.envelope.scope_key_version,
                        dek=scope_dek,
                    )
                return self._sessions.open(
                    principal_id,
                    vault_id,
                    materials,
                    envelope_revision=vault.envelope.envelope_revision,
                    root_key_version=vault.envelope.key_version,
                    ttl_seconds=ttl_seconds,
                )
            finally:
                clear_bytearray(vault_wrapping_key)
                for material in materials.values():
                    clear_bytearray(material.dek)

    def enroll_key_release_provider(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
        scope_ids: tuple[str, ...],
        provider: ScopeKeyEnrollmentProvider,
    ) -> None:
        """Provision selected scope keys into a trusted KMS/HSM integration.

        The provider must wrap or copy every key before returning. AuthGraph
        clears all temporary mutable scope-key buffers in ``finally``.
        """

        if not isinstance(provider, ScopeKeyEnrollmentProvider):
            raise TypeError("provider must support scoped-key enrollment.")
        try:
            _validate_principal_id(principal_id)
            _validate_vault_id(vault_id)
            requested_scope_ids = self._validated_scope_ids(scope_ids)
        except ValidationError:
            self._crypto.burn_failed_unlock(passphrase)
            raise UnlockDenied() from None
        materials: dict[str, ScopeKeyMaterial] = {}
        try:
            with self._sessions.vault_guard(principal_id, vault_id):
                vault = self._repository.get_vault(principal_id, vault_id)
                if vault is None:
                    self._crypto.burn_failed_unlock(passphrase)
                    raise UnlockDenied()
                vault_wrapping_key = self._crypto.unwrap_scoped_vault_key(
                    principal_id,
                    vault_id,
                    passphrase,
                    vault.envelope,
                )
                try:
                    rows = self._repository.get_protection_scopes(
                        principal_id,
                        vault_id,
                        vault.envelope.envelope_revision,
                        requested_scope_ids,
                    )
                    if rows is None:
                        raise UnlockDenied()
                    by_scope = {row.scope_id: row for row in rows}
                    if (
                        len(rows) != len(by_scope)
                        or set(by_scope) != set(requested_scope_ids)
                    ):
                        raise UnlockDenied()
                    for scope_id in requested_scope_ids:
                        row = by_scope[scope_id]
                        materials[scope_id] = ScopeKeyMaterial(
                            key_version=row.envelope.scope_key_version,
                            dek=unwrap_scope_dek(
                                vault_wrapping_key,
                                row.envelope,
                                principal_id=principal_id,
                                vault_id=vault_id,
                                scope_id=scope_id,
                                expected_root_key_version=(
                                    vault.envelope.key_version
                                ),
                            ),
                        )
                    envelope_revision = vault.envelope.envelope_revision
                    root_key_version = vault.envelope.key_version
                finally:
                    clear_bytearray(vault_wrapping_key)

            # Never call a provider while holding the vault guard. Providers
            # hold their own lifecycle locks during key enrollment/release.
            provider.enroll_scope_keys(
                principal_id=principal_id,
                vault_id=vault_id,
                envelope_revision=envelope_revision,
                root_key_version=root_key_version,
                scope_keys=materials,
            )
        finally:
            for material in materials.values():
                clear_bytearray(material.dek)

    def lock(self, context: AccessContext) -> None:
        self._sessions.close(context)

    def get_authorization_epoch(
        self,
        principal_id: str,
        vault_id: str,
    ) -> int:
        """Return the current v2 vault epoch for binding an auth challenge."""

        try:
            _validate_principal_id(principal_id)
            _validate_vault_id(vault_id)
        except ValidationError:
            raise UnlockDenied() from None
        vault = self._repository.get_vault(principal_id, vault_id)
        if vault is None or vault.envelope.version != SCOPED_PAYLOAD_VERSION:
            raise UnlockDenied()
        return vault.envelope.envelope_revision

    def unlock_with_provider(
        self,
        grant: ScopeUnlockGrant,
        grant_policy: ScopeGrantPolicy,
        provider: ScopeKeyReleaseProvider,
    ) -> AccessContext:
        """Consume a verified grant and open only provider-released scope keys.

        A production provider should unwrap KMS/HSM-backed key slots. One-time
        codes authorize the grant; they are never passed here as key material.
        """

        if (
            not isinstance(grant_policy, ScopeGrantPolicy)
            or not isinstance(provider, ScopeKeyReleaseProvider)
        ):
            raise ScopeGrantDenied()
        consumed = grant_policy.consume(grant)
        released: ReleasedScopeKeys | None = None
        materials: dict[str, ScopeKeyMaterial] = {}
        opened_context: AccessContext | None = None
        try:
            now = self._clock()
            if (
                type(now) not in (int, float)
                or not math.isfinite(now)
                or consumed.expires_at <= now
            ):
                raise ScopeGrantDenied()
            _validate_principal_id(consumed.principal_id)
            _validate_vault_id(consumed.vault_id)
            requested_scope_ids = self._validated_scope_ids(
                consumed.scope_ids
            )
            with provider.lease_scope_keys(consumed) as released:
                if (
                    not isinstance(released, ReleasedScopeKeys)
                    or not isinstance(released.scope_keys, Mapping)
                ):
                    raise ScopeGrantDenied()
                materials = dict(released.scope_keys)
                if set(materials) != set(requested_scope_ids):
                    raise ScopeGrantDenied()
                for scope_id, material in materials.items():
                    _validate_scope_id(scope_id)
                    if (
                        not isinstance(material, ScopeKeyMaterial)
                        or type(material.key_version) is not int
                        or material.key_version <= 0
                        or not isinstance(material.dek, bytearray)
                        or len(material.dek) != 32
                    ):
                        raise ScopeGrantDenied()
                vault = self._repository.get_vault(
                    consumed.principal_id,
                    consumed.vault_id,
                )
                after_release = self._clock()
                if (
                    vault is None
                    or vault.envelope.version != SCOPED_PAYLOAD_VERSION
                    or released.root_key_version
                    != vault.envelope.key_version
                    or consumed.authorization_epoch
                    != vault.envelope.envelope_revision
                    or type(after_release) not in (int, float)
                    or not math.isfinite(after_release)
                ):
                    raise ScopeGrantDenied()
                remaining_seconds = math.ceil(
                    consumed.expires_at - after_release
                )
                if remaining_seconds <= 0:
                    raise ScopeGrantDenied()
                opened_context = self._sessions.open(
                    consumed.principal_id,
                    consumed.vault_id,
                    materials,
                    envelope_revision=vault.envelope.envelope_revision,
                    root_key_version=released.root_key_version,
                    ttl_seconds=remaining_seconds,
                    not_after=consumed.expires_at,
                )
            if opened_context is None:
                raise ScopeGrantDenied()
            return opened_context
        except ScopeGrantDenied:
            if opened_context is not None:
                try:
                    self._sessions.close(opened_context)
                except Exception:
                    pass
            raise
        except Exception:
            if opened_context is not None:
                try:
                    self._sessions.close(opened_context)
                except Exception:
                    pass
            raise ScopeGrantDenied() from None
        finally:
            for material in materials.values():
                if isinstance(material, ScopeKeyMaterial):
                    clear_bytearray(material.dek)

    def change_passphrase(
        self,
        principal_id: str,
        vault_id: str,
        current_passphrase: bytes | bytearray | memoryview,
        new_passphrase: bytes | bytearray | memoryview,
    ) -> None:
        """Re-wrap only the v2 vault wrapping key and revoke local sessions."""

        try:
            _validate_principal_id(principal_id)
            _validate_vault_id(vault_id)
        except ValidationError:
            self._crypto.burn_failed_unlock(current_passphrase)
            raise UnlockDenied() from None
        with self._sessions.vault_guard(principal_id, vault_id):
            vault = self._repository.get_vault(principal_id, vault_id)
            if vault is None:
                self._crypto.burn_failed_unlock(current_passphrase)
                raise UnlockDenied()
            vault_wrapping_key = self._crypto.unwrap_scoped_vault_key(
                principal_id,
                vault_id,
                current_passphrase,
                vault.envelope,
            )
            try:
                next_revision = vault.envelope.envelope_revision + 1
                envelope = self._crypto.wrap_scoped_vault_key(
                    principal_id,
                    vault_id,
                    new_passphrase,
                    vault_wrapping_key,
                    envelope_revision=next_revision,
                    key_version=vault.envelope.key_version,
                )
                self._sessions.advance_envelope_revision(
                    principal_id,
                    vault_id,
                    vault.envelope.envelope_revision,
                )
                try:
                    if not self._repository.replace_envelope(
                        principal_id,
                        vault_id,
                        vault.envelope.envelope_revision,
                        envelope,
                    ):
                        raise UnlockDenied()
                    self._sessions.advance_envelope_revision(
                        principal_id,
                        vault_id,
                        next_revision,
                    )
                except Exception:
                    self._sessions.revoke_vault(principal_id, vault_id)
                    raise
            finally:
                clear_bytearray(vault_wrapping_key)

    @staticmethod
    def _require_scope(
        lease: ScopedSessionLease,
        scope_id: str,
    ) -> ScopedKeyLease:
        key = lease.scope_keys.get(scope_id)
        if key is None:
            raise AuthorizationDenied()
        return key

    def _get_relationship_record(
        self,
        lease: ScopedSessionLease,
        relationship_id: str,
    ) -> tuple[ScopedEncryptedRelationshipRow, str, str]:
        allowed_scope_ids = tuple(lease.scope_keys)
        row = self._repository.get_scoped_relationship(
            lease.principal_id,
            lease.vault_id,
            lease.envelope_revision,
            allowed_scope_ids,
            relationship_id,
        )
        if row is None:
            raise RecordNotFound()
        source = self._repository.get_scoped_entity(
            lease.principal_id,
            lease.vault_id,
            lease.envelope_revision,
            allowed_scope_ids,
            row.from_entity_id,
        )
        target = self._repository.get_scoped_entity(
            lease.principal_id,
            lease.vault_id,
            lease.envelope_revision,
            allowed_scope_ids,
            row.to_entity_id,
        )
        if source is None or target is None:
            raise IntegrityViolation()
        # Authenticate endpoint scope metadata before using it in relationship
        # AAD. Their semantic plaintext is discarded immediately.
        self._decrypt_entity(lease, source)
        self._decrypt_entity(lease, target)
        return row, source.scope_id, target.scope_id

    def create_entity(
        self,
        context: AccessContext,
        scope_id: str,
        kind: str,
        properties: Mapping[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> str:
        _validate_scope_id(scope_id)
        _validate_kind(kind)
        copied = _copy_properties(properties)
        if idempotency_key is not None:
            _validate_idempotency_key(idempotency_key)
        with self._sessions.guarded_lease(context) as lease:
            key = self._require_scope(lease, scope_id)
            attempts = 1 if idempotency_key is not None else 3
            for _ in range(attempts):
                entity_id = (
                    _idempotent_object_id(
                        key.dek,
                        operation="create-entity",
                        principal_id=lease.principal_id,
                        vault_id=lease.vault_id,
                        scope_id=scope_id,
                        idempotency_key=idempotency_key,
                    )
                    if idempotency_key is not None
                    else f"scoped_{secrets.token_urlsafe(24)}"
                )
                payload = self._crypto.encrypt_json(
                    key.dek,
                    _semantic_payload(
                        kind,
                        copied,
                        record_revision=1,
                    ),
                    aad_parts=_entity_aad(
                        lease.principal_id,
                        lease.vault_id,
                        scope_id,
                        entity_id,
                    ),
                    key_version=key.key_version,
                    payload_version=SCOPED_PAYLOAD_VERSION,
                )
                candidate = ScopedEncryptedEntityRow(
                    vault_id=lease.vault_id,
                    scope_id=scope_id,
                    entity_id=entity_id,
                    payload=payload,
                    record_revision=1,
                )
                if self._repository.put_scoped_entity(
                    lease.principal_id,
                    lease.vault_id,
                    lease.envelope_revision,
                    candidate,
                ):
                    return entity_id
                if idempotency_key is not None:
                    existing = self._repository.get_scoped_entity(
                        lease.principal_id,
                        lease.vault_id,
                        lease.envelope_revision,
                        tuple(lease.scope_keys),
                        entity_id,
                    )
                    if existing is None:
                        raise ConflictError(
                            "The idempotent entity create conflicted."
                        )
                    expected = self._decrypt_entity(lease, candidate)
                    actual = self._decrypt_entity(lease, existing)
                    if actual == expected:
                        return entity_id
                    raise ConflictError(
                        "The idempotency key was already used for "
                        "a different entity create."
                    )
        raise ConflictError("Could not allocate a unique scoped entity identifier.")

    def get_entity(
        self,
        context: AccessContext,
        entity_id: str,
    ) -> ScopedEntity:
        _validate_object_id(entity_id)
        with self._sessions.guarded_lease(context) as lease:
            row = self._repository.get_scoped_entity(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                tuple(lease.scope_keys),
                entity_id,
            )
            if row is None:
                raise RecordNotFound()
            return self._decrypt_entity(lease, row)

    def update_entity(
        self,
        context: AccessContext,
        entity_id: str,
        kind: str,
        properties: Mapping[str, Any],
        *,
        expected_revision: int,
    ) -> ScopedEntity:
        """Replace entity semantics with an optimistic revision check."""

        _validate_object_id(entity_id)
        _validate_kind(kind)
        _validate_record_revision(expected_revision)
        copied = _copy_properties(properties)
        with self._sessions.guarded_lease(context) as lease:
            allowed_scope_ids = tuple(lease.scope_keys)
            current_row = self._repository.get_scoped_entity(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                allowed_scope_ids,
                entity_id,
            )
            if current_row is None:
                raise RecordNotFound()
            current = self._decrypt_entity(lease, current_row)
            if current.record_revision != expected_revision:
                raise ConflictError("The entity revision is stale.")
            key = self._require_scope(lease, current.scope_id)
            next_revision = expected_revision + 1
            candidate = ScopedEncryptedEntityRow(
                vault_id=lease.vault_id,
                scope_id=current.scope_id,
                entity_id=entity_id,
                payload=self._crypto.encrypt_json(
                    key.dek,
                    _semantic_payload(
                        kind,
                        copied,
                        record_revision=next_revision,
                    ),
                    aad_parts=_entity_aad(
                        lease.principal_id,
                        lease.vault_id,
                        current.scope_id,
                        entity_id,
                    ),
                    key_version=key.key_version,
                    payload_version=SCOPED_PAYLOAD_VERSION,
                ),
                record_revision=next_revision,
            )
            if not self._repository.replace_scoped_entity(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                allowed_scope_ids,
                expected_revision,
                candidate,
            ):
                raise ConflictError("The entity update conflicted.")
            return self._decrypt_entity(lease, candidate)

    def delete_entity(
        self,
        context: AccessContext,
        entity_id: str,
        *,
        expected_revision: int,
    ) -> None:
        """Delete an entity only when it has no incident relationships."""

        _validate_object_id(entity_id)
        _validate_record_revision(expected_revision)
        with self._sessions.guarded_lease(context) as lease:
            allowed_scope_ids = tuple(lease.scope_keys)
            current_row = self._repository.get_scoped_entity(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                allowed_scope_ids,
                entity_id,
            )
            if current_row is None:
                raise RecordNotFound()
            current = self._decrypt_entity(lease, current_row)
            if current.record_revision != expected_revision:
                raise ConflictError("The entity revision is stale.")
            if not self._repository.delete_scoped_entity(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                allowed_scope_ids,
                entity_id,
                expected_revision,
            ):
                raise ConflictError(
                    "The entity delete conflicted or it still has "
                    "relationships."
                )

    def connect(
        self,
        context: AccessContext,
        scope_id: str,
        from_entity_id: str,
        to_entity_id: str,
        kind: str,
        properties: Mapping[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> str:
        _validate_scope_id(scope_id)
        _validate_object_id(from_entity_id)
        _validate_object_id(to_entity_id)
        _validate_kind(kind)
        copied = _copy_properties({} if properties is None else properties)
        if idempotency_key is not None:
            _validate_idempotency_key(idempotency_key)
        with self._sessions.guarded_lease(context) as lease:
            relationship_key = self._require_scope(lease, scope_id)
            allowed_scope_ids = tuple(lease.scope_keys)
            source = self._repository.get_scoped_entity(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                allowed_scope_ids,
                from_entity_id,
            )
            target = self._repository.get_scoped_entity(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                allowed_scope_ids,
                to_entity_id,
            )
            if source is None or target is None:
                raise RecordNotFound()
            try:
                _validate_scope_id(source.scope_id)
                _validate_scope_id(target.scope_id)
            except ValidationError:
                raise IntegrityViolation() from None
            if (
                source.scope_id not in lease.scope_keys
                or target.scope_id not in lease.scope_keys
            ):
                raise IntegrityViolation()
            # Authenticate endpoint scope metadata before binding it into the
            # relationship ciphertext's associated data.
            self._decrypt_entity(lease, source)
            self._decrypt_entity(lease, target)
            attempts = 1 if idempotency_key is not None else 3
            for _ in range(attempts):
                relationship_id = (
                    _idempotent_object_id(
                        relationship_key.dek,
                        operation="create-relationship",
                        principal_id=lease.principal_id,
                        vault_id=lease.vault_id,
                        scope_id=scope_id,
                        idempotency_key=idempotency_key,
                    )
                    if idempotency_key is not None
                    else f"scoped_{secrets.token_urlsafe(24)}"
                )
                payload = self._crypto.encrypt_json(
                    relationship_key.dek,
                    _semantic_payload(
                        kind,
                        copied,
                        record_revision=1,
                    ),
                    aad_parts=_relationship_aad(
                        lease.principal_id,
                        lease.vault_id,
                        scope_id,
                        relationship_id,
                        from_entity_id,
                        source.scope_id,
                        to_entity_id,
                        target.scope_id,
                    ),
                    key_version=relationship_key.key_version,
                    payload_version=SCOPED_PAYLOAD_VERSION,
                )
                candidate = ScopedEncryptedRelationshipRow(
                    vault_id=lease.vault_id,
                    scope_id=scope_id,
                    relationship_id=relationship_id,
                    from_entity_id=from_entity_id,
                    to_entity_id=to_entity_id,
                    payload=payload,
                    record_revision=1,
                )
                if self._repository.put_scoped_relationship(
                    lease.principal_id,
                    lease.vault_id,
                    lease.envelope_revision,
                    allowed_scope_ids,
                    candidate,
                ):
                    return relationship_id
                if idempotency_key is not None:
                    existing = self._repository.get_scoped_relationship(
                        lease.principal_id,
                        lease.vault_id,
                        lease.envelope_revision,
                        allowed_scope_ids,
                        relationship_id,
                    )
                    if existing is None:
                        raise ConflictError(
                            "The idempotent relationship create conflicted."
                        )
                    if (
                        existing.scope_id != scope_id
                        or existing.from_entity_id != from_entity_id
                        or existing.to_entity_id != to_entity_id
                    ):
                        raise ConflictError(
                            "The idempotency key was already used for "
                            "a different relationship create."
                        )
                    expected = self._decrypt_relationship(
                        lease,
                        candidate,
                        from_scope_id=source.scope_id,
                        to_scope_id=target.scope_id,
                    )
                    actual = self._decrypt_relationship(
                        lease,
                        existing,
                        from_scope_id=source.scope_id,
                        to_scope_id=target.scope_id,
                    )
                    if actual == expected:
                        return relationship_id
                    raise ConflictError(
                        "The idempotency key was already used for "
                        "a different relationship create."
                    )
        raise ConflictError(
            "Could not allocate a unique scoped relationship identifier."
        )

    def create_relationship(
        self,
        context: AccessContext,
        scope_id: str,
        from_entity_id: str,
        to_entity_id: str,
        kind: str,
        properties: Mapping[str, Any] | None = None,
        *,
        idempotency_key: str | None = None,
    ) -> str:
        """Canonical name for :meth:`connect`."""

        return self.connect(
            context,
            scope_id,
            from_entity_id,
            to_entity_id,
            kind,
            properties,
            idempotency_key=idempotency_key,
        )

    def create_relationship_bundle(
        self,
        context: AccessContext,
        scope_id: str,
        new_entities: tuple[tuple[str, Mapping[str, Any]], ...],
        from_endpoint: str | int,
        to_endpoint: str | int,
        kind: str,
        properties: Mapping[str, Any] | None = None,
    ) -> tuple[str, tuple[str, ...]]:
        """Atomically create scoped helper entities and one relationship."""

        _validate_scope_id(scope_id)
        if (
            not isinstance(new_entities, tuple)
            or not 1 <= len(new_entities) <= 2
        ):
            raise ValidationError(
                "A relationship bundle requires one or two new entities."
            )
        copied_specs: list[tuple[str, dict[str, Any]]] = []
        for spec in new_entities:
            if not isinstance(spec, tuple) or len(spec) != 2:
                raise ValidationError("Invalid relationship bundle entity.")
            entity_kind, entity_properties = spec
            _validate_kind(entity_kind)
            copied_specs.append(
                (entity_kind, _copy_properties(entity_properties))
            )
        _validate_kind(kind)
        relationship_properties = _copy_properties(
            {} if properties is None else properties
        )

        def validate_endpoint(endpoint: str | int) -> None:
            if isinstance(endpoint, str):
                _validate_object_id(endpoint)
                return
            if (
                type(endpoint) is not int
                or endpoint < 0
                or endpoint >= len(copied_specs)
            ):
                raise ValidationError(
                    "Invalid relationship bundle endpoint."
                )

        validate_endpoint(from_endpoint)
        validate_endpoint(to_endpoint)
        referenced_new_entities = {
            endpoint
            for endpoint in (from_endpoint, to_endpoint)
            if type(endpoint) is int
        }
        if referenced_new_entities != set(range(len(copied_specs))):
            raise ValidationError(
                "Every new relationship bundle entity must be an endpoint."
            )

        with self._sessions.guarded_lease(context) as lease:
            key = self._require_scope(lease, scope_id)
            allowed_scope_ids = tuple(lease.scope_keys)
            existing_scopes: dict[str, str] = {}
            for endpoint in (from_endpoint, to_endpoint):
                if not isinstance(endpoint, str):
                    continue
                row = self._repository.get_scoped_entity(
                    lease.principal_id,
                    lease.vault_id,
                    lease.envelope_revision,
                    allowed_scope_ids,
                    endpoint,
                )
                if row is None:
                    raise RecordNotFound()
                self._decrypt_entity(lease, row)
                existing_scopes[endpoint] = row.scope_id

            for _ in range(3):
                new_entity_ids = tuple(
                    f"scoped_{secrets.token_urlsafe(24)}"
                    for _ in copied_specs
                )

                def resolve_id(endpoint: str | int) -> str:
                    if isinstance(endpoint, str):
                        return endpoint
                    return new_entity_ids[endpoint]

                def resolve_scope(endpoint: str | int) -> str:
                    if isinstance(endpoint, str):
                        return existing_scopes[endpoint]
                    return scope_id

                from_entity_id = resolve_id(from_endpoint)
                to_entity_id = resolve_id(to_endpoint)
                from_scope_id = resolve_scope(from_endpoint)
                to_scope_id = resolve_scope(to_endpoint)
                entity_rows = tuple(
                    ScopedEncryptedEntityRow(
                        vault_id=lease.vault_id,
                        scope_id=scope_id,
                        entity_id=entity_id,
                        payload=self._crypto.encrypt_json(
                            key.dek,
                            _semantic_payload(
                                entity_kind,
                                entity_properties,
                                record_revision=1,
                            ),
                            aad_parts=_entity_aad(
                                lease.principal_id,
                                lease.vault_id,
                                scope_id,
                                entity_id,
                            ),
                            key_version=key.key_version,
                            payload_version=SCOPED_PAYLOAD_VERSION,
                        ),
                        record_revision=1,
                    )
                    for entity_id, (
                        entity_kind,
                        entity_properties,
                    ) in zip(
                        new_entity_ids,
                        copied_specs,
                        strict=True,
                    )
                )
                relationship_id = (
                    f"scoped_{secrets.token_urlsafe(24)}"
                )
                relationship_row = ScopedEncryptedRelationshipRow(
                    vault_id=lease.vault_id,
                    scope_id=scope_id,
                    relationship_id=relationship_id,
                    from_entity_id=from_entity_id,
                    to_entity_id=to_entity_id,
                    payload=self._crypto.encrypt_json(
                        key.dek,
                        _semantic_payload(
                            kind,
                            relationship_properties,
                            record_revision=1,
                        ),
                        aad_parts=_relationship_aad(
                            lease.principal_id,
                            lease.vault_id,
                            scope_id,
                            relationship_id,
                            from_entity_id,
                            from_scope_id,
                            to_entity_id,
                            to_scope_id,
                        ),
                        key_version=key.key_version,
                        payload_version=SCOPED_PAYLOAD_VERSION,
                    ),
                    record_revision=1,
                )
                if self._repository.put_scoped_entity_relationship_bundle(
                    lease.principal_id,
                    lease.vault_id,
                    lease.envelope_revision,
                    allowed_scope_ids,
                    entity_rows,
                    relationship_row,
                ):
                    return relationship_id, new_entity_ids
                if any(
                    self._repository.get_scoped_entity(
                        lease.principal_id,
                        lease.vault_id,
                        lease.envelope_revision,
                        allowed_scope_ids,
                        endpoint,
                    )
                    is None
                    for endpoint in existing_scopes
                ):
                    raise RecordNotFound()
        raise ConflictError(
            "Could not allocate a unique scoped relationship bundle."
        )

    def get_relationship(
        self,
        context: AccessContext,
        relationship_id: str,
    ) -> ScopedRelationship:
        _validate_object_id(relationship_id)
        with self._sessions.guarded_lease(context) as lease:
            row, from_scope_id, to_scope_id = (
                self._get_relationship_record(lease, relationship_id)
            )
            return self._decrypt_relationship(
                lease,
                row,
                from_scope_id=from_scope_id,
                to_scope_id=to_scope_id,
            )

    def update_relationship(
        self,
        context: AccessContext,
        relationship_id: str,
        kind: str,
        properties: Mapping[str, Any] | None = None,
        *,
        expected_revision: int,
    ) -> ScopedRelationship:
        """Replace relationship semantics without moving its endpoints."""

        _validate_object_id(relationship_id)
        _validate_kind(kind)
        _validate_record_revision(expected_revision)
        copied = _copy_properties({} if properties is None else properties)
        with self._sessions.guarded_lease(context) as lease:
            row, from_scope_id, to_scope_id = (
                self._get_relationship_record(lease, relationship_id)
            )
            current = self._decrypt_relationship(
                lease,
                row,
                from_scope_id=from_scope_id,
                to_scope_id=to_scope_id,
            )
            if current.record_revision != expected_revision:
                raise ConflictError("The relationship revision is stale.")
            key = self._require_scope(lease, row.scope_id)
            next_revision = expected_revision + 1
            candidate = ScopedEncryptedRelationshipRow(
                vault_id=lease.vault_id,
                scope_id=row.scope_id,
                relationship_id=relationship_id,
                from_entity_id=row.from_entity_id,
                to_entity_id=row.to_entity_id,
                payload=self._crypto.encrypt_json(
                    key.dek,
                    _semantic_payload(
                        kind,
                        copied,
                        record_revision=next_revision,
                    ),
                    aad_parts=_relationship_aad(
                        lease.principal_id,
                        lease.vault_id,
                        row.scope_id,
                        relationship_id,
                        row.from_entity_id,
                        from_scope_id,
                        row.to_entity_id,
                        to_scope_id,
                    ),
                    key_version=key.key_version,
                    payload_version=SCOPED_PAYLOAD_VERSION,
                ),
                record_revision=next_revision,
            )
            if not self._repository.replace_scoped_relationship(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                tuple(lease.scope_keys),
                expected_revision,
                candidate,
            ):
                raise ConflictError("The relationship update conflicted.")
            return self._decrypt_relationship(
                lease,
                candidate,
                from_scope_id=from_scope_id,
                to_scope_id=to_scope_id,
            )

    def delete_relationship(
        self,
        context: AccessContext,
        relationship_id: str,
        *,
        expected_revision: int,
    ) -> None:
        _validate_object_id(relationship_id)
        _validate_record_revision(expected_revision)
        with self._sessions.guarded_lease(context) as lease:
            row, from_scope_id, to_scope_id = (
                self._get_relationship_record(lease, relationship_id)
            )
            current = self._decrypt_relationship(
                lease,
                row,
                from_scope_id=from_scope_id,
                to_scope_id=to_scope_id,
            )
            if current.record_revision != expected_revision:
                raise ConflictError("The relationship revision is stale.")
            if not self._repository.delete_scoped_relationship(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                tuple(lease.scope_keys),
                relationship_id,
                expected_revision,
            ):
                raise ConflictError("The relationship delete conflicted.")

    def get_vault_snapshot(
        self,
        context: AccessContext,
        *,
        entity_limit: int = MAX_VAULT_SNAPSHOT_ENTITIES,
        relationship_limit: int = MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
    ) -> ScopedVaultSnapshot:
        if (
            type(entity_limit) is not int
            or entity_limit <= 0
            or entity_limit > MAX_VAULT_SNAPSHOT_ENTITIES
            or type(relationship_limit) is not int
            or relationship_limit <= 0
            or relationship_limit > MAX_VAULT_SNAPSHOT_RELATIONSHIPS
        ):
            raise ValidationError(
                "Scoped snapshot limits exceed the supported safety bounds."
            )
        with self._sessions.guarded_lease(context) as lease:
            encrypted = self._repository.get_scoped_vault_snapshot(
                lease.principal_id,
                lease.vault_id,
                lease.envelope_revision,
                tuple(lease.scope_keys),
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
                    "The complete granted-scope view does not fit within limits."
                )
            try:
                ciphertext_bytes = sum(
                    len(row.payload.ciphertext)
                    for row in (
                        *encrypted.entities,
                        *encrypted.relationships,
                    )
                )
            except (AttributeError, TypeError):
                raise IntegrityViolation() from None
            if ciphertext_bytes > MAX_VAULT_SNAPSHOT_CIPHERTEXT_BYTES:
                raise ValidationError(
                    "The complete granted-scope view does not fit within limits."
                )

            entities: dict[str, ScopedEntity] = {}
            entity_scopes: dict[str, str] = {}
            for row in encrypted.entities:
                if row.entity_id in entities:
                    raise IntegrityViolation()
                entity = self._decrypt_entity(lease, row)
                entities[entity.entity_id] = entity
                entity_scopes[entity.entity_id] = entity.scope_id

            relationships: dict[str, ScopedRelationship] = {}
            for row in encrypted.relationships:
                if (
                    row.relationship_id in relationships
                    or row.from_entity_id not in entities
                    or row.to_entity_id not in entities
                ):
                    raise IntegrityViolation()
                relationship = self._decrypt_relationship(
                    lease,
                    row,
                    from_scope_id=entity_scopes[row.from_entity_id],
                    to_scope_id=entity_scopes[row.to_entity_id],
                )
                relationships[relationship.relationship_id] = relationship
            return ScopedVaultSnapshot(
                entities=tuple(
                    sorted(
                        entities.values(),
                        key=lambda entity: entity.entity_id,
                    )
                ),
                relationships=tuple(
                    sorted(
                        relationships.values(),
                        key=lambda relationship: relationship.relationship_id,
                    )
                ),
            )

    def _decrypt_entity(
        self,
        lease: ScopedSessionLease,
        row: ScopedEncryptedEntityRow,
    ) -> ScopedEntity:
        if (
            not isinstance(row, ScopedEncryptedEntityRow)
            or row.vault_id != lease.vault_id
        ):
            raise IntegrityViolation()
        try:
            _validate_scope_id(row.scope_id)
            _validate_object_id(row.entity_id)
            _validate_record_revision(row.record_revision)
        except ValidationError:
            raise IntegrityViolation() from None
        key = lease.scope_keys.get(row.scope_id)
        if key is None or row.payload.key_version != key.key_version:
            raise IntegrityViolation()
        decoded = self._crypto.decrypt_json(
            key.dek,
            row.payload,
            aad_parts=_entity_aad(
                lease.principal_id,
                lease.vault_id,
                row.scope_id,
                row.entity_id,
            ),
            expected_payload_version=SCOPED_PAYLOAD_VERSION,
        )
        kind, properties, record_revision = self._decode_semantic(decoded)
        if record_revision != row.record_revision:
            raise IntegrityViolation()
        return ScopedEntity(
            entity_id=row.entity_id,
            scope_id=row.scope_id,
            kind=kind,
            properties=properties,
            record_revision=record_revision,
        )

    def _decrypt_relationship(
        self,
        lease: ScopedSessionLease,
        row: ScopedEncryptedRelationshipRow,
        *,
        from_scope_id: str,
        to_scope_id: str,
    ) -> ScopedRelationship:
        if (
            not isinstance(row, ScopedEncryptedRelationshipRow)
            or row.vault_id != lease.vault_id
        ):
            raise IntegrityViolation()
        try:
            _validate_scope_id(row.scope_id)
            _validate_object_id(row.relationship_id)
            _validate_object_id(row.from_entity_id)
            _validate_object_id(row.to_entity_id)
            _validate_scope_id(from_scope_id)
            _validate_scope_id(to_scope_id)
            _validate_record_revision(row.record_revision)
        except ValidationError:
            raise IntegrityViolation() from None
        key = lease.scope_keys.get(row.scope_id)
        if key is None or row.payload.key_version != key.key_version:
            raise IntegrityViolation()
        decoded = self._crypto.decrypt_json(
            key.dek,
            row.payload,
            aad_parts=_relationship_aad(
                lease.principal_id,
                lease.vault_id,
                row.scope_id,
                row.relationship_id,
                row.from_entity_id,
                from_scope_id,
                row.to_entity_id,
                to_scope_id,
            ),
            expected_payload_version=SCOPED_PAYLOAD_VERSION,
        )
        kind, properties, record_revision = self._decode_semantic(decoded)
        if record_revision != row.record_revision:
            raise IntegrityViolation()
        return ScopedRelationship(
            relationship_id=row.relationship_id,
            scope_id=row.scope_id,
            from_entity_id=row.from_entity_id,
            to_entity_id=row.to_entity_id,
            kind=kind,
            properties=properties,
            record_revision=record_revision,
        )

    @staticmethod
    def _decode_semantic(
        value: Mapping[str, Any],
    ) -> tuple[str, dict[str, Any], int]:
        try:
            fields = set(value)
            if fields == {"kind", "properties"}:
                record_revision = 1
            elif fields == {
                "kind",
                "properties",
                "record_revision",
            }:
                record_revision = value["record_revision"]
                _validate_record_revision(record_revision)
            else:
                raise IntegrityViolation()
            kind = value["kind"]
            properties = value["properties"]
            _validate_kind(kind)
            copied = _copy_properties(properties)
            return kind, copied, record_revision
        except (KeyError, TypeError, ValidationError):
            raise IntegrityViolation() from None
