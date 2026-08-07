"""Provider-neutral durable custody for scoped data-encryption keys.

The graph service already has narrow enrollment and release protocols.  This
module supplies a production-shaped implementation of those protocols while
keeping two concerns injectable:

* :class:`KeyWrappingBackend` protects one 256-bit scope key with a KMS/HSM;
* :class:`KeySlotStore` durably stores only opaque wrapped-key blobs and
  performs atomic compare-and-swap updates.

The included in-memory implementations are deliberately test helpers.  A
production deployment must use a durable, strongly consistent slot store and
a managed wrapping backend.  No implementation can guarantee complete
zeroization in Python, but every mutable plaintext buffer owned here is
overwritten in ``finally`` blocks.
"""

from __future__ import annotations

import hmac
import json
import math
import os
import threading
import unicodedata
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import AES_KEY_BYTES, NONCE_BYTES, clear_bytearray
from .errors import AuthGraphError, ValidationError
from .scoped_sessions import MAX_SCOPES_PER_SESSION, ScopeKeyMaterial
from .unlock_policy import (
    ReleasedScopeKeys,
    ScopeGrantDenied,
    ScopeUnlockGrant,
)

KEY_SLOT_FORMAT_VERSION = 1
WRAPPED_KEY_FORMAT_VERSION = 1
MAX_OPAQUE_ID_CHARS = 256
MAX_BACKEND_ID_CHARS = 128
MAX_KEY_ID_CHARS = 2048
MAX_ALGORITHM_CHARS = 128
MAX_WRAPPED_KEY_BYTES = 64 * 1024
MAX_CAS_ATTEMPTS = 3
IN_MEMORY_ALGORITHM = "AES-256-GCM"

__all__ = [
    "EnvelopeScopeKeyProvider",
    "InMemoryAesKeyWrappingBackend",
    "InMemoryKeySlotStore",
    "KeyCustodyConflict",
    "KeyCustodyError",
    "KeyCustodyUnavailable",
    "KeySlotIdentity",
    "KeySlotRow",
    "KeySlotState",
    "KeySlotStore",
    "KeyWrappingBackend",
    "RecoveredKeyMaterial",
    "RecoveryKeyProvenance",
    "RecoveryKeyWrappingBackend",
    "RecoveryRewrapResult",
    "WrappedKeyBlob",
]


class KeyCustodyError(AuthGraphError):
    """Base class for management-plane key-custody failures."""


class KeyCustodyConflict(KeyCustodyError):
    """A slot changed or was revoked during a custody operation."""

    def __init__(self) -> None:
        super().__init__("The key-custody operation conflicted.")


class KeyCustodyUnavailable(KeyCustodyError):
    """A wrapping backend or durable slot store was unavailable or invalid."""

    def __init__(self) -> None:
        super().__init__("The key-custody service is unavailable.")


class KeySlotState(StrEnum):
    """Durable lifecycle state for one scope-key slot."""

    ACTIVE = "active"
    REVOKED = "revoked"


def _validate_text(
    value: object,
    *,
    maximum: int,
    message: str,
) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ValidationError(message)
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValidationError(message) from None
    return value


def _validate_opaque_id(value: object, message: str) -> str:
    return _validate_text(
        value,
        maximum=MAX_OPAQUE_ID_CHARS,
        message=message,
    )


def _validate_positive_int(value: object, message: str) -> int:
    if type(value) is not int or value <= 0 or value > (2**63 - 1):
        raise ValidationError(message)
    return value


def _validate_scope_ids(scope_ids: object) -> tuple[str, ...]:
    if (
        not isinstance(scope_ids, tuple)
        or not scope_ids
        or len(scope_ids) > MAX_SCOPES_PER_SESSION
    ):
        raise ValidationError("Invalid protection-scope set.")
    validated = tuple(
        _validate_opaque_id(
            scope_id,
            "Invalid opaque protection-scope identifier.",
        )
        for scope_id in scope_ids
    )
    if len(set(validated)) != len(validated):
        raise ValidationError("Invalid protection-scope set.")
    return validated


@dataclass(frozen=True, slots=True)
class WrappedKeyBlob:
    """Opaque provider ciphertext plus the metadata needed to unwrap it."""

    backend_id: str
    key_id: str = field(repr=False)
    algorithm: str
    ciphertext: bytes = field(repr=False)
    format_version: int = WRAPPED_KEY_FORMAT_VERSION

    def __post_init__(self) -> None:
        if (
            type(self.format_version) is not int
            or self.format_version != WRAPPED_KEY_FORMAT_VERSION
        ):
            raise ValidationError("Invalid wrapped-key format version.")
        _validate_text(
            self.backend_id,
            maximum=MAX_BACKEND_ID_CHARS,
            message="Invalid key-wrapping backend identifier.",
        )
        _validate_text(
            self.key_id,
            maximum=MAX_KEY_ID_CHARS,
            message="Invalid provider key identifier.",
        )
        _validate_text(
            self.algorithm,
            maximum=MAX_ALGORITHM_CHARS,
            message="Invalid provider wrapping algorithm.",
        )
        if (
            type(self.ciphertext) is not bytes
            or not self.ciphertext
            or len(self.ciphertext) > MAX_WRAPPED_KEY_BYTES
        ):
            raise ValidationError("Invalid wrapped-key ciphertext.")


@dataclass(frozen=True, slots=True)
class KeySlotIdentity:
    """Storage key for one owner/vault/protection-scope slot."""

    principal_id: str = field(repr=False)
    vault_id: str = field(repr=False)
    scope_id: str = field(repr=False)

    def __post_init__(self) -> None:
        _validate_opaque_id(
            self.principal_id,
            "Invalid opaque principal identifier.",
        )
        _validate_opaque_id(
            self.vault_id,
            "Invalid opaque vault identifier.",
        )
        _validate_opaque_id(
            self.scope_id,
            "Invalid opaque protection-scope identifier.",
        )


@dataclass(frozen=True, slots=True)
class KeySlotRow:
    """Immutable active wrapped-key slot or ciphertext-free tombstone.

    A tombstone may retain prior non-secret version metadata.  A tombstone
    created before a slot was ever enrolled has all three key metadata fields
    set to ``None``.  It still blocks accidental future enrollment.
    """

    identity: KeySlotIdentity
    slot_version: int
    state: KeySlotState
    enrolled_envelope_revision: int | None = field(repr=False)
    root_key_version: int | None
    scope_key_version: int | None
    wrapped_key: WrappedKeyBlob | None = field(repr=False)
    format_version: int = KEY_SLOT_FORMAT_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.identity, KeySlotIdentity):
            raise ValidationError("Invalid key-slot identity.")
        if (
            type(self.format_version) is not int
            or self.format_version != KEY_SLOT_FORMAT_VERSION
        ):
            raise ValidationError("Invalid key-slot format version.")
        _validate_positive_int(
            self.slot_version,
            "Invalid key-slot revision.",
        )
        if type(self.state) is not KeySlotState:
            raise ValidationError("Invalid key-slot state.")
        metadata = (
            self.enrolled_envelope_revision,
            self.root_key_version,
            self.scope_key_version,
        )
        if self.state is KeySlotState.ACTIVE:
            for value in metadata:
                _validate_positive_int(
                    value,
                    "Invalid active key-slot metadata.",
                )
            if not isinstance(self.wrapped_key, WrappedKeyBlob):
                raise ValidationError("An active key slot requires ciphertext.")
            return
        if self.wrapped_key is not None:
            raise ValidationError("A revoked key slot cannot retain ciphertext.")
        if any(value is None for value in metadata):
            if any(value is not None for value in metadata):
                raise ValidationError("Invalid revoked key-slot metadata.")
            return
        for value in metadata:
            _validate_positive_int(
                value,
                "Invalid revoked key-slot metadata.",
            )


@runtime_checkable
class KeyWrappingBackend(Protocol):
    """KMS/HSM boundary for wrapping one 256-bit key.

    ``backend_id`` must identify one exact backend/key generation.  Changing
    the provider key requires a new ID so rewrap is safely idempotent.
    """

    @property
    def backend_id(self) -> str: ...

    def wrap_key(
        self,
        plaintext: bytes | bytearray | memoryview,
        *,
        aad: bytes,
    ) -> WrappedKeyBlob: ...

    def unwrap_key(
        self,
        wrapped_key: WrappedKeyBlob,
        *,
        aad: bytes,
    ) -> AbstractContextManager[bytearray]: ...


@dataclass(frozen=True, slots=True)
class RecoveryKeyProvenance:
    """Exact recovery backend and provider key used for one unwrap."""

    backend_id: str
    key_id: str = field(repr=False)

    def __post_init__(self) -> None:
        _validate_text(
            self.backend_id,
            maximum=MAX_BACKEND_ID_CHARS,
            message="Invalid recovery backend identifier.",
        )
        _validate_text(
            self.key_id,
            maximum=MAX_KEY_ID_CHARS,
            message="Invalid recovery provider key identifier.",
        )

    def audit_source_id(self) -> str:
        """Return a structured value intended only for audit pseudonymization."""

        return json.dumps(
            [self.backend_id, self.key_id],
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        )


@dataclass(slots=True)
class RecoveredKeyMaterial:
    """Context-bound plaintext key and provenance from a recovery backend."""

    dek: bytearray = field(repr=False)
    provenance: RecoveryKeyProvenance

    def __post_init__(self) -> None:
        if (
            not isinstance(self.dek, bytearray)
            or len(self.dek) != AES_KEY_BYTES
            or not isinstance(self.provenance, RecoveryKeyProvenance)
        ):
            raise KeyCustodyUnavailable()


@dataclass(frozen=True, slots=True)
class RecoveryRewrapResult:
    """Committed recovery rewrap count and the exact source keys used."""

    changed_count: int
    sources: tuple[RecoveryKeyProvenance, ...]

    def __post_init__(self) -> None:
        if (
            type(self.changed_count) is not int
            or self.changed_count <= 0
            or not isinstance(self.sources, tuple)
            or not self.sources
            or any(
                not isinstance(source, RecoveryKeyProvenance)
                for source in self.sources
            )
        ):
            raise ValidationError("Invalid recovery rewrap result.")


@runtime_checkable
class RecoveryKeyWrappingBackend(Protocol):
    """Explicit break-glass unwrap boundary, never used by normal release."""

    @property
    def backend_id(self) -> str: ...

    def unwrap_key_for_recovery(
        self,
        wrapped_key: WrappedKeyBlob,
        *,
        aad: bytes,
    ) -> AbstractContextManager[RecoveredKeyMaterial]: ...


@runtime_checkable
class KeySlotStore(Protocol):
    """Strongly consistent durable storage for wrapped slots.

    Implementations must return one consistent, detached snapshot from
    ``get_slots`` and atomically compare every expected version before
    replacing any row.  They must never persist plaintext key material.
    """

    def get_slots(
        self,
        *,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
    ) -> tuple[KeySlotRow, ...]: ...

    def compare_and_swap_slots(
        self,
        *,
        expected_versions: Mapping[KeySlotIdentity, int | None],
        replacement_rows: tuple[KeySlotRow, ...],
    ) -> bool: ...

    def list_vault_slots(
        self,
        *,
        principal_id: str,
        vault_id: str,
    ) -> tuple[KeySlotRow, ...]: ...


def _detached_slot_row(row: KeySlotRow) -> KeySlotRow:
    """Copy every nested slot value across the storage trust boundary."""

    wrapped = row.wrapped_key
    wrapped_copy = (
        None
        if wrapped is None
        else WrappedKeyBlob(
            backend_id=wrapped.backend_id,
            key_id=wrapped.key_id,
            algorithm=wrapped.algorithm,
            ciphertext=bytes(wrapped.ciphertext),
            format_version=wrapped.format_version,
        )
    )
    return KeySlotRow(
        identity=KeySlotIdentity(
            principal_id=row.identity.principal_id,
            vault_id=row.identity.vault_id,
            scope_id=row.identity.scope_id,
        ),
        slot_version=row.slot_version,
        state=row.state,
        enrolled_envelope_revision=row.enrolled_envelope_revision,
        root_key_version=row.root_key_version,
        scope_key_version=row.scope_key_version,
        wrapped_key=wrapped_copy,
        format_version=row.format_version,
    )


class InMemoryKeySlotStore:
    """Thread-safe test implementation of :class:`KeySlotStore`.

    This class has the same atomic CAS behavior as a durable adapter, but its
    rows do not survive restart and therefore it is not a production store.
    """

    def __init__(self) -> None:
        self._rows: dict[KeySlotIdentity, KeySlotRow] = {}
        self._lock = threading.RLock()

    def get_slots(
        self,
        *,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
    ) -> tuple[KeySlotRow, ...]:
        principal = _validate_opaque_id(
            principal_id,
            "Invalid opaque principal identifier.",
        )
        vault = _validate_opaque_id(
            vault_id,
            "Invalid opaque vault identifier.",
        )
        scopes = _validate_scope_ids(scope_ids)
        with self._lock:
            return tuple(
                _detached_slot_row(row)
                for scope_id in scopes
                if (
                    row := self._rows.get(
                        KeySlotIdentity(principal, vault, scope_id)
                    )
                )
                is not None
            )

    def compare_and_swap_slots(
        self,
        *,
        expected_versions: Mapping[KeySlotIdentity, int | None],
        replacement_rows: tuple[KeySlotRow, ...],
    ) -> bool:
        if not isinstance(expected_versions, Mapping):
            raise ValidationError("Invalid key-slot compare-and-swap request.")
        expected = dict(expected_versions)
        if (
            not expected
            or len(expected) > MAX_SCOPES_PER_SESSION
            or not isinstance(replacement_rows, tuple)
            or len(replacement_rows) != len(expected)
        ):
            raise ValidationError("Invalid key-slot compare-and-swap request.")
        replacements: dict[KeySlotIdentity, KeySlotRow] = {}
        for identity, version in expected.items():
            if not isinstance(identity, KeySlotIdentity) or (
                version is not None
                and (type(version) is not int or version <= 0)
            ):
                raise ValidationError(
                    "Invalid key-slot compare-and-swap request."
                )
        for row in replacement_rows:
            if (
                not isinstance(row, KeySlotRow)
                or row.identity in replacements
            ):
                raise ValidationError(
                    "Invalid key-slot compare-and-swap request."
                )
            replacements[row.identity] = row
        if set(replacements) != set(expected):
            raise ValidationError("Invalid key-slot compare-and-swap request.")
        for identity, expected_version in expected.items():
            replacement_version = replacements[identity].slot_version
            if expected_version is None:
                valid_replacement = replacement_version == 1
            else:
                valid_replacement = replacement_version in (
                    expected_version,
                    expected_version + 1,
                )
            if not valid_replacement:
                raise ValidationError(
                    "Invalid key-slot compare-and-swap revision."
                )
        with self._lock:
            for identity, expected_version in expected.items():
                current = self._rows.get(identity)
                current_version = (
                    None if current is None else current.slot_version
                )
                if current_version != expected_version:
                    return False
                replacement = replacements[identity]
                if (
                    current is not None
                    and replacement.slot_version == current.slot_version
                    and replacement != current
                ):
                    raise ValidationError(
                        "A changed key-slot row must advance its revision."
                    )
            owned_replacements: dict[KeySlotIdentity, KeySlotRow] = {}
            for row in replacements.values():
                owned = _detached_slot_row(row)
                owned_replacements[owned.identity] = owned
            self._rows.update(owned_replacements)
            return True

    def list_vault_slots(
        self,
        *,
        principal_id: str,
        vault_id: str,
    ) -> tuple[KeySlotRow, ...]:
        principal = _validate_opaque_id(
            principal_id,
            "Invalid opaque principal identifier.",
        )
        vault = _validate_opaque_id(
            vault_id,
            "Invalid opaque vault identifier.",
        )
        with self._lock:
            return tuple(
                _detached_slot_row(row)
                for row in sorted(
                    (
                        row
                        for identity, row in self._rows.items()
                        if identity.principal_id == principal
                        and identity.vault_id == vault
                    ),
                    key=lambda row: row.identity.scope_id,
                )
            )


class InMemoryAesKeyWrappingBackend:
    """Process-local AES-GCM wrapping backend for tests only."""

    def __init__(
        self,
        *,
        backend_id: str = "in-memory-aes",
        key_id: str = "process-local-key",
        wrapping_key: bytes | bytearray | memoryview | None = None,
    ) -> None:
        self._backend_id = _validate_text(
            backend_id,
            maximum=MAX_BACKEND_ID_CHARS,
            message="Invalid key-wrapping backend identifier.",
        )
        self._key_id = _validate_text(
            key_id,
            maximum=MAX_KEY_ID_CHARS,
            message="Invalid provider key identifier.",
        )
        source = os.urandom(AES_KEY_BYTES) if wrapping_key is None else wrapping_key
        try:
            view = memoryview(source)
            if not view.contiguous or view.nbytes != AES_KEY_BYTES:
                raise ValidationError("Invalid in-memory wrapping key.")
            self._wrapping_key = bytearray(view.cast("B"))
        except (TypeError, ValueError):
            raise ValidationError("Invalid in-memory wrapping key.") from None
        self._lock = threading.RLock()
        self._closed = False

    @property
    def backend_id(self) -> str:
        return self._backend_id

    @staticmethod
    def _validated_aad(aad: object) -> bytes:
        if type(aad) is not bytes or not aad:
            raise ValidationError("Invalid key-slot associated data.")
        return aad

    @staticmethod
    def _copy_plaintext(
        plaintext: bytes | bytearray | memoryview,
    ) -> bytearray:
        try:
            view = memoryview(plaintext)
            if not view.contiguous or view.nbytes != AES_KEY_BYTES:
                raise ValidationError("Invalid scope key material.")
            return bytearray(view.cast("B"))
        except (TypeError, ValueError):
            raise ValidationError("Invalid scope key material.") from None

    def wrap_key(
        self,
        plaintext: bytes | bytearray | memoryview,
        *,
        aad: bytes,
    ) -> WrappedKeyBlob:
        associated_data = self._validated_aad(aad)
        copied = self._copy_plaintext(plaintext)
        try:
            with self._lock:
                if self._closed:
                    raise KeyCustodyUnavailable()
                nonce = os.urandom(NONCE_BYTES)
                ciphertext = AESGCM(self._wrapping_key).encrypt(
                    nonce,
                    copied,
                    associated_data,
                )
            return WrappedKeyBlob(
                backend_id=self._backend_id,
                key_id=self._key_id,
                algorithm=IN_MEMORY_ALGORITHM,
                ciphertext=nonce + ciphertext,
            )
        except KeyCustodyUnavailable:
            raise
        except Exception:
            raise KeyCustodyUnavailable() from None
        finally:
            clear_bytearray(copied)

    @contextmanager
    def unwrap_key(
        self,
        wrapped_key: WrappedKeyBlob,
        *,
        aad: bytes,
    ) -> Iterator[bytearray]:
        associated_data = self._validated_aad(aad)
        plaintext: bytearray | None = None
        try:
            if (
                not isinstance(wrapped_key, WrappedKeyBlob)
                or wrapped_key.backend_id != self._backend_id
                or wrapped_key.key_id != self._key_id
                or wrapped_key.algorithm != IN_MEMORY_ALGORITHM
                or len(wrapped_key.ciphertext)
                != NONCE_BYTES + AES_KEY_BYTES + 16
            ):
                raise KeyCustodyUnavailable()
            with self._lock:
                if self._closed:
                    raise KeyCustodyUnavailable()
                plaintext = bytearray(
                    AESGCM(self._wrapping_key).decrypt(
                        wrapped_key.ciphertext[:NONCE_BYTES],
                        wrapped_key.ciphertext[NONCE_BYTES:],
                        associated_data,
                    )
                )
            if len(plaintext) != AES_KEY_BYTES:
                raise KeyCustodyUnavailable()
        except (InvalidTag, KeyCustodyUnavailable):
            raise KeyCustodyUnavailable() from None
        except Exception:
            raise KeyCustodyUnavailable() from None
        assert plaintext is not None
        try:
            yield plaintext
        finally:
            clear_bytearray(plaintext)

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                clear_bytearray(self._wrapping_key)


def _slot_aad_values(
    identity: KeySlotIdentity,
    *,
    enrolled_envelope_revision: int,
    root_key_version: int,
    scope_key_version: int,
    slot_version: int,
    backend_id: str,
) -> bytes:
    return json.dumps(
        [
            "authgraph",
            "scope-key-slot",
            KEY_SLOT_FORMAT_VERSION,
            identity.principal_id,
            identity.vault_id,
            identity.scope_id,
            enrolled_envelope_revision,
            root_key_version,
            scope_key_version,
            slot_version,
            backend_id,
        ],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")


def _slot_aad(row: KeySlotRow) -> bytes:
    if row.state is not KeySlotState.ACTIVE or row.wrapped_key is None:
        raise KeyCustodyUnavailable()
    assert row.enrolled_envelope_revision is not None
    assert row.root_key_version is not None
    assert row.scope_key_version is not None
    return _slot_aad_values(
        row.identity,
        enrolled_envelope_revision=row.enrolled_envelope_revision,
        root_key_version=row.root_key_version,
        scope_key_version=row.scope_key_version,
        slot_version=row.slot_version,
        backend_id=row.wrapped_key.backend_id,
    )


class EnvelopeScopeKeyProvider:
    """Compose durable slots and KMS/HSM backends into the existing SPI.

    Enrollment is exact and idempotent: an existing active slot is accepted
    only when its versions and unwrapped 256-bit key match.  Revoked slots are
    tombstones and cannot be silently recreated.  Release returns exactly the
    grant's requested scopes, never every slot in a vault.
    """

    def __init__(
        self,
        slot_store: KeySlotStore,
        wrapping_backends: Mapping[str, KeyWrappingBackend],
        *,
        active_backend_id: str,
    ) -> None:
        if not isinstance(slot_store, KeySlotStore):
            raise TypeError("slot_store must implement KeySlotStore.")
        if not isinstance(wrapping_backends, Mapping):
            raise TypeError("wrapping_backends must be a mapping.")
        copied = dict(wrapping_backends)
        if not copied:
            raise ValidationError("At least one wrapping backend is required.")
        for backend_id, backend in copied.items():
            if (
                not isinstance(backend, KeyWrappingBackend)
                or backend_id != backend.backend_id
            ):
                raise ValidationError("Invalid key-wrapping backend mapping.")
            _validate_text(
                backend_id,
                maximum=MAX_BACKEND_ID_CHARS,
                message="Invalid key-wrapping backend identifier.",
            )
        if active_backend_id not in copied:
            raise ValidationError("The active wrapping backend is unavailable.")
        self._slot_store = slot_store
        self._backends = MappingProxyType(copied)
        self._active_backend_id = active_backend_id

    @property
    def active_backend_id(self) -> str:
        return self._active_backend_id

    def _backend(self, backend_id: str) -> KeyWrappingBackend:
        backend = self._backends.get(backend_id)
        if backend is None:
            raise KeyCustodyUnavailable()
        return backend

    @staticmethod
    def _validated_materials(
        scope_keys: Mapping[str, ScopeKeyMaterial],
    ) -> dict[str, ScopeKeyMaterial]:
        if not isinstance(scope_keys, Mapping):
            raise ValidationError("Invalid scope-key enrollment set.")
        copied = dict(scope_keys)
        if not copied or len(copied) > MAX_SCOPES_PER_SESSION:
            raise ValidationError("Invalid scope-key enrollment set.")
        for scope_id, material in copied.items():
            _validate_opaque_id(
                scope_id,
                "Invalid opaque protection-scope identifier.",
            )
            if (
                not isinstance(material, ScopeKeyMaterial)
                or type(material.key_version) is not int
                or material.key_version <= 0
                or not isinstance(material.dek, bytearray)
                or len(material.dek) != AES_KEY_BYTES
            ):
                raise ValidationError("Invalid scope-key enrollment material.")
        return copied

    def _read_exact(
        self,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
    ) -> dict[str, KeySlotRow]:
        try:
            rows = self._slot_store.get_slots(
                principal_id=principal_id,
                vault_id=vault_id,
                scope_ids=scope_ids,
            )
            if not isinstance(rows, tuple):
                raise KeyCustodyUnavailable()
            by_scope: dict[str, KeySlotRow] = {}
            for row in rows:
                if (
                    not isinstance(row, KeySlotRow)
                    or row.identity.principal_id != principal_id
                    or row.identity.vault_id != vault_id
                    or row.identity.scope_id not in scope_ids
                    or row.identity.scope_id in by_scope
                ):
                    raise KeyCustodyUnavailable()
                by_scope[row.identity.scope_id] = row
            return by_scope
        except KeyCustodyUnavailable:
            raise
        except Exception:
            raise KeyCustodyUnavailable() from None

    def _active_slot_matches(
        self,
        row: KeySlotRow,
        material: ScopeKeyMaterial,
        *,
        envelope_revision: int,
        root_key_version: int,
    ) -> bool:
        if (
            row.state is not KeySlotState.ACTIVE
            or row.wrapped_key is None
            or row.enrolled_envelope_revision is None
            or row.enrolled_envelope_revision > envelope_revision
            or row.root_key_version != root_key_version
            or row.scope_key_version != material.key_version
        ):
            return False
        backend = self._backend(row.wrapped_key.backend_id)
        with backend.unwrap_key(row.wrapped_key, aad=_slot_aad(row)) as existing:
            if not isinstance(existing, bytearray) or len(existing) != AES_KEY_BYTES:
                raise KeyCustodyUnavailable()
            return hmac.compare_digest(existing, material.dek)

    def _new_active_row(
        self,
        identity: KeySlotIdentity,
        material: ScopeKeyMaterial,
        *,
        envelope_revision: int,
        root_key_version: int,
    ) -> KeySlotRow:
        backend = self._backend(self._active_backend_id)
        slot_version = 1
        aad = _slot_aad_values(
            identity,
            enrolled_envelope_revision=envelope_revision,
            root_key_version=root_key_version,
            scope_key_version=material.key_version,
            slot_version=slot_version,
            backend_id=backend.backend_id,
        )
        wrapped_key = backend.wrap_key(material.dek, aad=aad)
        if (
            not isinstance(wrapped_key, WrappedKeyBlob)
            or wrapped_key.backend_id != backend.backend_id
        ):
            raise KeyCustodyUnavailable()
        return KeySlotRow(
            identity=identity,
            slot_version=slot_version,
            state=KeySlotState.ACTIVE,
            enrolled_envelope_revision=envelope_revision,
            root_key_version=root_key_version,
            scope_key_version=material.key_version,
            wrapped_key=wrapped_key,
        )

    def enroll_scope_keys(
        self,
        *,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        root_key_version: int,
        scope_keys: Mapping[str, ScopeKeyMaterial],
    ) -> None:
        """Idempotently enroll an exact scope-key set.

        A password rewrap may advance ``envelope_revision`` without changing
        the existing slot.  A root/scope key-version change is not enrollment;
        it must use an explicit future cryptographic rotation workflow.
        """

        principal = _validate_opaque_id(
            principal_id,
            "Invalid opaque principal identifier.",
        )
        vault = _validate_opaque_id(
            vault_id,
            "Invalid opaque vault identifier.",
        )
        envelope = _validate_positive_int(
            envelope_revision,
            "Invalid key-slot envelope revision.",
        )
        root_version = _validate_positive_int(
            root_key_version,
            "Invalid vault root-key version.",
        )
        materials = self._validated_materials(scope_keys)
        scope_ids = tuple(materials)

        for _ in range(MAX_CAS_ATTEMPTS):
            existing_by_scope = self._read_exact(
                principal,
                vault,
                scope_ids,
            )
            expected: dict[KeySlotIdentity, int | None] = {}
            replacements: list[KeySlotRow] = []
            for scope_id, material in materials.items():
                identity = KeySlotIdentity(principal, vault, scope_id)
                current = existing_by_scope.get(scope_id)
                expected[identity] = (
                    None if current is None else current.slot_version
                )
                if current is None:
                    replacements.append(
                        self._new_active_row(
                            identity,
                            material,
                            envelope_revision=envelope,
                            root_key_version=root_version,
                        )
                    )
                    continue
                if current.state is KeySlotState.REVOKED:
                    raise KeyCustodyConflict()
                if not self._active_slot_matches(
                    current,
                    material,
                    envelope_revision=envelope,
                    root_key_version=root_version,
                ):
                    raise KeyCustodyConflict()
                replacements.append(current)
            try:
                committed = self._slot_store.compare_and_swap_slots(
                    expected_versions=expected,
                    replacement_rows=tuple(replacements),
                )
            except (ValidationError, KeyCustodyError):
                raise
            except Exception:
                raise KeyCustodyUnavailable() from None
            if committed:
                return
        raise KeyCustodyConflict()

    @staticmethod
    def _validated_grant(grant: object) -> ScopeUnlockGrant:
        if not isinstance(grant, ScopeUnlockGrant):
            raise ScopeGrantDenied()
        try:
            _validate_opaque_id(
                grant.principal_id,
                "Invalid opaque principal identifier.",
            )
            _validate_opaque_id(
                grant.vault_id,
                "Invalid opaque vault identifier.",
            )
            _validate_scope_ids(grant.scope_ids)
            _validate_positive_int(
                grant.authorization_epoch,
                "Invalid authorization epoch.",
            )
            if (
                type(grant.expires_at) not in (int, float)
                or not math.isfinite(grant.expires_at)
            ):
                raise ValidationError("Invalid grant expiry.")
        except (AttributeError, TypeError, ValidationError):
            raise ScopeGrantDenied() from None
        return grant

    @contextmanager
    def lease_scope_keys(
        self,
        grant: ScopeUnlockGrant,
    ) -> Iterator[ReleasedScopeKeys]:
        """Lease exactly the active scope keys named by one consumed grant."""

        trusted_grant = self._validated_grant(grant)
        materials: dict[str, ScopeKeyMaterial] = {}
        stack = ExitStack()
        try:
            stack.__enter__()
            scope_ids = _validate_scope_ids(trusted_grant.scope_ids)
            rows_by_scope = self._read_exact(
                trusted_grant.principal_id,
                trusted_grant.vault_id,
                scope_ids,
            )
            if set(rows_by_scope) != set(scope_ids):
                raise ScopeGrantDenied()
            rows = tuple(rows_by_scope[scope_id] for scope_id in scope_ids)
            root_versions = {
                row.root_key_version
                for row in rows
                if row.state is KeySlotState.ACTIVE
            }
            if (
                any(
                    row.state is not KeySlotState.ACTIVE
                    or row.wrapped_key is None
                    or row.enrolled_envelope_revision is None
                    or row.enrolled_envelope_revision
                    > trusted_grant.authorization_epoch
                    for row in rows
                )
                or len(root_versions) != 1
                or None in root_versions
            ):
                raise ScopeGrantDenied()

            for row in rows:
                assert row.wrapped_key is not None
                assert row.scope_key_version is not None
                backend = self._backend(row.wrapped_key.backend_id)
                plaintext = stack.enter_context(
                    backend.unwrap_key(
                        row.wrapped_key,
                        aad=_slot_aad(row),
                    )
                )
                if (
                    not isinstance(plaintext, bytearray)
                    or len(plaintext) != AES_KEY_BYTES
                ):
                    raise ScopeGrantDenied()
                materials[row.identity.scope_id] = ScopeKeyMaterial(
                    key_version=row.scope_key_version,
                    dek=plaintext,
                )

            # Detect a revoke or rewrap that committed while a backend was
            # releasing keys.  A later revoke may still linearize after this
            # check; the caller must pair provider and session revocation, as
            # required by the existing service contract.
            latest = self._read_exact(
                trusted_grant.principal_id,
                trusted_grant.vault_id,
                scope_ids,
            )
            if any(
                latest.get(scope_id) != rows_by_scope[scope_id]
                for scope_id in scope_ids
            ):
                raise ScopeGrantDenied()
            root_key_version = next(iter(root_versions))
            if root_key_version is None:
                raise ScopeGrantDenied()
            released = ReleasedScopeKeys(
                root_key_version=root_key_version,
                scope_keys=MappingProxyType(materials),
            )
        except ScopeGrantDenied:
            for material in materials.values():
                clear_bytearray(material.dek)
            materials.clear()
            stack.close()
            raise
        except Exception:
            for material in materials.values():
                clear_bytearray(material.dek)
            materials.clear()
            stack.close()
            raise ScopeGrantDenied() from None
        try:
            yield released
        finally:
            for material in materials.values():
                clear_bytearray(material.dek)
            materials.clear()
            stack.close()

    def revoke_scope_keys(
        self,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
    ) -> int:
        """Atomically replace selected active/missing slots with tombstones.

        This blocks later cooperative provider release.  It cannot claw back
        an already leased or independently copied scope key; suspected key
        compromise requires scope-key rotation and record re-encryption.
        """

        principal = _validate_opaque_id(
            principal_id,
            "Invalid opaque principal identifier.",
        )
        vault = _validate_opaque_id(
            vault_id,
            "Invalid opaque vault identifier.",
        )
        scopes = _validate_scope_ids(scope_ids)
        for _ in range(MAX_CAS_ATTEMPTS):
            rows_by_scope = self._read_exact(principal, vault, scopes)
            expected: dict[KeySlotIdentity, int | None] = {}
            replacements: list[KeySlotRow] = []
            changed = 0
            for scope_id in scopes:
                identity = KeySlotIdentity(principal, vault, scope_id)
                current = rows_by_scope.get(scope_id)
                expected[identity] = (
                    None if current is None else current.slot_version
                )
                if current is not None and current.state is KeySlotState.REVOKED:
                    replacements.append(current)
                    continue
                changed += 1
                replacements.append(
                    KeySlotRow(
                        identity=identity,
                        slot_version=(
                            1 if current is None else current.slot_version + 1
                        ),
                        state=KeySlotState.REVOKED,
                        enrolled_envelope_revision=(
                            None
                            if current is None
                            else current.enrolled_envelope_revision
                        ),
                        root_key_version=(
                            None if current is None else current.root_key_version
                        ),
                        scope_key_version=(
                            None if current is None else current.scope_key_version
                        ),
                        wrapped_key=None,
                    )
                )
            if changed == 0:
                return 0
            try:
                committed = self._slot_store.compare_and_swap_slots(
                    expected_versions=expected,
                    replacement_rows=tuple(replacements),
                )
            except (ValidationError, KeyCustodyError):
                raise
            except Exception:
                raise KeyCustodyUnavailable() from None
            if committed:
                return changed
        raise KeyCustodyConflict()

    def rewrap_provider_key(
        self,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
        *,
        destination_backend_id: str,
    ) -> int:
        """Atomically rewrap selected slots under another configured backend.

        The scope key and its cryptographic key version do not change.  The
        destination backend ID must denote one exact provider-key generation;
        calling this method again is then an idempotent no-op.
        """

        principal = _validate_opaque_id(
            principal_id,
            "Invalid opaque principal identifier.",
        )
        vault = _validate_opaque_id(
            vault_id,
            "Invalid opaque vault identifier.",
        )
        scopes = _validate_scope_ids(scope_ids)
        destination = self._backend(
            _validate_text(
                destination_backend_id,
                maximum=MAX_BACKEND_ID_CHARS,
                message="Invalid key-wrapping backend identifier.",
            )
        )

        for _ in range(MAX_CAS_ATTEMPTS):
            rows_by_scope = self._read_exact(principal, vault, scopes)
            if set(rows_by_scope) != set(scopes):
                raise KeyCustodyConflict()
            expected: dict[KeySlotIdentity, int | None] = {}
            replacements: list[KeySlotRow] = []
            changed = 0
            for scope_id in scopes:
                current = rows_by_scope[scope_id]
                if (
                    current.state is not KeySlotState.ACTIVE
                    or current.wrapped_key is None
                    or current.enrolled_envelope_revision is None
                    or current.root_key_version is None
                    or current.scope_key_version is None
                ):
                    raise KeyCustodyConflict()
                expected[current.identity] = current.slot_version
                if current.wrapped_key.backend_id == destination.backend_id:
                    replacements.append(current)
                    continue
                changed += 1
                next_version = current.slot_version + 1
                next_aad = _slot_aad_values(
                    current.identity,
                    enrolled_envelope_revision=(
                        current.enrolled_envelope_revision
                    ),
                    root_key_version=current.root_key_version,
                    scope_key_version=current.scope_key_version,
                    slot_version=next_version,
                    backend_id=destination.backend_id,
                )
                source = self._backend(current.wrapped_key.backend_id)
                with source.unwrap_key(
                    current.wrapped_key,
                    aad=_slot_aad(current),
                ) as plaintext:
                    if (
                        not isinstance(plaintext, bytearray)
                        or len(plaintext) != AES_KEY_BYTES
                    ):
                        raise KeyCustodyUnavailable()
                    wrapped = destination.wrap_key(plaintext, aad=next_aad)
                if (
                    not isinstance(wrapped, WrappedKeyBlob)
                    or wrapped.backend_id != destination.backend_id
                ):
                    raise KeyCustodyUnavailable()
                replacements.append(
                    replace(
                        current,
                        slot_version=next_version,
                        wrapped_key=wrapped,
                    )
                )
            if changed == 0:
                return 0
            try:
                committed = self._slot_store.compare_and_swap_slots(
                    expected_versions=expected,
                    replacement_rows=tuple(replacements),
                )
            except (ValidationError, KeyCustodyError):
                raise
            except Exception:
                raise KeyCustodyUnavailable() from None
            if committed:
                return changed
        raise KeyCustodyConflict()

    def recover_provider_key(
        self,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
        *,
        destination_backend_id: str,
    ) -> RecoveryRewrapResult:
        """Rewrap through explicit break-glass source APIs only.

        This method never calls an ordinary source unwrap.  Every source slot
        must name a configured :class:`RecoveryKeyWrappingBackend`; callers
        should expose this operation only behind a separately authorized
        management boundary.
        """

        principal = _validate_opaque_id(
            principal_id,
            "Invalid opaque principal identifier.",
        )
        vault = _validate_opaque_id(
            vault_id,
            "Invalid opaque vault identifier.",
        )
        scopes = _validate_scope_ids(scope_ids)
        destination = self._backend(
            _validate_text(
                destination_backend_id,
                maximum=MAX_BACKEND_ID_CHARS,
                message="Invalid key-wrapping backend identifier.",
            )
        )

        for _ in range(MAX_CAS_ATTEMPTS):
            rows_by_scope = self._read_exact(principal, vault, scopes)
            if set(rows_by_scope) != set(scopes):
                raise KeyCustodyConflict()
            expected: dict[KeySlotIdentity, int | None] = {}
            replacements: list[KeySlotRow] = []
            provenance: list[RecoveryKeyProvenance] = []
            changed = 0
            for scope_id in scopes:
                current = rows_by_scope[scope_id]
                if (
                    current.state is not KeySlotState.ACTIVE
                    or current.wrapped_key is None
                    or current.enrolled_envelope_revision is None
                    or current.root_key_version is None
                    or current.scope_key_version is None
                ):
                    raise KeyCustodyConflict()
                expected[current.identity] = current.slot_version
                if current.wrapped_key.backend_id == destination.backend_id:
                    # Recovery must actually cross the break-glass boundary
                    # and rewrap every requested slot to a different provider
                    # generation.  Treating this as an idempotent no-op could
                    # unblock a vault while its ordinary primary is unusable.
                    raise KeyCustodyConflict()
                changed += 1
                next_version = current.slot_version + 1
                next_aad = _slot_aad_values(
                    current.identity,
                    enrolled_envelope_revision=(
                        current.enrolled_envelope_revision
                    ),
                    root_key_version=current.root_key_version,
                    scope_key_version=current.scope_key_version,
                    slot_version=next_version,
                    backend_id=destination.backend_id,
                )
                source = self._backend(current.wrapped_key.backend_id)
                if not isinstance(source, RecoveryKeyWrappingBackend):
                    raise KeyCustodyUnavailable()
                with source.unwrap_key_for_recovery(
                    current.wrapped_key,
                    aad=_slot_aad(current),
                ) as recovered:
                    if not isinstance(recovered, RecoveredKeyMaterial):
                        raise KeyCustodyUnavailable()
                    wrapped = destination.wrap_key(
                        recovered.dek,
                        aad=next_aad,
                    )
                    provenance.append(recovered.provenance)
                if (
                    not isinstance(wrapped, WrappedKeyBlob)
                    or wrapped.backend_id != destination.backend_id
                ):
                    raise KeyCustodyUnavailable()
                replacements.append(
                    replace(
                        current,
                        slot_version=next_version,
                        wrapped_key=wrapped,
                    )
                )
            try:
                committed = self._slot_store.compare_and_swap_slots(
                    expected_versions=expected,
                    replacement_rows=tuple(replacements),
                )
            except (ValidationError, KeyCustodyError):
                raise
            except Exception:
                raise KeyCustodyUnavailable() from None
            if committed:
                unique_sources = tuple(dict.fromkeys(provenance))
                if not unique_sources:
                    raise KeyCustodyUnavailable()
                return RecoveryRewrapResult(changed, unique_sources)
        raise KeyCustodyConflict()
