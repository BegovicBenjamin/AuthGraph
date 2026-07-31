"""Trusted policy boundary between authentication evidence and scope keys."""

from __future__ import annotations

import math
import json
import os
import secrets
import threading
import time
import unicodedata
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import (
    Callable,
    ContextManager,
    Iterator,
    Mapping,
    Protocol,
    runtime_checkable,
)

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import AES_KEY_BYTES, NONCE_BYTES, clear_bytearray
from .errors import AuthGraphError, ValidationError
from .otp import OneTimeCodeEvidence, OneTimeCodeEvidenceConsumer
from .scoped_sessions import MAX_SCOPES_PER_SESSION, ScopeKeyMaterial


MAX_PROFILE_TTL_SECONDS = 30 * 60
MAX_EVIDENCE_AGE_SECONDS = 5 * 60
MAX_ACTIVE_GRANTS = 100_000


class ScopeGrantDenied(AuthGraphError):
    """Authentication evidence did not authorize a usable scope grant."""

    def __init__(self) -> None:
        super().__init__("The scoped unlock grant was denied.")


@dataclass(frozen=True, slots=True)
class UnlockProfile:
    """Server-owned mapping from one policy name to scopes and session TTL."""

    profile_id: str
    scope_ids: tuple[str, ...] = field(repr=False)
    session_ttl_seconds: int
    allow_one_time_code: bool = False

    def __post_init__(self) -> None:
        _validate_opaque_id(self.profile_id, "Invalid unlock profile identifier.")
        if (
            not isinstance(self.scope_ids, tuple)
            or not self.scope_ids
            or len(self.scope_ids) > MAX_SCOPES_PER_SESSION
        ):
            raise ValidationError("Invalid unlock profile scope grant.")
        for scope_id in self.scope_ids:
            _validate_opaque_id(
                scope_id,
                "Invalid opaque protection-scope identifier.",
            )
        if len(set(self.scope_ids)) != len(self.scope_ids):
            raise ValidationError("Invalid unlock profile scope grant.")
        if (
            type(self.session_ttl_seconds) is not int
            or self.session_ttl_seconds <= 0
            or self.session_ttl_seconds > MAX_PROFILE_TTL_SECONDS
            or type(self.allow_one_time_code) is not bool
        ):
            raise ValidationError("Invalid unlock profile configuration.")


@dataclass(frozen=True, slots=True)
class ScopeUnlockGrant:
    """Single-use server-side authority to release a fixed scope set."""

    principal_id: str
    profile_id: str
    vault_id: str = field(repr=False)
    scope_ids: tuple[str, ...] = field(repr=False)
    client_binding: str = field(repr=False)
    authorization_epoch: int = field(repr=False)
    evidence_provider: str
    evidence_id: str = field(repr=False)
    issued_at: float
    expires_at: float
    grant_id: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _GrantSnapshot:
    """Policy-owned grant fields that are never exposed to the caller."""

    principal_id: str
    profile_id: str
    vault_id: str
    scope_ids: tuple[str, ...]
    client_binding: str
    authorization_epoch: int
    evidence_provider: str
    evidence_id: str
    issued_at: float
    expires_at: float
    grant_id: str

    def exposed_copy(self) -> ScopeUnlockGrant:
        return ScopeUnlockGrant(
            principal_id=self.principal_id,
            profile_id=self.profile_id,
            vault_id=self.vault_id,
            scope_ids=self.scope_ids,
            client_binding=self.client_binding,
            authorization_epoch=self.authorization_epoch,
            evidence_provider=self.evidence_provider,
            evidence_id=self.evidence_id,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            grant_id=self.grant_id,
        )

    def matches(self, grant: ScopeUnlockGrant) -> bool:
        """Compare both values and concrete field types to detect mutation."""

        expected = (
            self.principal_id,
            self.profile_id,
            self.vault_id,
            self.scope_ids,
            self.client_binding,
            self.authorization_epoch,
            self.evidence_provider,
            self.evidence_id,
            self.issued_at,
            self.expires_at,
            self.grant_id,
        )
        actual = (
            grant.principal_id,
            grant.profile_id,
            grant.vault_id,
            grant.scope_ids,
            grant.client_binding,
            grant.authorization_epoch,
            grant.evidence_provider,
            grant.evidence_id,
            grant.issued_at,
            grant.expires_at,
            grant.grant_id,
        )
        return all(
            type(candidate) is type(original) and candidate == original
            for candidate, original in zip(actual, expected, strict=True)
        )


@dataclass(frozen=True, slots=True)
class _PendingGrant:
    """One exposed capability plus its independent policy-owned snapshot."""

    exposed: ScopeUnlockGrant
    snapshot: _GrantSnapshot


@dataclass(slots=True)
class ReleasedScopeKeys:
    """Mutable keys leased by a trusted KMS/HSM integration.

    The values are valid only inside the provider's release context.
    ``ScopedAuthGraphService`` also clears every buffer after use.
    """

    root_key_version: int
    scope_keys: Mapping[str, ScopeKeyMaterial] = field(repr=False)


@runtime_checkable
class ScopeKeyReleaseProvider(Protocol):
    """KMS/HSM boundary that leases only keys named by a consumed grant."""

    def lease_scope_keys(
        self,
        grant: ScopeUnlockGrant,
    ) -> ContextManager[ReleasedScopeKeys]: ...


@runtime_checkable
class ScopeKeyEnrollmentProvider(Protocol):
    """Management boundary that wraps/stores scope keys in a KMS/HSM."""

    def enroll_scope_keys(
        self,
        *,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        root_key_version: int,
        scope_keys: Mapping[str, ScopeKeyMaterial],
    ) -> None: ...


@dataclass(slots=True)
class _InMemoryScopeSlot:
    root_key_version: int
    scope_key_version: int
    nonce: bytes
    ciphertext: bytearray = field(repr=False)


def _provider_slot_aad(
    principal_id: str,
    vault_id: str,
    scope_id: str,
    root_key_version: int,
    scope_key_version: int,
) -> bytes:
    return json.dumps(
        [
            "authgraph",
            "in-memory-scope-key-provider",
            1,
            principal_id,
            vault_id,
            scope_id,
            root_key_version,
            scope_key_version,
        ],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")


class InMemoryScopeKeyProvider:
    """Synthetic-test key provider; replace with a real KMS/HSM in production.

    It keeps one random process-local wrapping key and only encrypted scope-key
    slots. Restart or ``close()`` intentionally destroys release capability.
    Compromise of this process can expose every enrolled scope, so this class
    is not production key custody.
    """

    def __init__(self) -> None:
        self._wrapping_key = bytearray(os.urandom(AES_KEY_BYTES))
        self._slots: dict[
            tuple[str, str, str],
            _InMemoryScopeSlot,
        ] = {}
        self._lock = threading.RLock()
        self._closed = False

    @staticmethod
    def _clear_slot(slot: _InMemoryScopeSlot) -> None:
        clear_bytearray(slot.ciphertext)

    def enroll_scope_keys(
        self,
        *,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        root_key_version: int,
        scope_keys: Mapping[str, ScopeKeyMaterial],
    ) -> None:
        _validate_opaque_id(
            principal_id,
            "Invalid opaque principal identifier.",
        )
        _validate_opaque_id(vault_id, "Invalid opaque vault identifier.")
        if (
            type(envelope_revision) is not int
            or envelope_revision <= 0
            or type(root_key_version) is not int
            or root_key_version <= 0
            or not isinstance(scope_keys, Mapping)
        ):
            raise ValidationError("Invalid scope-key enrollment metadata.")
        copied = dict(scope_keys)
        if not copied or len(copied) > MAX_SCOPES_PER_SESSION:
            raise ValidationError("Invalid scope-key enrollment set.")
        pending: dict[tuple[str, str, str], _InMemoryScopeSlot] = {}
        try:
            with self._lock:
                if self._closed:
                    raise ScopeGrantDenied()
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
                        raise ValidationError(
                            "Invalid scope-key enrollment material."
                        )
                    nonce = os.urandom(NONCE_BYTES)
                    aad = _provider_slot_aad(
                        principal_id,
                        vault_id,
                        scope_id,
                        root_key_version,
                        material.key_version,
                    )
                    pending[(principal_id, vault_id, scope_id)] = (
                        _InMemoryScopeSlot(
                            root_key_version=root_key_version,
                            scope_key_version=material.key_version,
                            nonce=nonce,
                            ciphertext=bytearray(
                                AESGCM(self._wrapping_key).encrypt(
                                    nonce,
                                    material.dek,
                                    aad,
                                )
                            ),
                        )
                    )
                for slot_key, slot in pending.items():
                    prior = self._slots.get(slot_key)
                    if prior is not None:
                        self._clear_slot(prior)
                    self._slots[slot_key] = slot
                pending.clear()
        finally:
            for slot in pending.values():
                self._clear_slot(slot)

    @contextmanager
    def lease_scope_keys(
        self,
        grant: ScopeUnlockGrant,
    ) -> Iterator[ReleasedScopeKeys]:
        if not isinstance(grant, ScopeUnlockGrant):
            raise ScopeGrantDenied()
        materials: dict[str, ScopeKeyMaterial] = {}
        with self._lock:
            try:
                if self._closed:
                    raise ScopeGrantDenied()
                slots = {
                    scope_id: self._slots.get(
                        (grant.principal_id, grant.vault_id, scope_id)
                    )
                    for scope_id in grant.scope_ids
                }
                if (
                    not slots
                    or any(slot is None for slot in slots.values())
                ):
                    raise ScopeGrantDenied()
                root_versions = {
                    slot.root_key_version
                    for slot in slots.values()
                    if slot is not None
                }
                if len(root_versions) != 1:
                    raise ScopeGrantDenied()
                root_key_version = next(iter(root_versions))
                for scope_id, slot in slots.items():
                    if slot is None:
                        raise ScopeGrantDenied()
                    aad = _provider_slot_aad(
                        grant.principal_id,
                        grant.vault_id,
                        scope_id,
                        root_key_version,
                        slot.scope_key_version,
                    )
                    plaintext = bytearray(
                        AESGCM(self._wrapping_key).decrypt(
                            slot.nonce,
                            slot.ciphertext,
                            aad,
                        )
                    )
                    if len(plaintext) != AES_KEY_BYTES:
                        clear_bytearray(plaintext)
                        raise InvalidTag()
                    materials[scope_id] = ScopeKeyMaterial(
                        key_version=slot.scope_key_version,
                        dek=plaintext,
                    )
                    del plaintext
                released = ReleasedScopeKeys(
                    root_key_version=root_key_version,
                    scope_keys=materials,
                )
            except (
                InvalidTag,
                KeyError,
                TypeError,
                ValueError,
                ScopeGrantDenied,
            ):
                for material in materials.values():
                    clear_bytearray(material.dek)
                raise ScopeGrantDenied() from None
            try:
                yield released
            finally:
                for material in materials.values():
                    clear_bytearray(material.dek)

    def close(self) -> int:
        with self._lock:
            if self._closed:
                return 0
            self._closed = True
            slots = list(self._slots.values())
            self._slots.clear()
            clear_bytearray(self._wrapping_key)
        for slot in slots:
            self._clear_slot(slot)
        return len(slots)

    def revoke_scope_keys(
        self,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
    ) -> int:
        """Remove and clear selected test-provider key slots."""

        _validate_opaque_id(
            principal_id,
            "Invalid opaque principal identifier.",
        )
        _validate_opaque_id(vault_id, "Invalid opaque vault identifier.")
        if (
            not isinstance(scope_ids, tuple)
            or not scope_ids
            or len(scope_ids) > MAX_SCOPES_PER_SESSION
        ):
            raise ValidationError("Invalid scope-key revocation set.")
        for scope_id in scope_ids:
            _validate_opaque_id(
                scope_id,
                "Invalid opaque protection-scope identifier.",
            )
        if len(set(scope_ids)) != len(scope_ids):
            raise ValidationError("Invalid scope-key revocation set.")
        with self._lock:
            if self._closed:
                raise ScopeGrantDenied()
            removed = [
                self._slots.pop(
                    (principal_id, vault_id, scope_id),
                    None,
                )
                for scope_id in scope_ids
            ]
        present = [slot for slot in removed if slot is not None]
        for slot in present:
            self._clear_slot(slot)
        return len(present)

    def revoke_vault(self, principal_id: str, vault_id: str) -> int:
        """Remove and clear every test-provider slot for one owner vault."""

        _validate_opaque_id(
            principal_id,
            "Invalid opaque principal identifier.",
        )
        _validate_opaque_id(vault_id, "Invalid opaque vault identifier.")
        with self._lock:
            if self._closed:
                raise ScopeGrantDenied()
            keys = [
                slot_key
                for slot_key in self._slots
                if slot_key[:2] == (principal_id, vault_id)
            ]
            removed = [self._slots.pop(slot_key) for slot_key in keys]
        for slot in removed:
            self._clear_slot(slot)
        return len(removed)

    @property
    def enrolled_scope_count(self) -> int:
        with self._lock:
            return len(self._slots)


def _validate_opaque_id(value: str, message: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ValidationError(message)


class ScopeGrantPolicy:
    """Mint and atomically consume scope grants from verified evidence.

    This is process-local policy state. The host chooses profiles at startup,
    maps an authenticated principal to an opaque vault ID, and passes only
    evidence produced by a registered trusted one-time-code consumer. A
    consumer implementation is authentication-critical trusted code.
    """

    def __init__(
        self,
        profiles: Mapping[str, UnlockProfile],
        *,
        max_evidence_age_seconds: int = 60,
        max_active_grants: int = MAX_ACTIVE_GRANTS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(profiles, Mapping):
            raise ValidationError("Unlock profiles must be supplied as a mapping.")
        copied = dict(profiles)
        if not copied:
            raise ValidationError("At least one unlock profile is required.")
        for profile_id, profile in copied.items():
            if (
                not isinstance(profile, UnlockProfile)
                or profile_id != profile.profile_id
            ):
                raise ValidationError("Invalid unlock profile mapping.")
        if (
            type(max_evidence_age_seconds) is not int
            or max_evidence_age_seconds <= 0
            or max_evidence_age_seconds > MAX_EVIDENCE_AGE_SECONDS
            or type(max_active_grants) is not int
            or max_active_grants <= 0
            or max_active_grants > MAX_ACTIVE_GRANTS
            or not callable(clock)
        ):
            raise ValidationError("Invalid scope-grant policy configuration.")
        self._profiles = copied
        self._max_evidence_age = max_evidence_age_seconds
        self._max_active = max_active_grants
        self._clock = clock
        self._active: dict[str, _PendingGrant] = {}
        self._grant_by_object_id: dict[int, str] = {}
        self._lock = threading.RLock()
        self._closed = False

    def _now(self) -> float:
        try:
            now = self._clock()
        except Exception:
            raise ScopeGrantDenied() from None
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ScopeGrantDenied()
        return float(now)

    def authorize_one_time_code(
        self,
        evidence: OneTimeCodeEvidence,
        *,
        vault_id: str,
        evidence_consumer: OneTimeCodeEvidenceConsumer,
    ) -> ScopeUnlockGrant:
        """Exchange fresh OTP evidence for one fixed, single-use scope grant."""

        if (
            not isinstance(evidence, OneTimeCodeEvidence)
            or not isinstance(
                evidence_consumer,
                OneTimeCodeEvidenceConsumer,
            )
        ):
            raise ScopeGrantDenied()
        try:
            _validate_opaque_id(vault_id, "Invalid opaque vault identifier.")
            now = self._now()
        except (AttributeError, TypeError, ValidationError):
            raise ScopeGrantDenied() from None
        with self._lock:
            self._purge_expired_locked(now)
            if self._closed or len(self._active) >= self._max_active:
                raise ScopeGrantDenied()
            for _ in range(3):
                grant_id = secrets.token_urlsafe(32)
                if grant_id not in self._active:
                    break
            else:
                raise ScopeGrantDenied()
            try:
                consumed_evidence = evidence_consumer.consume_evidence(evidence)
                if (
                    not isinstance(
                        consumed_evidence,
                        OneTimeCodeEvidence,
                    )
                    or consumed_evidence is evidence
                ):
                    raise ScopeGrantDenied()
            except Exception:
                raise ScopeGrantDenied() from None
            try:
                _validate_opaque_id(
                    consumed_evidence.principal_id,
                    "Invalid opaque principal identifier.",
                )
                _validate_opaque_id(
                    consumed_evidence.profile_id,
                    "Invalid unlock profile identifier.",
                )
                _validate_opaque_id(
                    consumed_evidence.client_binding,
                    "Invalid opaque client binding.",
                )
                _validate_opaque_id(
                    consumed_evidence.challenge_id,
                    "Invalid opaque evidence identifier.",
                )
                _validate_opaque_id(
                    consumed_evidence.authorization_context,
                    "Invalid opaque authorization context.",
                )
                profile = self._profiles.get(consumed_evidence.profile_id)
                now = self._now()
                grant_expires_at = now + (
                    profile.session_ttl_seconds
                    if profile is not None
                    else 0
                )
                if (
                    profile is None
                    or not profile.allow_one_time_code
                    or consumed_evidence.authorization_context != vault_id
                    or type(consumed_evidence.verified_at)
                    not in (int, float)
                    or type(consumed_evidence.challenge_expires_at)
                    not in (int, float)
                    or not math.isfinite(consumed_evidence.verified_at)
                    or not math.isfinite(
                        consumed_evidence.challenge_expires_at
                    )
                    or consumed_evidence.verified_at > now
                    or (
                        now - consumed_evidence.verified_at
                        > self._max_evidence_age
                    )
                    or (
                        consumed_evidence.verified_at
                        > consumed_evidence.challenge_expires_at
                    )
                    or consumed_evidence.challenge_expires_at <= now
                    or type(consumed_evidence.authorization_epoch) is not int
                    or consumed_evidence.authorization_epoch <= 0
                    or not math.isfinite(grant_expires_at)
                    or grant_expires_at <= now
                ):
                    raise ScopeGrantDenied()
            except (AttributeError, TypeError, ValidationError):
                raise ScopeGrantDenied() from None
            snapshot = _GrantSnapshot(
                principal_id=consumed_evidence.principal_id,
                profile_id=profile.profile_id,
                vault_id=vault_id,
                scope_ids=profile.scope_ids,
                client_binding=consumed_evidence.client_binding,
                authorization_epoch=consumed_evidence.authorization_epoch,
                evidence_provider="one_time_code",
                evidence_id=consumed_evidence.challenge_id,
                issued_at=now,
                expires_at=grant_expires_at,
                grant_id=grant_id,
            )
            grant = snapshot.exposed_copy()
            self._active[grant_id] = _PendingGrant(
                exposed=grant,
                snapshot=snapshot,
            )
            self._grant_by_object_id[id(grant)] = grant_id
            return grant

    def consume(self, grant: ScopeUnlockGrant) -> ScopeUnlockGrant:
        """Consume an unchanged exact grant and return a trusted field copy."""

        if not isinstance(grant, ScopeUnlockGrant):
            raise ScopeGrantDenied()
        now = self._now()
        with self._lock:
            try:
                grant_id = self._grant_by_object_id.get(id(grant))
                pending = (
                    self._active.get(grant_id)
                    if grant_id is not None
                    else None
                )
                if pending is None or pending.exposed is not grant:
                    grant_id = (
                        grant.grant_id
                        if type(grant.grant_id) is str
                        else None
                    )
                    pending = (
                        self._active.get(grant_id)
                        if grant_id is not None
                        else None
                    )
                if pending is not None and grant_id is not None:
                    self._active.pop(grant_id, None)
                    if (
                        self._grant_by_object_id.get(id(pending.exposed))
                        == grant_id
                    ):
                        self._grant_by_object_id.pop(
                            id(pending.exposed),
                            None,
                        )
                if (
                    self._closed
                    or pending is None
                    or pending.exposed is not grant
                    or not pending.snapshot.matches(grant)
                    or pending.snapshot.expires_at <= now
                ):
                    raise ScopeGrantDenied()
                return pending.snapshot.exposed_copy()
            except ScopeGrantDenied:
                raise
            except Exception:
                raise ScopeGrantDenied()
        raise ScopeGrantDenied()

    def _purge_expired_locked(self, now: float) -> int:
        purged = 0
        for grant_id, pending in list(self._active.items()):
            if pending.snapshot.expires_at <= now:
                del self._active[grant_id]
                if (
                    self._grant_by_object_id.get(id(pending.exposed))
                    == grant_id
                ):
                    self._grant_by_object_id.pop(
                        id(pending.exposed),
                        None,
                    )
                purged += 1
        return purged

    def purge_expired(self) -> int:
        now = self._now()
        with self._lock:
            return self._purge_expired_locked(now)

    def close(self) -> int:
        with self._lock:
            self._closed = True
            count = len(self._active)
            self._active.clear()
            self._grant_by_object_id.clear()
            return count

    @property
    def active_count(self) -> int:
        self.purge_expired()
        with self._lock:
            return len(self._active)
