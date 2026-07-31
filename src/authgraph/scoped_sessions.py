"""Short-lived sessions that hold only explicitly granted protection scopes."""

from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Callable, Iterator, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import AES_KEY_BYTES, NONCE_BYTES, clear_bytearray
from .errors import SessionUnavailable, ValidationError
from .models import AccessContext
from .sessions import (
    ABSOLUTE_MAX_TTL_SECONDS,
    DEFAULT_SWEEP_INTERVAL_SECONDS,
    InMemorySessionBroker,
)


MAX_SCOPES_PER_SESSION = 32


@dataclass(slots=True)
class ScopeKeyMaterial:
    """Mutable scope key passed into a new session."""

    key_version: int
    dek: bytearray = field(repr=False)


@dataclass(slots=True)
class ScopedKeyLease:
    """Temporary mutable copy of one session-granted scope key."""

    key_version: int
    dek: bytearray = field(repr=False)


@dataclass(slots=True)
class ScopedSessionLease:
    principal_id: str
    vault_id: str
    envelope_revision: int
    root_key_version: int
    scope_keys: Mapping[str, ScopedKeyLease] = field(repr=False)


@dataclass(slots=True)
class _WrappedSessionScopeKey:
    key_version: int
    nonce: bytes
    ciphertext: bytearray = field(repr=False)


@dataclass(slots=True)
class _ScopedSessionRecord:
    principal_id: str
    vault_id: str
    envelope_revision: int
    root_key_version: int
    scope_keys: dict[str, _WrappedSessionScopeKey] = field(repr=False)
    expires_at: float


def _session_scope_aad(
    principal_id: str,
    vault_id: str,
    envelope_revision: int,
    root_key_version: int,
    scope_id: str,
    scope_key_version: int,
) -> bytes:
    return json.dumps(
        [
            "authgraph",
            "session-scope-key",
            1,
            principal_id,
            vault_id,
            envelope_revision,
            root_key_version,
            scope_id,
            scope_key_version,
        ],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")


class ScopedSessionBroker:
    """Store only granted scope keys under one short-lived in-memory key.

    The underlying session broker holds a random session key. Scope DEKs are
    encrypted under that key while resident and copied into mutable plaintext
    buffers only for a guarded operation.
    """

    def __init__(
        self,
        *,
        default_ttl_seconds: int = 300,
        max_ttl_seconds: int = 1800,
        max_tracked_vaults: int = 100_000,
        sweep_interval_seconds: float | None = DEFAULT_SWEEP_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            type(default_ttl_seconds) is not int
            or type(max_ttl_seconds) is not int
            or default_ttl_seconds <= 0
            or max_ttl_seconds < default_ttl_seconds
            or max_ttl_seconds > ABSOLUTE_MAX_TTL_SECONDS
        ):
            raise ValidationError("Invalid scoped-session broker configuration.")
        self._default_ttl = default_ttl_seconds
        self._max_ttl = max_ttl_seconds
        self._clock = clock
        self._base = InMemorySessionBroker(
            default_ttl_seconds=default_ttl_seconds,
            max_ttl_seconds=max_ttl_seconds,
            max_tracked_vaults=max_tracked_vaults,
            sweep_interval_seconds=sweep_interval_seconds,
            clock=clock,
        )
        self._records: dict[bytes, _ScopedSessionRecord] = {}
        self._lock = threading.RLock()
        self._scope_sweeper_failed = False
        self._scope_sweeper_stop = threading.Event()
        self._scope_sweep_interval = (
            None
            if sweep_interval_seconds is None
            else float(sweep_interval_seconds)
        )
        self._scope_sweeper: threading.Thread | None = None
        if self._scope_sweep_interval is not None:
            self._scope_sweeper = threading.Thread(
                target=self._scope_sweep_worker,
                name="authgraph-scoped-session-sweeper",
                daemon=True,
            )
            self._scope_sweeper.start()

    def __enter__(self) -> ScopedSessionBroker:
        if self.closed:
            raise SessionUnavailable()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close_all()

    @staticmethod
    def _digest(context: AccessContext) -> bytes:
        if not isinstance(context, AccessContext):
            raise SessionUnavailable()
        return InMemorySessionBroker._token_digest(context.session_token)

    @staticmethod
    def _validate_scope_id(scope_id: str) -> None:
        if (
            not isinstance(scope_id, str)
            or not scope_id
            or len(scope_id) > 256
        ):
            raise ValidationError("Invalid opaque protection-scope identifier.")

    @staticmethod
    def _clear_record(record: _ScopedSessionRecord) -> None:
        for wrapped in record.scope_keys.values():
            clear_bytearray(wrapped.ciphertext)
        record.scope_keys.clear()

    @contextmanager
    def vault_guard(
        self,
        principal_id: str,
        vault_id: str,
    ) -> Iterator[None]:
        """Serialize scoped lifecycle operations for one local vault."""

        with self._base.vault_guard(principal_id, vault_id):
            yield

    def open(
        self,
        principal_id: str,
        vault_id: str,
        scope_keys: Mapping[str, ScopeKeyMaterial],
        *,
        envelope_revision: int,
        root_key_version: int,
        ttl_seconds: int | None = None,
        not_after: float | None = None,
    ) -> AccessContext:
        """Open a session containing exactly the supplied protection scopes."""

        if not isinstance(scope_keys, Mapping):
            raise ValidationError("Scope keys must be supplied as a mapping.")
        supplied = dict(scope_keys)
        if not supplied or len(supplied) > MAX_SCOPES_PER_SESSION:
            raise ValidationError(
                f"A session requires between 1 and "
                f"{MAX_SCOPES_PER_SESSION} protection scopes."
            )
        if (
            type(envelope_revision) is not int
            or envelope_revision <= 0
            or type(root_key_version) is not int
            or root_key_version <= 0
        ):
            raise ValidationError("Invalid scoped-session key revision.")
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        if type(ttl) is not int or ttl <= 0 or ttl > self._max_ttl:
            raise ValidationError("Requested secure-session TTL is not allowed.")
        if not_after is not None and (
            type(not_after) not in (int, float)
            or not math.isfinite(not_after)
        ):
            raise ValidationError("Invalid absolute scoped-session expiry.")
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise SessionUnavailable()
        scoped_expires_at = float(now) + ttl
        if not_after is not None:
            scoped_expires_at = min(
                scoped_expires_at,
                float(not_after),
            )
        if (
            not math.isfinite(scoped_expires_at)
            or scoped_expires_at <= now
        ):
            raise SessionUnavailable()

        session_key = bytearray(AESGCM.generate_key(bit_length=256))
        wrapped_scope_keys: dict[str, _WrappedSessionScopeKey] = {}
        try:
            for scope_id, material in supplied.items():
                self._validate_scope_id(scope_id)
                if (
                    not isinstance(material, ScopeKeyMaterial)
                    or type(material.key_version) is not int
                    or material.key_version <= 0
                    or not isinstance(material.dek, bytearray)
                    or len(material.dek) != AES_KEY_BYTES
                ):
                    raise ValidationError("Invalid scoped-session key material.")
                nonce = os.urandom(NONCE_BYTES)
                aad = _session_scope_aad(
                    principal_id,
                    vault_id,
                    envelope_revision,
                    root_key_version,
                    scope_id,
                    material.key_version,
                )
                ciphertext = bytearray(
                    AESGCM(bytes(session_key)).encrypt(
                        nonce,
                        bytes(material.dek),
                        aad,
                    )
                )
                wrapped_scope_keys[scope_id] = _WrappedSessionScopeKey(
                    key_version=material.key_version,
                    nonce=nonce,
                    ciphertext=ciphertext,
                )
            with self._base.vault_guard(principal_id, vault_id):
                context = self._base._open_under_guard(
                    principal_id,
                    vault_id,
                    session_key,
                    envelope_revision=envelope_revision,
                    key_version=root_key_version,
                    ttl_seconds=ttl,
                    not_after=not_after,
                )
                digest = self._digest(context)
                record = _ScopedSessionRecord(
                    principal_id=principal_id,
                    vault_id=vault_id,
                    envelope_revision=envelope_revision,
                    root_key_version=root_key_version,
                    scope_keys=wrapped_scope_keys,
                    expires_at=scoped_expires_at,
                )
                try:
                    with self._lock:
                        if digest in self._records or self._base.closed:
                            raise SessionUnavailable()
                        self._records[digest] = record
                except Exception:
                    self._clear_record(record)
                    try:
                        self._base.close(context)
                    except SessionUnavailable:
                        pass
                    raise
            return context
        except Exception:
            for wrapped in wrapped_scope_keys.values():
                clear_bytearray(wrapped.ciphertext)
            raise
        finally:
            clear_bytearray(session_key)

    @contextmanager
    def guarded_lease(
        self,
        context: AccessContext,
    ) -> Iterator[ScopedSessionLease]:
        """Lease mutable copies of exactly the scopes granted to the session."""

        digest = self._digest(context)
        leased: dict[str, ScopedKeyLease] = {}
        integrity_failed = False
        try:
            with self._base.guarded_lease(context) as base_lease:
                with self._lock:
                    record = self._records.get(digest)
                    if (
                        record is None
                        or record.principal_id != base_lease.principal_id
                        or record.vault_id != base_lease.vault_id
                        or record.envelope_revision
                        != base_lease.envelope_revision
                        or record.root_key_version != base_lease.key_version
                    ):
                        raise SessionUnavailable()
                    wrapped_items = tuple(
                        (
                            scope_id,
                            wrapped.key_version,
                            wrapped.nonce,
                            bytes(wrapped.ciphertext),
                        )
                        for scope_id, wrapped in record.scope_keys.items()
                    )
                try:
                    for (
                        scope_id,
                        key_version,
                        nonce,
                        ciphertext,
                    ) in wrapped_items:
                        aad = _session_scope_aad(
                            base_lease.principal_id,
                            base_lease.vault_id,
                            base_lease.envelope_revision,
                            base_lease.key_version,
                            scope_id,
                            key_version,
                        )
                        plaintext = bytearray(
                            AESGCM(base_lease.dek).decrypt(
                                nonce,
                                ciphertext,
                                aad,
                            )
                        )
                        if len(plaintext) != AES_KEY_BYTES:
                            clear_bytearray(plaintext)
                            raise InvalidTag()
                        leased[scope_id] = ScopedKeyLease(
                            key_version=key_version,
                            dek=plaintext,
                        )
                        del plaintext
                except (InvalidTag, ValueError, TypeError):
                    integrity_failed = True
                    raise SessionUnavailable() from None
                yield ScopedSessionLease(
                    principal_id=base_lease.principal_id,
                    vault_id=base_lease.vault_id,
                    envelope_revision=base_lease.envelope_revision,
                    root_key_version=base_lease.key_version,
                    scope_keys=MappingProxyType(leased),
                )
        finally:
            for material in leased.values():
                clear_bytearray(material.dek)
            leased.clear()
            if integrity_failed:
                try:
                    self.close(context)
                except SessionUnavailable:
                    pass

    def close(self, context: AccessContext) -> None:
        digest = self._digest(context)
        self._base.close(context)
        with self._lock:
            record = self._records.pop(digest, None)
            if record is not None:
                self._clear_record(record)

    def revoke_vault(self, principal_id: str, vault_id: str) -> int:
        revoked = self._base.revoke_vault(principal_id, vault_id)
        with self._lock:
            for digest, record in list(self._records.items()):
                if (
                    record.principal_id == principal_id
                    and record.vault_id == vault_id
                ):
                    self._clear_record(self._records.pop(digest))
        return revoked

    def advance_envelope_revision(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> int:
        revoked = self._base.advance_envelope_revision(
            principal_id,
            vault_id,
            envelope_revision,
        )
        with self._lock:
            for digest, record in list(self._records.items()):
                if (
                    record.principal_id == principal_id
                    and record.vault_id == vault_id
                    and record.envelope_revision < envelope_revision
                ):
                    self._clear_record(self._records.pop(digest))
        return revoked

    def purge_expired(self) -> int:
        purged_base = self._base.purge_expired()
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            now = float("inf")
        purged_records = 0
        with self._lock:
            for digest, record in list(self._records.items()):
                if record.expires_at <= now:
                    self._clear_record(self._records.pop(digest))
                    purged_records += 1
        return max(purged_base, purged_records)

    def _scope_sweep_worker(self) -> None:
        assert self._scope_sweep_interval is not None
        while not self._scope_sweeper_stop.wait(
            self._scope_sweep_interval
        ):
            try:
                self.purge_expired()
                if self._base.sweeper_failed:
                    raise SessionUnavailable()
            except Exception:
                with self._lock:
                    self._scope_sweeper_failed = True
                self.close_all()
                return

    def close_all(self) -> int:
        self._scope_sweeper_stop.set()
        closed = self._base.close_all()
        with self._lock:
            records = list(self._records.values())
            self._records.clear()
        for record in records:
            self._clear_record(record)
        if (
            self._scope_sweeper is not None
            and self._scope_sweeper is not threading.current_thread()
        ):
            self._scope_sweeper.join()
        return max(closed, len(records))

    @property
    def active_count(self) -> int:
        self.purge_expired()
        return self._base.active_count

    @property
    def resident_scope_ciphertext_count(self) -> int:
        self.purge_expired()
        with self._lock:
            return sum(len(record.scope_keys) for record in self._records.values())

    @property
    def sweeper_alive(self) -> bool:
        scoped = self._scope_sweeper
        return (
            self._base.sweeper_alive
            and scoped is not None
            and scoped.is_alive()
        )

    @property
    def sweeper_failed(self) -> bool:
        with self._lock:
            return self._base.sweeper_failed or self._scope_sweeper_failed

    @property
    def closed(self) -> bool:
        return self._base.closed
