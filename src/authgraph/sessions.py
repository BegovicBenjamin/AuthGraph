"""Short-lived, in-memory vault key sessions."""

from __future__ import annotations

import hashlib
import math
import secrets
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass, field
from typing import Protocol

from .crypto import clear_bytearray
from .errors import SessionUnavailable, ValidationError
from .lifecycle import (
    VaultGuard,
    VaultLifecyclePhase,
    VaultLifecycleState,
    VaultManagementTransition,
    VaultRevisionTransition,
)
from .models import AccessContext

VAULT_GUARD_STRIPES = 64
ABSOLUTE_MAX_TTL_SECONDS = 24 * 60 * 60
SESSION_TOKEN_LENGTH = 43
SESSION_TOKEN_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
DEFAULT_SWEEP_INTERVAL_SECONDS = 1.0
MIN_SWEEP_INTERVAL_SECONDS = 0.01
MAX_SWEEP_INTERVAL_SECONDS = 60.0


@dataclass(slots=True)
class _SessionRecord:
    principal_id: str
    vault_id: str
    envelope_revision: int
    key_version: int
    dek: bytearray = field(repr=False)
    expires_at: float


@dataclass(slots=True)
class SessionLease:
    principal_id: str
    vault_id: str
    envelope_revision: int
    key_version: int
    dek: bytearray = field(repr=False)


class SessionBroker(Protocol):
    """Typed session surface consumed by the v1 service."""

    def vault_guard(
        self,
        principal_id: str,
        vault_id: str,
    ) -> AbstractContextManager[VaultGuard]: ...

    def open(
        self,
        principal_id: str,
        vault_id: str,
        dek: bytes | bytearray | memoryview,
        *,
        envelope_revision: int,
        key_version: int,
        ttl_seconds: int | None = None,
        not_after: float | None = None,
    ) -> AccessContext: ...

    def close(self, context: AccessContext) -> None: ...

    def guarded_lease(
        self,
        context: AccessContext,
    ) -> AbstractContextManager[SessionLease]: ...

    def prepare_revision_change(
        self,
        principal_id: str,
        vault_id: str,
        current_revision: int,
        next_revision: int,
    ) -> VaultRevisionTransition: ...

    def finalize_revision_change(
        self,
        transition: VaultRevisionTransition,
    ) -> VaultLifecycleState: ...

    def reconcile_revision_change(
        self,
        principal_id: str,
        vault_id: str,
        authoritative_revision: int,
    ) -> VaultLifecycleState: ...


class _InMemoryVaultGuard:
    """Thread-owned lifecycle fence used by the in-memory broker."""

    __slots__ = (
        "_active",
        "_broker",
        "_generation",
        "_principal_id",
        "_vault_id",
    )

    def __init__(
        self,
        broker: InMemorySessionBroker,
        principal_id: str,
        vault_id: str,
        generation: int,
    ) -> None:
        self._broker = broker
        self._principal_id = principal_id
        self._vault_id = vault_id
        self._generation = generation
        self._active = True

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def vault_id(self) -> str:
        return self._vault_id

    @property
    def generation(self) -> int:
        return self._generation

    def renew(self) -> None:
        self.assert_active()

    def assert_active(self) -> None:
        self._broker._assert_guard(self)

    def _deactivate(self) -> None:
        self._active = False


class _InMemoryGuardLocal(threading.local):
    def __init__(self) -> None:
        self.held: dict[
            tuple[str, str], tuple[_InMemoryVaultGuard, int]
        ] = {}


class InMemorySessionBroker:
    """Holds transient DEKs in one process and never serializes them.

    This is an MVP boundary, not a production distributed-session design.
    Process restart intentionally locks every vault. Python and other managed
    runtimes cannot guarantee that every temporary secret copy is zeroized.
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
            or type(max_tracked_vaults) is not int
            or default_ttl_seconds <= 0
            or max_ttl_seconds < default_ttl_seconds
            or max_ttl_seconds > ABSOLUTE_MAX_TTL_SECONDS
            or max_tracked_vaults <= 0
        ):
            raise ValidationError("Invalid secure-session broker configuration.")
        if (
            sweep_interval_seconds is not None
            and (
                type(sweep_interval_seconds) not in (int, float)
                or not math.isfinite(sweep_interval_seconds)
                or sweep_interval_seconds < MIN_SWEEP_INTERVAL_SECONDS
                or sweep_interval_seconds > MAX_SWEEP_INTERVAL_SECONDS
            )
        ):
            raise ValidationError("Invalid session-key sweep interval.")
        self._default_ttl = default_ttl_seconds
        self._max_ttl = max_ttl_seconds
        self._max_tracked_vaults = max_tracked_vaults
        self._clock = clock
        self._records: dict[bytes, _SessionRecord] = {}
        self._vault_lifecycle: dict[
            tuple[str, str], VaultLifecycleState
        ] = {}
        self._guard_generations: dict[tuple[str, str], int] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._sweeper_failed = False
        self._guard_state = _InMemoryGuardLocal()
        self._sweep_interval = (
            None
            if sweep_interval_seconds is None
            else float(sweep_interval_seconds)
        )
        self._sweeper_stop = threading.Event()
        self._vault_guards = tuple(
            threading.RLock() for _ in range(VAULT_GUARD_STRIPES)
        )
        self._sweeper: threading.Thread | None = None
        if self._sweep_interval is not None:
            self._sweeper = threading.Thread(
                target=self._sweep_worker,
                name="authgraph-session-key-sweeper",
                daemon=True,
            )
            self._sweeper.start()

    def __enter__(self) -> InMemorySessionBroker:
        with self._lock:
            if self._closed:
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
    def _token_digest(token: str) -> bytes:
        if (
            type(token) is str
            and len(token) == SESSION_TOKEN_LENGTH
            and token.isascii()
            and all(char in SESSION_TOKEN_ALPHABET for char in token)
        ):
            encoded = token.encode("ascii")
        else:
            encoded = b"invalid"
        return hashlib.sha256(encoded).digest()

    @contextmanager
    def vault_guard(
        self,
        principal_id: str,
        vault_id: str,
    ) -> Iterator[VaultGuard]:
        """Serialize lifecycle and data operations for one local vault."""

        if (
            not isinstance(principal_id, str)
            or not principal_id
            or len(principal_id) > 256
            or not isinstance(vault_id, str)
            or not vault_id
            or len(vault_id) > 256
        ):
            raise ValidationError("Invalid secure-session scope.")
        digest = hashlib.sha256(
            principal_id.encode("utf-8")
            + b"\x00"
            + vault_id.encode("utf-8")
        ).digest()
        guard_index = (
            int.from_bytes(digest[:4], "big") % len(self._vault_guards)
        )
        guard = self._vault_guards[guard_index]
        scope = (principal_id, vault_id)
        guard.acquire()
        held = self._guard_state.held
        existing = held.get(scope)
        prior_depth = 0 if existing is None else existing[1]
        with self._lock:
            closed_to_new_work = self._closed and prior_depth == 0
        if closed_to_new_work:
            guard.release()
            raise SessionUnavailable()
        if existing is None:
            with self._lock:
                generation = self._guard_generations.get(scope, 0) + 1
                self._guard_generations[scope] = generation
            handle = _InMemoryVaultGuard(
                self,
                principal_id,
                vault_id,
                generation,
            )
        else:
            handle = existing[0]
        held[scope] = (handle, prior_depth + 1)
        try:
            yield handle
        finally:
            next_depth = held[scope][1] - 1
            if next_depth:
                held[scope] = (handle, next_depth)
            else:
                del held[scope]
                handle._deactivate()
            guard.release()

    def _assert_guard(self, guard: _InMemoryVaultGuard) -> None:
        scope = (guard.principal_id, guard.vault_id)
        held = self._guard_state.held
        existing = held.get(scope)
        with self._lock:
            valid = (
                guard._active
                and not self._closed
                and self._guard_generations.get(scope) == guard.generation
                and existing is not None
                and existing[0] is guard
                and existing[1] > 0
            )
        if not valid:
            raise SessionUnavailable()

    def _current_guard(
        self,
        principal_id: str,
        vault_id: str,
    ) -> _InMemoryVaultGuard:
        existing = self._guard_state.held.get((principal_id, vault_id))
        if existing is None:
            raise SessionUnavailable()
        guard = existing[0]
        guard.assert_active()
        return guard

    def open(
        self,
        principal_id: str,
        vault_id: str,
        dek: bytes | bytearray | memoryview,
        *,
        envelope_revision: int,
        key_version: int,
        ttl_seconds: int | None = None,
        not_after: float | None = None,
    ) -> AccessContext:
        """Open a session while serialized against vault lifecycle changes."""

        with self.vault_guard(principal_id, vault_id):
            return self._open_under_guard(
                principal_id,
                vault_id,
                dek,
                envelope_revision=envelope_revision,
                key_version=key_version,
                ttl_seconds=ttl_seconds,
                not_after=not_after,
            )

    def _open_under_guard(
        self,
        principal_id: str,
        vault_id: str,
        dek: bytes | bytearray | memoryview,
        *,
        envelope_revision: int,
        key_version: int,
        ttl_seconds: int | None = None,
        not_after: float | None = None,
    ) -> AccessContext:
        guard = self._current_guard(principal_id, vault_id)
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        if type(ttl) is not int or ttl <= 0 or ttl > self._max_ttl:
            raise ValidationError("Requested secure-session TTL is not allowed.")
        if not_after is not None and (
            type(not_after) not in (int, float)
            or not math.isfinite(not_after)
        ):
            raise ValidationError("Invalid absolute session expiry.")
        if (
            not isinstance(principal_id, str)
            or not principal_id
            or len(principal_id) > 256
            or not isinstance(vault_id, str)
            or not vault_id
            or len(vault_id) > 256
            or not isinstance(dek, (bytes, bytearray, memoryview))
            or (
                dek.nbytes if isinstance(dek, memoryview) else len(dek)
            ) != 32
            or type(envelope_revision) is not int
            or envelope_revision <= 0
            or type(key_version) is not int
            or key_version <= 0
        ):
            raise ValidationError("Invalid vault key material.")
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise SessionUnavailable()
        expires_at = now + ttl
        if not_after is not None:
            expires_at = min(expires_at, float(not_after))
        if not math.isfinite(expires_at) or expires_at <= now:
            raise SessionUnavailable()
        stale_revision = False
        with self._lock:
            guard.assert_active()
            self._remove_expired_locked(now)
            scope = (principal_id, vault_id)
            if self._closed:
                stale_revision = True
            else:
                lifecycle = self._vault_lifecycle.get(scope)
                if lifecycle is None:
                    if len(self._vault_lifecycle) >= self._max_tracked_vaults:
                        stale_revision = True
                    else:
                        lifecycle = VaultLifecycleState(
                            principal_id,
                            vault_id,
                            VaultLifecyclePhase.ACTIVE,
                            envelope_revision,
                            None,
                            1,
                        )
                        self._vault_lifecycle[scope] = lifecycle
                elif (
                    lifecycle.phase is not VaultLifecyclePhase.ACTIVE
                    or envelope_revision != lifecycle.current_revision
                ):
                    stale_revision = True
                if not stale_revision:
                    for digest, existing in list(self._records.items()):
                        if (
                            existing.principal_id == principal_id
                            and existing.vault_id == vault_id
                            and existing.envelope_revision < envelope_revision
                        ):
                            removed = self._records.pop(digest)
                            clear_bytearray(removed.dek)
                    token = secrets.token_urlsafe(32)
                    digest = self._token_digest(token)
                    while digest in self._records:
                        token = secrets.token_urlsafe(32)
                        digest = self._token_digest(token)
                    self._records[digest] = _SessionRecord(
                        principal_id=principal_id,
                        vault_id=vault_id,
                        envelope_revision=envelope_revision,
                        key_version=key_version,
                        dek=bytearray(dek),
                        expires_at=expires_at,
                    )
        if stale_revision:
            raise SessionUnavailable()
        return AccessContext(principal_id=principal_id, session_token=token)

    @contextmanager
    def guarded_lease(self, context: AccessContext) -> Iterator[SessionLease]:
        """Hold the vault lifecycle guard for the entire data operation."""

        digest = self._token_digest(context.session_token)
        with self._lock:
            if self._closed:
                raise SessionUnavailable()
            record = self._records.get(digest)
            if record is None or record.principal_id != context.principal_id:
                raise SessionUnavailable()
            principal_id = record.principal_id
            vault_id = record.vault_id
        with self.vault_guard(principal_id, vault_id):
            with self._lease_under_guard(context) as lease:
                yield lease

    @contextmanager
    def lease(self, context: AccessContext) -> Iterator[SessionLease]:
        """Borrow a DEK under the same lifecycle guard used by the service."""

        with self.guarded_lease(context) as lease:
            yield lease

    @contextmanager
    def _lease_under_guard(
        self,
        context: AccessContext,
    ) -> Iterator[SessionLease]:
        """Borrow a short-lived DEK copy after checking principal and expiry."""

        digest = self._token_digest(context.session_token)
        leased_key: bytearray | None = None
        with self._lock:
            if self._closed:
                raise SessionUnavailable()
            record = self._records.get(digest)
            now = self._clock()
            valid_clock = type(now) in (int, float) and math.isfinite(now)
            lifecycle = (
                self._vault_lifecycle.get((record.principal_id, record.vault_id))
                if record is not None
                else None
            )
            expired_or_stale = record is not None and (
                not valid_clock
                or record.expires_at <= now
                or (
                    lifecycle is not None
                    and (
                        lifecycle.phase is not VaultLifecyclePhase.ACTIVE
                        or record.envelope_revision
                        != lifecycle.current_revision
                    )
                )
            )
            if (
                record is None
                or expired_or_stale
                or record.principal_id != context.principal_id
            ):
                if expired_or_stale:
                    removed = self._records.pop(digest)
                    clear_bytearray(removed.dek)
                raise SessionUnavailable()
            leased_key = bytearray(record.dek)
            lease = SessionLease(
                principal_id=record.principal_id,
                vault_id=record.vault_id,
                envelope_revision=record.envelope_revision,
                key_version=record.key_version,
                dek=leased_key,
            )
        try:
            yield lease
        finally:
            if leased_key is not None:
                clear_bytearray(leased_key)

    def close(self, context: AccessContext) -> None:
        digest = self._token_digest(context.session_token)
        with self._lock:
            record = self._records.get(digest)
            if record is None or record.principal_id != context.principal_id:
                raise SessionUnavailable()
            principal_id = record.principal_id
            vault_id = record.vault_id
        with self.vault_guard(principal_id, vault_id):
            with self._lock:
                record = self._records.get(digest)
                if record is None or record.principal_id != context.principal_id:
                    raise SessionUnavailable()
                removed = self._records.pop(digest)
                clear_bytearray(removed.dek)

    def revoke_vault(self, principal_id: str, vault_id: str) -> int:
        """Lock every existing session without disabling a future unlock."""

        with self.vault_guard(principal_id, vault_id):
            with self._lock:
                return self._revoke_vault_locked(principal_id, vault_id)

    def _revoke_vault_locked(self, principal_id: str, vault_id: str) -> int:
        revoked = 0
        for digest, record in list(self._records.items()):
            if (
                record.principal_id == principal_id
                and record.vault_id == vault_id
            ):
                removed = self._records.pop(digest)
                clear_bytearray(removed.dek)
                revoked += 1
        return revoked

    @staticmethod
    def _validate_revision_pair(
        current_revision: int,
        next_revision: int,
    ) -> None:
        if (
            type(current_revision) is not int
            or current_revision <= 0
            or type(next_revision) is not int
            or next_revision != current_revision + 1
        ):
            raise ValidationError("Invalid envelope revision transition.")

    def _active_state_locked(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> VaultLifecycleState:
        scope = (principal_id, vault_id)
        state = self._vault_lifecycle.get(scope)
        if state is None:
            if len(self._vault_lifecycle) >= self._max_tracked_vaults:
                raise SessionUnavailable()
            state = VaultLifecycleState(
                principal_id,
                vault_id,
                VaultLifecyclePhase.ACTIVE,
                envelope_revision,
                None,
                1,
            )
            self._vault_lifecycle[scope] = state
        if (
            state.phase is not VaultLifecyclePhase.ACTIVE
            or state.current_revision != envelope_revision
        ):
            raise SessionUnavailable()
        return state

    def prepare_revision_change(
        self,
        principal_id: str,
        vault_id: str,
        current_revision: int,
        next_revision: int,
    ) -> VaultRevisionTransition:
        """Persist a fail-closed revision intent before an envelope CAS."""

        self._validate_revision_pair(current_revision, next_revision)
        with self.vault_guard(principal_id, vault_id) as guard:
            with self._lock:
                guard.assert_active()
                state = self._active_state_locked(
                    principal_id,
                    vault_id,
                    current_revision,
                )
                pending = VaultLifecycleState(
                    principal_id,
                    vault_id,
                    VaultLifecyclePhase.REVISION_PENDING,
                    current_revision,
                    next_revision,
                    state.generation + 1,
                )
                self._vault_lifecycle[(principal_id, vault_id)] = pending
                self._revoke_vault_locked(principal_id, vault_id)
                return VaultRevisionTransition(
                    principal_id,
                    vault_id,
                    current_revision,
                    next_revision,
                    pending.generation,
                )

    def finalize_revision_change(
        self,
        transition: VaultRevisionTransition,
    ) -> VaultLifecycleState:
        """Activate the prepared revision after the graph CAS is committed."""

        if not isinstance(transition, VaultRevisionTransition):
            raise ValidationError("Invalid envelope revision transition.")
        with self.vault_guard(
            transition.principal_id,
            transition.vault_id,
        ) as guard:
            with self._lock:
                guard.assert_active()
                state = self._vault_lifecycle.get(
                    (transition.principal_id, transition.vault_id)
                )
                if (
                    state is None
                    or state.phase is not VaultLifecyclePhase.REVISION_PENDING
                    or state.current_revision != transition.current_revision
                    or state.next_revision != transition.next_revision
                    or state.generation != transition.generation
                ):
                    raise SessionUnavailable()
                active = VaultLifecycleState(
                    transition.principal_id,
                    transition.vault_id,
                    VaultLifecyclePhase.ACTIVE,
                    transition.next_revision,
                    None,
                    state.generation + 1,
                )
                self._vault_lifecycle[
                    (transition.principal_id, transition.vault_id)
                ] = active
                return active

    def reconcile_revision_change(
        self,
        principal_id: str,
        vault_id: str,
        authoritative_revision: int,
    ) -> VaultLifecycleState:
        """Resolve PENDING only from the trusted graph's exact revision."""

        if type(authoritative_revision) is not int or authoritative_revision <= 0:
            raise ValidationError("Invalid authoritative envelope revision.")
        with self.vault_guard(principal_id, vault_id) as guard:
            with self._lock:
                guard.assert_active()
                state = self._vault_lifecycle.get((principal_id, vault_id))
                if (
                    state is None
                    or state.phase is not VaultLifecyclePhase.REVISION_PENDING
                    or authoritative_revision
                    not in (state.current_revision, state.next_revision)
                ):
                    raise SessionUnavailable()
                active = VaultLifecycleState(
                    principal_id,
                    vault_id,
                    VaultLifecyclePhase.ACTIVE,
                    authoritative_revision,
                    None,
                    state.generation + 1,
                )
                self._vault_lifecycle[(principal_id, vault_id)] = active
                self._revoke_vault_locked(principal_id, vault_id)
                return active

    def begin_management_transition(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> VaultManagementTransition:
        """Block admission and revoke sessions before key management work."""

        if type(envelope_revision) is not int or envelope_revision <= 0:
            raise ValidationError("Invalid management envelope revision.")
        with self.vault_guard(principal_id, vault_id) as guard:
            with self._lock:
                guard.assert_active()
                state = self._vault_lifecycle.get((principal_id, vault_id))
                if state is not None and state.phase is VaultLifecyclePhase.BLOCKED:
                    raise SessionUnavailable()
                state = self._active_state_locked(
                    principal_id,
                    vault_id,
                    envelope_revision,
                )
                blocked = VaultLifecycleState(
                    principal_id,
                    vault_id,
                    VaultLifecyclePhase.BLOCKED,
                    envelope_revision,
                    None,
                    state.generation + 1,
                )
                self._vault_lifecycle[(principal_id, vault_id)] = blocked
                self._revoke_vault_locked(principal_id, vault_id)
                return VaultManagementTransition(
                    principal_id,
                    vault_id,
                    envelope_revision,
                    blocked.generation,
                )

    def finalize_management_transition(
        self,
        transition: VaultManagementTransition,
    ) -> VaultLifecycleState:
        """Restore ACTIVE only for the exact fenced BLOCKED generation."""

        if not isinstance(transition, VaultManagementTransition):
            raise ValidationError("Invalid management transition.")
        return self.reconcile_management_transition(
            transition.principal_id,
            transition.vault_id,
            transition.envelope_revision,
            transition.generation,
        )

    def reconcile_management_transition(
        self,
        principal_id: str,
        vault_id: str,
        authoritative_revision: int,
        blocked_generation: int,
    ) -> VaultLifecycleState:
        """Explicitly unblock a verified BLOCKED generation after recovery."""

        if (
            type(authoritative_revision) is not int
            or authoritative_revision <= 0
            or type(blocked_generation) is not int
            or blocked_generation <= 0
        ):
            raise ValidationError("Invalid management reconciliation.")
        with self.vault_guard(principal_id, vault_id) as guard:
            with self._lock:
                guard.assert_active()
                state = self._vault_lifecycle.get((principal_id, vault_id))
                if (
                    state is None
                    or state.phase is not VaultLifecyclePhase.BLOCKED
                    or state.current_revision != authoritative_revision
                    or state.generation != blocked_generation
                ):
                    raise SessionUnavailable()
                active = VaultLifecycleState(
                    principal_id,
                    vault_id,
                    VaultLifecyclePhase.ACTIVE,
                    authoritative_revision,
                    None,
                    state.generation + 1,
                )
                self._vault_lifecycle[(principal_id, vault_id)] = active
                return active

    def get_lifecycle_state(
        self,
        principal_id: str,
        vault_id: str,
    ) -> VaultLifecycleState | None:
        """Return immutable lifecycle metadata for trusted operations."""

        with self._lock:
            return self._vault_lifecycle.get((principal_id, vault_id))

    def advance_envelope_revision(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> int:
        """Reject stale unlocks and revoke sessions from older envelopes."""

        if type(envelope_revision) is not int or envelope_revision <= 0:
            raise ValidationError("Envelope revision must be a positive integer.")
        with self.vault_guard(principal_id, vault_id) as guard:
            with self._lock:
                guard.assert_active()
                scope = (principal_id, vault_id)
                state = self._vault_lifecycle.get(scope)
                if state is None:
                    if len(self._vault_lifecycle) >= self._max_tracked_vaults:
                        raise SessionUnavailable()
                    state = VaultLifecycleState(
                        principal_id,
                        vault_id,
                        VaultLifecyclePhase.ACTIVE,
                        envelope_revision,
                        None,
                        1,
                    )
                    self._vault_lifecycle[scope] = state
                elif (
                    state.phase is not VaultLifecyclePhase.ACTIVE
                    or envelope_revision < state.current_revision
                ):
                    raise SessionUnavailable()
                elif envelope_revision > state.current_revision:
                    self._vault_lifecycle[scope] = VaultLifecycleState(
                        principal_id,
                        vault_id,
                        VaultLifecyclePhase.ACTIVE,
                        envelope_revision,
                        None,
                        state.generation + 1,
                    )
                revoked = 0
                for digest, record in list(self._records.items()):
                    if (
                        record.principal_id == principal_id
                        and record.vault_id == vault_id
                        and record.envelope_revision < envelope_revision
                    ):
                        removed = self._records.pop(digest)
                        clear_bytearray(removed.dek)
                        revoked += 1
                return revoked

    def _remove_expired_locked(self, now: float) -> int:
        expired = 0
        for digest, record in list(self._records.items()):
            if record.expires_at <= now:
                removed = self._records.pop(digest)
                clear_bytearray(removed.dek)
                expired += 1
        return expired

    def purge_expired(self) -> int:
        now = self._clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            now = float("inf")
        with self._lock:
            expired = self._remove_expired_locked(now)
        return expired

    def _sweep_worker(self) -> None:
        assert self._sweep_interval is not None
        while not self._sweeper_stop.wait(self._sweep_interval):
            try:
                self.purge_expired()
            except Exception:
                # A dead cleanup worker must never silently leave resident
                # keys behind. Stop admission, drain guarded work, and clear
                # all session keys. The health flag lets the host alert.
                with self._lock:
                    self._sweeper_failed = True
                    self._closed = True
                self.close_all()
                return

    def close_all(self) -> int:
        """Stop admission, wait for guarded work, then clear every stored DEK."""

        with self._lock:
            self._closed = True
        self._sweeper_stop.set()
        acquired: list[threading.RLock] = []
        for guard in self._vault_guards:
            guard.acquire()
            acquired.append(guard)
        try:
            with self._lock:
                records = list(self._records.values())
                for record in records:
                    clear_bytearray(record.dek)
                self._records.clear()
                self._vault_lifecycle.clear()
                self._guard_generations.clear()
        finally:
            for guard in reversed(acquired):
                guard.release()
        if (
            self._sweeper is not None
            and self._sweeper is not threading.current_thread()
        ):
            self._sweeper.join()
        return len(records)

    @property
    def active_count(self) -> int:
        self.purge_expired()
        with self._lock:
            return len(self._records)

    @property
    def tracked_vault_count(self) -> int:
        with self._lock:
            return len(self._vault_lifecycle)

    @property
    def resident_session_count(self) -> int:
        """Return stored session count without triggering an opportunistic purge."""

        with self._lock:
            return len(self._records)

    @property
    def sweeper_alive(self) -> bool:
        sweeper = self._sweeper
        return sweeper is not None and sweeper.is_alive()

    @property
    def sweeper_failed(self) -> bool:
        with self._lock:
            return self._sweeper_failed

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed
