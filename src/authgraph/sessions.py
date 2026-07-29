"""Short-lived, in-memory vault key sessions."""

from __future__ import annotations

import hashlib
import math
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Callable, Iterator

from .crypto import clear_bytearray
from .errors import SessionUnavailable, ValidationError
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
        self._vault_revisions: dict[tuple[str, str], int] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._sweeper_failed = False
        self._guard_state = threading.local()
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
    ) -> Iterator[None]:
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
        counts = getattr(self._guard_state, "counts", None)
        if counts is None:
            counts = {}
            self._guard_state.counts = counts
        prior_depth = counts.get(scope, 0)
        with self._lock:
            closed_to_new_work = self._closed and prior_depth == 0
        if closed_to_new_work:
            guard.release()
            raise SessionUnavailable()
        counts[scope] = prior_depth + 1
        try:
            yield
        finally:
            next_depth = counts[scope] - 1
            if next_depth:
                counts[scope] = next_depth
            else:
                del counts[scope]
            guard.release()

    def open(
        self,
        principal_id: str,
        vault_id: str,
        dek: bytes | bytearray | memoryview,
        *,
        envelope_revision: int,
        key_version: int,
        ttl_seconds: int | None = None,
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
    ) -> AccessContext:
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        if type(ttl) is not int or ttl <= 0 or ttl > self._max_ttl:
            raise ValidationError("Requested secure-session TTL is not allowed.")
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
        stale_revision = False
        with self._lock:
            self._remove_expired_locked(now)
            scope = (principal_id, vault_id)
            current_revision = self._vault_revisions.get(scope)
            if self._closed:
                stale_revision = True
            elif (
                current_revision is not None
                and envelope_revision < current_revision
            ):
                stale_revision = True
            else:
                if current_revision is None or envelope_revision > current_revision:
                    if (
                        current_revision is None
                        and len(self._vault_revisions)
                        >= self._max_tracked_vaults
                    ):
                        stale_revision = True
                    else:
                        self._vault_revisions[scope] = envelope_revision
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
                        expires_at=now + ttl,
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
            current_revision = (
                self._vault_revisions.get((record.principal_id, record.vault_id))
                if record is not None
                else None
            )
            expired_or_stale = record is not None and (
                not valid_clock
                or record.expires_at <= now
                or (
                    current_revision is not None
                    and record.envelope_revision < current_revision
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

        revoked = 0
        with self.vault_guard(principal_id, vault_id):
            with self._lock:
                for digest, record in list(self._records.items()):
                    if (
                        record.principal_id == principal_id
                        and record.vault_id == vault_id
                    ):
                        removed = self._records.pop(digest)
                        clear_bytearray(removed.dek)
                        revoked += 1
        return revoked

    def advance_envelope_revision(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> int:
        """Reject stale unlocks and revoke sessions from older envelopes."""

        if type(envelope_revision) is not int or envelope_revision <= 0:
            raise ValidationError("Envelope revision must be a positive integer.")
        revoked = 0
        with self.vault_guard(principal_id, vault_id):
            with self._lock:
                scope = (principal_id, vault_id)
                current_revision = self._vault_revisions.get(scope)
                if (
                    current_revision is not None
                    and envelope_revision < current_revision
                ):
                    raise SessionUnavailable()
                if (
                    current_revision is None
                    and len(self._vault_revisions) >= self._max_tracked_vaults
                ):
                    raise SessionUnavailable()
                self._vault_revisions[scope] = envelope_revision
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
                self._vault_revisions.clear()
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
            return len(self._vault_revisions)

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
