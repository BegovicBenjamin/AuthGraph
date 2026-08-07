"""KMS-wrapped, restart-safe scoped sessions backed by SQLite.

Session capabilities and scope DEKs are never stored in plaintext.  The
database holds an HMAC digest of each random session token plus scope keys
wrapped by an injected KMS/HSM backend.  ``BEGIN IMMEDIATE`` linearizes lease,
logout, expiry, and vault-revision fencing across local worker processes.

This is the included durable single-host reference.  Multi-host deployments
need the same broker semantics over a shared strongly consistent state store.
Already-started operations may finish after revocation commits, but no new
lease can begin after that point.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
import stat
import threading
import time
import unicodedata
from collections.abc import Callable, Iterator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from types import MappingProxyType

from .crypto import AES_KEY_BYTES, clear_bytearray
from .errors import SessionUnavailable, ValidationError
from .key_custody import KeyWrappingBackend, WrappedKeyBlob
from .lifecycle import (
    VaultGuard,
    VaultLifecyclePhase,
    VaultLifecycleState,
    VaultManagementTransition,
    VaultRevisionTransition,
)
from .models import AccessContext
from .scoped_sessions import (
    MAX_SCOPES_PER_SESSION,
    ScopedKeyLease,
    ScopedSessionLease,
    ScopeKeyMaterial,
)
from .sessions import (
    ABSOLUTE_MAX_TTL_SECONDS,
    SESSION_TOKEN_ALPHABET,
    SESSION_TOKEN_LENGTH,
)

SESSION_STATE_FORMAT_VERSION = 1
SESSION_TOKEN_HMAC_BYTES = 32
DEFAULT_GUARD_TTL_SECONDS = 60
MAX_GUARD_TTL_SECONDS = 5 * 60
DEFAULT_GUARD_WAIT_SECONDS = 10.0
DEFAULT_LEASE_TTL_SECONDS = 60
MAX_LEASE_TTL_SECONDS = 5 * 60
_DATABASE_INITIALIZE_LOCK = threading.Lock()


class _DurableVaultGuard:
    """Monotonic SQLite-backed vault fence with automatic renewal."""

    __slots__ = (
        "_active",
        "_broker",
        "_generation",
        "_lost",
        "_owner_token",
        "_principal_id",
        "_release_lock",
        "_released",
        "_stop",
        "_started",
        "_thread",
        "_vault_id",
    )

    def __init__(
        self,
        broker: DurableScopedSessionBroker,
        principal_id: str,
        vault_id: str,
        owner_token: str,
        generation: int,
    ) -> None:
        self._broker = broker
        self._principal_id = principal_id
        self._vault_id = vault_id
        self._owner_token = owner_token
        self._generation = generation
        self._active = True
        self._lost = threading.Event()
        self._release_lock = threading.Lock()
        self._released = False
        self._stop = threading.Event()
        self._started = False
        self._thread = threading.Thread(
            target=self._heartbeat,
            name="authgraph-vault-guard-heartbeat",
            daemon=True,
        )

    @property
    def principal_id(self) -> str:
        return self._principal_id

    @property
    def vault_id(self) -> str:
        return self._vault_id

    @property
    def generation(self) -> int:
        return self._generation

    def _start(self) -> None:
        self._thread.start()
        self._started = True

    def _heartbeat(self) -> None:
        interval = max(0.05, self._broker._guard_ttl / 3)
        while not self._stop.wait(interval):
            try:
                self.renew()
            except SessionUnavailable:
                self._lost.set()
                return

    def renew(self) -> None:
        if not self._active or self._lost.is_set():
            raise SessionUnavailable()
        self._broker._renew_guard(self)

    def assert_active(self) -> None:
        if not self._active or self._lost.is_set():
            raise SessionUnavailable()
        self._broker._assert_guard(self)

    def _stop_heartbeat(self) -> None:
        self._stop.set()
        if self._started and self._thread is not threading.current_thread():
            self._thread.join()

    def _deactivate(self) -> None:
        self._active = False

    def _claim_release(self) -> bool:
        with self._release_lock:
            if self._released:
                return False
            self._released = True
            return True


class _DurableGuardLocal(threading.local):
    def __init__(self) -> None:
        self.guards: dict[
            tuple[str, str], tuple[_DurableVaultGuard, int]
        ] = {}


class _DurableLeaseLocal(threading.local):
    def __init__(self) -> None:
        self.depth = 0


def _session_scope_aad(
    token_digest: bytes,
    principal_id: str,
    vault_id: str,
    envelope_revision: int,
    root_key_version: int,
    scope_id: str,
    scope_key_version: int,
    backend_id: str,
) -> bytes:
    return json.dumps(
        [
            "authgraph",
            "durable-scoped-session",
            SESSION_STATE_FORMAT_VERSION,
            token_digest.hex(),
            principal_id,
            vault_id,
            envelope_revision,
            root_key_version,
            scope_id,
            scope_key_version,
            backend_id,
        ],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")


class DurableScopedSessionBroker:
    """Restart-safe scoped-session broker with KMS-wrapped resident keys."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        token_hmac_key: bytes | bytearray | memoryview,
        wrapping_backends: Mapping[str, KeyWrappingBackend],
        *,
        active_backend_id: str,
        default_ttl_seconds: int = 300,
        max_ttl_seconds: int = 1800,
        max_tracked_sessions: int = 100_000,
        guard_ttl_seconds: int = DEFAULT_GUARD_TTL_SECONDS,
        guard_wait_seconds: float = DEFAULT_GUARD_WAIT_SECONDS,
        lease_ttl_seconds: int = DEFAULT_LEASE_TTL_SECONDS,
        busy_timeout_seconds: float = 5.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        try:
            token_key = bytearray(token_hmac_key)
        except (TypeError, ValueError):
            raise ValidationError("Invalid durable-session token key.") from None
        if not isinstance(wrapping_backends, Mapping):
            clear_bytearray(token_key)
            raise TypeError("wrapping_backends must be a mapping.")
        backends = dict(wrapping_backends)
        if (
            len(token_key) < SESSION_TOKEN_HMAC_BYTES
            or not backends
            or active_backend_id not in backends
            or any(
                not isinstance(backend, KeyWrappingBackend)
                or backend_id != backend.backend_id
                for backend_id, backend in backends.items()
            )
            or type(default_ttl_seconds) is not int
            or type(max_ttl_seconds) is not int
            or not 0 < default_ttl_seconds <= max_ttl_seconds
            or max_ttl_seconds > ABSOLUTE_MAX_TTL_SECONDS
            or type(max_tracked_sessions) is not int
            or max_tracked_sessions <= 0
            or type(guard_ttl_seconds) is not int
            or not 0 < guard_ttl_seconds <= MAX_GUARD_TTL_SECONDS
            or type(lease_ttl_seconds) is not int
            or not 0 < lease_ttl_seconds <= MAX_LEASE_TTL_SECONDS
            or type(guard_wait_seconds) not in (int, float)
            or not math.isfinite(guard_wait_seconds)
            or not 0 < guard_wait_seconds <= 60
            or type(busy_timeout_seconds) not in (int, float)
            or not math.isfinite(busy_timeout_seconds)
            or not 0 < busy_timeout_seconds <= 60
            or not callable(clock)
        ):
            clear_bytearray(token_key)
            raise ValidationError("Invalid durable-session configuration.")
        self._path = Path(database_path)
        self._token_key = token_key
        self._backends = MappingProxyType(backends)
        self._active_backend_id = active_backend_id
        self._default_ttl = default_ttl_seconds
        self._max_ttl = max_ttl_seconds
        self._max_tracked = max_tracked_sessions
        self._guard_ttl = guard_ttl_seconds
        self._guard_wait = float(guard_wait_seconds)
        self._lease_ttl = lease_ttl_seconds
        self._timeout = float(busy_timeout_seconds)
        self._clock = clock
        self._state_lock = threading.Lock()
        self._state_changed = threading.Condition(self._state_lock)
        self._active_guards: set[_DurableVaultGuard] = set()
        self._active_local_leases = 0
        self._guard_state = _DurableGuardLocal()
        self._lease_state = _DurableLeaseLocal()
        self._closed = False
        self._prepare_database_file()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect(configure_durability=False)
            self._initialize(connection)
        except Exception:
            clear_bytearray(self._token_key)
            raise SessionUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    def __enter__(self) -> DurableScopedSessionBroker:
        self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close_all()

    def _ensure_open(self) -> None:
        with self._state_lock:
            if self._closed:
                raise SessionUnavailable()

    def _now(self) -> float:
        try:
            now = self._clock()
        except Exception:
            raise SessionUnavailable() from None
        if type(now) not in (int, float) or not math.isfinite(now):
            raise SessionUnavailable()
        return float(now)

    def _prepare_database_file(self) -> None:
        try:
            parent = self._path.parent
            if not parent.is_dir():
                raise SessionUnavailable()
            parent_metadata = parent.lstat()
            if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
                parent_metadata.st_mode
            ):
                raise SessionUnavailable()
            if os.name == "posix" and (
                parent_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(parent_metadata.st_mode) & 0o022
            ):
                raise SessionUnavailable()
            if self._path.exists() or self._path.is_symlink():
                self._validate_database_file()
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                descriptor = os.open(self._path, flags, 0o600)
            except FileExistsError:
                # A concurrent constructor may have securely won O_EXCL.
                # Revalidate the exact path; a symlink or unsafe mode still
                # fails closed rather than being accepted as a race winner.
                self._validate_database_file()
            else:
                os.close(descriptor)
        except SessionUnavailable:
            raise
        except OSError:
            raise SessionUnavailable() from None

    def _validate_database_file(self) -> None:
        metadata = self._path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise SessionUnavailable()
        if os.name == "posix" and (
            metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise SessionUnavailable()

    def _connect(
        self,
        *,
        configure_durability: bool = True,
    ) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=self._timeout,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {int(self._timeout * 1000)}")
        connection.execute("PRAGMA foreign_keys = ON")
        if configure_durability:
            connection.execute("PRAGMA synchronous = FULL")
            synchronous = connection.execute("PRAGMA synchronous").fetchone()
            if synchronous is None or int(synchronous[0]) != 2:
                connection.close()
                raise SessionUnavailable()
        return connection

    def _initialize(self, connection: sqlite3.Connection) -> None:
        schema = """
            CREATE TABLE IF NOT EXISTS authgraph_session (
                token_digest BLOB PRIMARY KEY,
                principal_id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                envelope_revision INTEGER NOT NULL,
                root_key_version INTEGER NOT NULL,
                expires_at REAL NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                active_leases INTEGER NOT NULL DEFAULT 0,
                format_version INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS authgraph_session_vault
                ON authgraph_session(principal_id, vault_id);
            CREATE INDEX IF NOT EXISTS authgraph_session_expiry
                ON authgraph_session(expires_at);

            CREATE TABLE IF NOT EXISTS authgraph_session_scope (
                token_digest BLOB NOT NULL,
                scope_id TEXT NOT NULL,
                scope_key_version INTEGER NOT NULL,
                wrapped_format_version INTEGER NOT NULL,
                backend_id TEXT NOT NULL,
                provider_key_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                PRIMARY KEY(token_digest, scope_id),
                FOREIGN KEY(token_digest) REFERENCES authgraph_session(token_digest)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS authgraph_vault_revision (
                principal_id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                minimum_envelope_revision INTEGER NOT NULL,
                PRIMARY KEY(principal_id, vault_id)
            );

            CREATE TABLE IF NOT EXISTS authgraph_vault_guard (
                principal_id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                owner_token TEXT NOT NULL,
                generation INTEGER NOT NULL DEFAULT 0,
                expires_at REAL NOT NULL,
                PRIMARY KEY(principal_id, vault_id)
            );

            CREATE TABLE IF NOT EXISTS authgraph_vault_guard_generation (
                principal_id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                last_generation INTEGER NOT NULL,
                PRIMARY KEY(principal_id, vault_id)
            );

            CREATE TABLE IF NOT EXISTS authgraph_vault_lifecycle (
                principal_id TEXT NOT NULL,
                vault_id TEXT NOT NULL,
                phase TEXT NOT NULL,
                current_revision INTEGER NOT NULL,
                next_revision INTEGER,
                generation INTEGER NOT NULL,
                PRIMARY KEY(principal_id, vault_id),
                CHECK(phase IN ('ACTIVE', 'REVISION_PENDING', 'BLOCKED')),
                CHECK(current_revision > 0),
                CHECK(generation > 0),
                CHECK(
                    (phase = 'REVISION_PENDING' AND next_revision > current_revision)
                    OR (phase != 'REVISION_PENDING' AND next_revision IS NULL)
                )
            );

            CREATE TABLE IF NOT EXISTS authgraph_session_lease (
                lease_id TEXT PRIMARY KEY,
                token_digest BLOB NOT NULL,
                expires_at REAL NOT NULL,
                FOREIGN KEY(token_digest) REFERENCES authgraph_session(token_digest)
                    ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS authgraph_session_lease_token
                ON authgraph_session_lease(token_digest);
            CREATE INDEX IF NOT EXISTS authgraph_session_lease_expiry
                ON authgraph_session_lease(expires_at);
        """
        deadline = time.monotonic() + self._timeout
        with _DATABASE_INITIALIZE_LOCK:
            while True:
                try:
                    mode = connection.execute(
                        "PRAGMA journal_mode = WAL"
                    ).fetchone()
                    if mode is None or str(mode[0]).lower() != "wal":
                        raise sqlite3.OperationalError(
                            "Could not activate SQLite WAL mode."
                        )
                    connection.execute("PRAGMA synchronous = FULL")
                    break
                except sqlite3.OperationalError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)
            while True:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    break
                except sqlite3.OperationalError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.01)
            try:
                # ``executescript`` implicitly commits, so execute each static
                # DDL statement separately inside this serialized transaction.
                for statement in schema.split(";"):
                    if statement.strip():
                        connection.execute(statement)
                guard_columns = {
                    str(row[1])
                    for row in connection.execute(
                        "PRAGMA table_info(authgraph_vault_guard)"
                    ).fetchall()
                }
                if "generation" not in guard_columns:
                    connection.execute(
                        """
                        ALTER TABLE authgraph_vault_guard
                        ADD COLUMN generation INTEGER NOT NULL DEFAULT 0
                        """
                    )
                connection.execute(
                    """
                    INSERT INTO authgraph_vault_guard_generation(
                        principal_id, vault_id, last_generation
                    )
                    SELECT principal_id, vault_id, generation
                    FROM authgraph_vault_guard
                    WHERE 1 = 1
                    ON CONFLICT(principal_id, vault_id) DO UPDATE SET
                        last_generation = max(
                            authgraph_vault_guard_generation.last_generation,
                            excluded.last_generation
                        )
                    """
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO authgraph_vault_lifecycle(
                        principal_id, vault_id, phase, current_revision,
                        next_revision, generation
                    )
                    SELECT principal_id, vault_id, 'ACTIVE',
                           minimum_envelope_revision, NULL, 1
                    FROM authgraph_vault_revision
                    """
                )
                # The former scalar counter cannot identify crashed owners.
                # Per-lease rows are authoritative; already-copied plaintext
                # keys may finish even if legacy ciphertext is reclaimed.
                connection.execute(
                    "UPDATE authgraph_session SET active_leases = 0"
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    @staticmethod
    def _valid_identifier(value: object) -> bool:
        return (
            isinstance(value, str)
            and bool(value)
            and len(value) <= 256
            and not any(
                unicodedata.category(char).startswith("C") for char in value
            )
        )

    def _token_digest(self, token: object) -> bytes:
        if (
            type(token) is str
            and len(token) == SESSION_TOKEN_LENGTH
            and token.isascii()
            and all(char in SESSION_TOKEN_ALPHABET for char in token)
        ):
            encoded = token.encode("ascii")
        else:
            encoded = b"invalid"
        return hmac.new(
            bytes(self._token_key),
            b"authgraph-durable-session-token-v1\x00" + encoded,
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _validate_scope_keys(
        scope_keys: Mapping[str, ScopeKeyMaterial],
    ) -> dict[str, ScopeKeyMaterial]:
        if not isinstance(scope_keys, Mapping):
            raise ValidationError("Scope keys must be supplied as a mapping.")
        copied = dict(scope_keys)
        if not copied or len(copied) > MAX_SCOPES_PER_SESSION:
            raise ValidationError("Invalid scoped-session key set.")
        for scope_id, material in copied.items():
            if (
                not DurableScopedSessionBroker._valid_identifier(scope_id)
                or not isinstance(material, ScopeKeyMaterial)
                or type(material.key_version) is not int
                or material.key_version <= 0
                or not isinstance(material.dek, bytearray)
                or len(material.dek) != AES_KEY_BYTES
            ):
                raise ValidationError("Invalid scoped-session key material.")
        return copied

    def _backend(self, backend_id: str) -> KeyWrappingBackend:
        backend = self._backends.get(backend_id)
        if backend is None:
            raise SessionUnavailable()
        return backend

    @contextmanager
    def vault_guard(
        self,
        principal_id: str,
        vault_id: str,
    ) -> Iterator[VaultGuard]:
        """Acquire a monotonic, renewed lifecycle fence for one vault."""

        if not self._valid_identifier(principal_id) or not self._valid_identifier(
            vault_id
        ):
            raise ValidationError("Invalid secure-session scope.")
        key = (principal_id, vault_id)
        guards = self._guard_state.guards
        existing = guards.get(key)
        if existing is not None:
            handle, depth = existing
            handle.assert_active()
            guards[key] = (handle, depth + 1)
            try:
                yield handle
            finally:
                current_handle, current_depth = guards[key]
                guards[key] = (current_handle, current_depth - 1)
            return

        self._ensure_open()

        owner = secrets.token_urlsafe(32)
        deadline = time.monotonic() + self._guard_wait
        generation: int | None = None
        while time.monotonic() < deadline:
            now = self._now()
            connection: sqlite3.Connection | None = None
            try:
                connection = self._connect()
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "DELETE FROM authgraph_vault_guard WHERE expires_at <= ?",
                    (now,),
                )
                occupied = connection.execute(
                    """
                    SELECT 1 FROM authgraph_vault_guard
                    WHERE principal_id = ? AND vault_id = ?
                    """,
                    (principal_id, vault_id),
                ).fetchone()
                if occupied is not None:
                    connection.commit()
                else:
                    counter = connection.execute(
                        """
                        SELECT last_generation
                        FROM authgraph_vault_guard_generation
                        WHERE principal_id = ? AND vault_id = ?
                        """,
                        (principal_id, vault_id),
                    ).fetchone()
                    candidate = (
                        1 if counter is None else int(counter[0]) + 1
                    )
                    connection.execute(
                        """
                        INSERT INTO authgraph_vault_guard_generation(
                            principal_id, vault_id, last_generation
                        ) VALUES (?, ?, ?)
                        ON CONFLICT(principal_id, vault_id) DO UPDATE SET
                            last_generation = excluded.last_generation
                        """,
                        (principal_id, vault_id, candidate),
                    )
                    connection.execute(
                        """
                        INSERT INTO authgraph_vault_guard(
                            principal_id, vault_id, owner_token, generation,
                            expires_at
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            principal_id,
                            vault_id,
                            owner,
                            candidate,
                            now + self._guard_ttl,
                        ),
                    )
                    connection.commit()
                    generation = candidate
            except Exception:
                if connection is not None:
                    connection.rollback()
            finally:
                if connection is not None:
                    connection.close()
            if generation is not None:
                break
            time.sleep(0.01)
        if generation is None:
            raise SessionUnavailable()
        handle = _DurableVaultGuard(
            self,
            principal_id,
            vault_id,
            owner,
            generation,
        )
        guards[key] = (handle, 1)
        with self._state_changed:
            admitted = not self._closed
            if admitted:
                self._active_guards.add(handle)
        if not admitted:
            guards.pop(key, None)
            self._force_release_guard(handle)
            raise SessionUnavailable()
        try:
            handle._start()
        except BaseException:
            guards.pop(key, None)
            self._force_release_guard(handle)
            raise SessionUnavailable() from None
        try:
            yield handle
        except BaseException:
            self._release_guard(handle, guards, key, fail_if_lost=False)
            raise
        else:
            self._release_guard(handle, guards, key, fail_if_lost=True)

    def _release_guard(
        self,
        handle: _DurableVaultGuard,
        guards: dict[tuple[str, str], tuple[_DurableVaultGuard, int]],
        key: tuple[str, str],
        *,
        fail_if_lost: bool,
    ) -> None:
        existing = guards.pop(key, None)
        malformed_depth = existing is None or existing != (handle, 1)
        deleted = 0
        claimed = handle._claim_release()
        if claimed:
            handle._stop_heartbeat()
            try:
                deleted = self._delete_guard_row(handle)
            except Exception:
                handle._lost.set()
        else:
            handle._lost.set()
        handle._deactivate()
        with self._state_changed:
            self._active_guards.discard(handle)
            self._state_changed.notify_all()
        if fail_if_lost and (
            malformed_depth
            or not claimed
            or handle._lost.is_set()
            or deleted != 1
        ):
            raise SessionUnavailable()

    def _delete_guard_row(self, handle: _DurableVaultGuard) -> int:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            cursor = connection.execute(
                """
                DELETE FROM authgraph_vault_guard
                WHERE principal_id = ? AND vault_id = ?
                  AND owner_token = ? AND generation = ?
                """,
                (
                    handle.principal_id,
                    handle.vault_id,
                    handle._owner_token,
                    handle.generation,
                ),
            )
            return cursor.rowcount
        finally:
            if connection is not None:
                connection.close()

    def _force_release_guard(self, handle: _DurableVaultGuard) -> bool:
        released = True
        if handle._claim_release():
            handle._stop_heartbeat()
            try:
                released = self._delete_guard_row(handle) == 1
            except Exception:
                released = False
        handle._lost.set()
        handle._deactivate()
        with self._state_changed:
            self._active_guards.discard(handle)
            self._state_changed.notify_all()
        return released

    def _renew_guard(self, guard: _DurableVaultGuard) -> None:
        with self._state_lock:
            if guard not in self._active_guards:
                raise SessionUnavailable()
        now = self._now()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            cursor = connection.execute(
                """
                UPDATE authgraph_vault_guard SET expires_at = ?
                WHERE principal_id = ? AND vault_id = ?
                  AND owner_token = ? AND generation = ?
                  AND expires_at > ?
                """,
                (
                    now + self._guard_ttl,
                    guard.principal_id,
                    guard.vault_id,
                    guard._owner_token,
                    guard.generation,
                    now,
                ),
            )
            if cursor.rowcount != 1:
                guard._lost.set()
                raise SessionUnavailable()
        except SessionUnavailable:
            raise
        except Exception:
            guard._lost.set()
            raise SessionUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    def _assert_guard(self, guard: _DurableVaultGuard) -> None:
        with self._state_lock:
            if guard not in self._active_guards:
                raise SessionUnavailable()
        now = self._now()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            row = connection.execute(
                """
                SELECT owner_token, generation, expires_at
                FROM authgraph_vault_guard
                WHERE principal_id = ? AND vault_id = ?
                """,
                (guard.principal_id, guard.vault_id),
            ).fetchone()
            if (
                row is None
                or not hmac.compare_digest(str(row[0]), guard._owner_token)
                or int(row[1]) != guard.generation
                or float(row[2]) <= now
            ):
                guard._lost.set()
                raise SessionUnavailable()
        except SessionUnavailable:
            raise
        except Exception:
            guard._lost.set()
            raise SessionUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    def _assert_guard_locked(
        self,
        connection: sqlite3.Connection,
        guard: _DurableVaultGuard,
        now: float,
    ) -> None:
        row = connection.execute(
            """
            SELECT owner_token, generation, expires_at
            FROM authgraph_vault_guard
            WHERE principal_id = ? AND vault_id = ?
            """,
            (guard.principal_id, guard.vault_id),
        ).fetchone()
        if (
            row is None
            or not hmac.compare_digest(str(row[0]), guard._owner_token)
            or int(row[1]) != guard.generation
            or float(row[2]) <= now
        ):
            guard._lost.set()
            raise SessionUnavailable()

    def _current_guard(
        self,
        principal_id: str,
        vault_id: str,
    ) -> _DurableVaultGuard:
        existing = self._guard_state.guards.get((principal_id, vault_id))
        if existing is None:
            raise SessionUnavailable()
        handle = existing[0]
        handle.assert_active()
        return handle

    def _ensure_active_revision_locked(
        self,
        connection: sqlite3.Connection,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        *,
        allow_advance: bool,
    ) -> VaultLifecycleState:
        row = connection.execute(
            """
            SELECT phase, current_revision, next_revision, generation
            FROM authgraph_vault_lifecycle
            WHERE principal_id = ? AND vault_id = ?
            """,
            (principal_id, vault_id),
        ).fetchone()
        if row is None:
            state = VaultLifecycleState(
                principal_id,
                vault_id,
                VaultLifecyclePhase.ACTIVE,
                envelope_revision,
                None,
                1,
            )
            connection.execute(
                """
                INSERT INTO authgraph_vault_lifecycle(
                    principal_id, vault_id, phase, current_revision,
                    next_revision, generation
                ) VALUES (?, ?, 'ACTIVE', ?, NULL, 1)
                """,
                (principal_id, vault_id, envelope_revision),
            )
        else:
            try:
                phase = VaultLifecyclePhase(str(row["phase"]))
            except ValueError:
                raise SessionUnavailable() from None
            current = int(row["current_revision"])
            generation = int(row["generation"])
            if (
                phase is not VaultLifecyclePhase.ACTIVE
                or envelope_revision < current
                or (envelope_revision > current and not allow_advance)
            ):
                raise SessionUnavailable()
            if envelope_revision > current:
                cursor = connection.execute(
                    """
                    UPDATE authgraph_vault_lifecycle
                    SET current_revision = ?, generation = generation + 1
                    WHERE principal_id = ? AND vault_id = ?
                      AND phase = 'ACTIVE' AND current_revision = ?
                      AND generation = ?
                    """,
                    (
                        envelope_revision,
                        principal_id,
                        vault_id,
                        current,
                        generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SessionUnavailable()
                connection.execute(
                    """
                    UPDATE authgraph_session SET revoked = 1
                    WHERE principal_id = ? AND vault_id = ?
                      AND envelope_revision < ?
                    """,
                    (principal_id, vault_id, envelope_revision),
                )
                state = VaultLifecycleState(
                    principal_id,
                    vault_id,
                    VaultLifecyclePhase.ACTIVE,
                    envelope_revision,
                    None,
                    generation + 1,
                )
            else:
                state = VaultLifecycleState(
                    principal_id,
                    vault_id,
                    phase,
                    current,
                    row["next_revision"],
                    generation,
                )
        connection.execute(
            """
            INSERT INTO authgraph_vault_revision(
                principal_id, vault_id, minimum_envelope_revision
            ) VALUES (?, ?, ?)
            ON CONFLICT(principal_id, vault_id) DO UPDATE SET
                minimum_envelope_revision = excluded.minimum_envelope_revision
            WHERE excluded.minimum_envelope_revision >=
                  authgraph_vault_revision.minimum_envelope_revision
            """,
            (principal_id, vault_id, envelope_revision),
        )
        return state

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
        """Open only while holding the current monotonic vault fence."""

        with self.vault_guard(principal_id, vault_id) as guard:
            if not isinstance(guard, _DurableVaultGuard):
                raise SessionUnavailable()
            return self._open_under_guard(
                principal_id,
                vault_id,
                scope_keys,
                envelope_revision=envelope_revision,
                root_key_version=root_key_version,
                ttl_seconds=ttl_seconds,
                not_after=not_after,
                guard=guard,
            )

    def _open_under_guard(
        self,
        principal_id: str,
        vault_id: str,
        scope_keys: Mapping[str, ScopeKeyMaterial],
        *,
        envelope_revision: int,
        root_key_version: int,
        ttl_seconds: int | None,
        not_after: float | None,
        guard: _DurableVaultGuard,
    ) -> AccessContext:
        guard.assert_active()
        if not self._valid_identifier(principal_id) or not self._valid_identifier(
            vault_id
        ):
            raise ValidationError("Invalid scoped-session owner.")
        materials = self._validate_scope_keys(scope_keys)
        if (
            type(envelope_revision) is not int
            or envelope_revision <= 0
            or type(root_key_version) is not int
            or root_key_version <= 0
        ):
            raise ValidationError("Invalid scoped-session key revision.")
        ttl = self._default_ttl if ttl_seconds is None else ttl_seconds
        if type(ttl) is not int or not 0 < ttl <= self._max_ttl:
            raise ValidationError("Requested secure-session TTL is not allowed.")
        now = self._now()
        expires_at = now + ttl
        if not_after is not None:
            if (
                type(not_after) not in (int, float)
                or not math.isfinite(not_after)
            ):
                raise ValidationError("Invalid absolute scoped-session expiry.")
            expires_at = min(expires_at, float(not_after))
        if not math.isfinite(expires_at) or expires_at <= now:
            raise SessionUnavailable()

        backend = self._backend(self._active_backend_id)
        for _ in range(3):
            token = secrets.token_urlsafe(32)
            token_digest = self._token_digest(token)
            wrapped_rows: list[tuple[object, ...]] = []
            try:
                for scope_id, material in materials.items():
                    aad = _session_scope_aad(
                        token_digest,
                        principal_id,
                        vault_id,
                        envelope_revision,
                        root_key_version,
                        scope_id,
                        material.key_version,
                        backend.backend_id,
                    )
                    wrapped = backend.wrap_key(material.dek, aad=aad)
                    if (
                        not isinstance(wrapped, WrappedKeyBlob)
                        or wrapped.backend_id != backend.backend_id
                    ):
                        raise SessionUnavailable()
                    wrapped_rows.append(
                        (
                            token_digest,
                            scope_id,
                            material.key_version,
                            wrapped.format_version,
                            wrapped.backend_id,
                            wrapped.key_id,
                            wrapped.algorithm,
                            wrapped.ciphertext,
                        )
                    )
                connection: sqlite3.Connection | None = None
                try:
                    connection = self._connect()
                    connection.execute("BEGIN IMMEDIATE")
                    self._purge_locked(connection, now)
                    self._assert_guard_locked(connection, guard, now)
                    self._ensure_active_revision_locked(
                        connection,
                        principal_id,
                        vault_id,
                        envelope_revision,
                        allow_advance=False,
                    )
                    count = int(
                        connection.execute(
                            "SELECT count(*) FROM authgraph_session WHERE revoked = 0"
                        ).fetchone()[0]
                    )
                    if count >= self._max_tracked:
                        raise SessionUnavailable()
                    connection.execute(
                        """
                        INSERT INTO authgraph_session(
                            token_digest, principal_id, vault_id,
                            envelope_revision, root_key_version, expires_at,
                            revoked, active_leases, format_version
                        ) VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?)
                        """,
                        (
                            token_digest,
                            principal_id,
                            vault_id,
                            envelope_revision,
                            root_key_version,
                            expires_at,
                            SESSION_STATE_FORMAT_VERSION,
                        ),
                    )
                    connection.executemany(
                        """
                        INSERT INTO authgraph_session_scope(
                            token_digest, scope_id, scope_key_version,
                            wrapped_format_version, backend_id,
                            provider_key_id, algorithm, ciphertext
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        wrapped_rows,
                    )
                    self._assert_guard_locked(
                        connection,
                        guard,
                        self._now(),
                    )
                    connection.commit()
                    return AccessContext(principal_id, token)
                except sqlite3.IntegrityError:
                    if connection is not None:
                        connection.rollback()
                    continue
                except Exception:
                    if connection is not None:
                        connection.rollback()
                    raise
                finally:
                    if connection is not None:
                        connection.close()
            except SessionUnavailable:
                raise
            except Exception:
                raise SessionUnavailable() from None
        raise SessionUnavailable()

    @staticmethod
    def _purge_locked(connection: sqlite3.Connection, now: float) -> int:
        expired_sessions = int(
            connection.execute(
                """
                SELECT count(*) FROM authgraph_session
                WHERE expires_at <= ? AND revoked = 0
                """,
                (now,),
            ).fetchone()[0]
        )
        connection.execute(
            "DELETE FROM authgraph_session_lease WHERE expires_at <= ?",
            (now,),
        )
        connection.execute(
            """
            UPDATE authgraph_session SET revoked = 1
            WHERE expires_at <= ? AND revoked = 0
            """,
            (now,),
        )
        connection.execute(
            """
            DELETE FROM authgraph_session AS session
            WHERE revoked = 1 AND NOT EXISTS (
                SELECT 1 FROM authgraph_session_lease AS lease
                WHERE lease.token_digest = session.token_digest
                  AND lease.expires_at > ?
            )
            """
            ,
            (now,),
        )
        return expired_sessions

    @contextmanager
    def _local_lease_admission(self) -> Iterator[None]:
        with self._state_changed:
            if self._closed:
                raise SessionUnavailable()
            self._active_local_leases += 1
            self._lease_state.depth += 1
        try:
            yield
        finally:
            with self._state_changed:
                self._lease_state.depth -= 1
                self._active_local_leases -= 1
                self._state_changed.notify_all()

    @contextmanager
    def guarded_lease(
        self,
        context: AccessContext,
    ) -> Iterator[ScopedSessionLease]:
        """Drainable local wrapper around one durable per-lease row."""

        with self._local_lease_admission():
            with self._guarded_lease_admitted(context) as lease:
                yield lease

    @contextmanager
    def _guarded_lease_admitted(
        self,
        context: AccessContext,
    ) -> Iterator[ScopedSessionLease]:
        if not isinstance(context, AccessContext):
            raise SessionUnavailable()
        digest = self._token_digest(context.session_token)
        now = self._now()
        session: sqlite3.Row | None = None
        scope_rows: list[sqlite3.Row] = []
        connection: sqlite3.Connection | None = None
        acquired = False
        lease_id: str | None = None
        leases: dict[str, ScopedKeyLease] = {}
        stack = ExitStack()
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            self._purge_locked(connection, now)
            session = connection.execute(
                """
                SELECT * FROM authgraph_session
                WHERE token_digest = ? AND principal_id = ?
                  AND revoked = 0 AND expires_at > ?
                  AND format_version = ?
                """,
                (
                    digest,
                    context.principal_id,
                    now,
                    SESSION_STATE_FORMAT_VERSION,
                ),
            ).fetchone()
            if session is None:
                raise SessionUnavailable()
            lifecycle = connection.execute(
                """
                SELECT phase, current_revision
                FROM authgraph_vault_lifecycle
                WHERE principal_id = ? AND vault_id = ?
                """,
                (session["principal_id"], session["vault_id"]),
            ).fetchone()
            if (
                lifecycle is None
                or str(lifecycle["phase"]) != VaultLifecyclePhase.ACTIVE.value
                or int(session["envelope_revision"])
                != int(lifecycle["current_revision"])
            ):
                raise SessionUnavailable()
            scope_rows = connection.execute(
                """
                SELECT * FROM authgraph_session_scope
                WHERE token_digest = ? ORDER BY scope_id
                """,
                (digest,),
            ).fetchall()
            if not scope_rows or len(scope_rows) > MAX_SCOPES_PER_SESSION:
                raise SessionUnavailable()
            lease_id = secrets.token_urlsafe(32)
            lease_expires_at = min(
                float(session["expires_at"]),
                now + self._lease_ttl,
            )
            connection.execute(
                """
                INSERT INTO authgraph_session_lease(
                    lease_id, token_digest, expires_at
                ) VALUES (?, ?, ?)
                """,
                (lease_id, digest, lease_expires_at),
            )
            connection.commit()
            acquired = True
            connection.close()
            connection = None

            stack.__enter__()
            for row in scope_rows:
                scope_id = row["scope_id"]
                key_version = int(row["scope_key_version"])
                backend_id = row["backend_id"]
                wrapped = WrappedKeyBlob(
                    backend_id=backend_id,
                    key_id=row["provider_key_id"],
                    algorithm=row["algorithm"],
                    ciphertext=bytes(row["ciphertext"]),
                    format_version=int(row["wrapped_format_version"]),
                )
                aad = _session_scope_aad(
                    digest,
                    session["principal_id"],
                    session["vault_id"],
                    int(session["envelope_revision"]),
                    int(session["root_key_version"]),
                    scope_id,
                    key_version,
                    backend_id,
                )
                plaintext = stack.enter_context(
                    self._backend(backend_id).unwrap_key(wrapped, aad=aad)
                )
                if not isinstance(plaintext, bytearray) or len(plaintext) != 32:
                    raise SessionUnavailable()
                leases[scope_id] = ScopedKeyLease(key_version, plaintext)
            yield ScopedSessionLease(
                principal_id=session["principal_id"],
                vault_id=session["vault_id"],
                envelope_revision=int(session["envelope_revision"]),
                root_key_version=int(session["root_key_version"]),
                scope_keys=MappingProxyType(leases),
            )
        except SessionUnavailable:
            if connection is not None:
                connection.rollback()
            raise
        except Exception:
            if connection is not None:
                connection.rollback()
            raise SessionUnavailable() from None
        finally:
            if connection is not None:
                connection.close()
            try:
                stack.close()
            finally:
                for lease in leases.values():
                    clear_bytearray(lease.dek)
                leases.clear()
                if acquired and lease_id is not None:
                    self._finish_lease(digest, lease_id)

    def _finish_lease(self, digest: bytes, lease_id: str) -> None:
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM authgraph_session_lease WHERE lease_id = ?",
                (lease_id,),
            )
            connection.execute(
                """
                DELETE FROM authgraph_session AS session
                WHERE token_digest = ? AND revoked = 1 AND NOT EXISTS (
                    SELECT 1 FROM authgraph_session_lease AS lease
                    WHERE lease.token_digest = session.token_digest
                )
                """,
                (digest,),
            )
            connection.commit()
        except Exception:
            if connection is not None:
                connection.rollback()
            raise SessionUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    def close(self, context: AccessContext) -> None:
        if not isinstance(context, AccessContext):
            raise SessionUnavailable()
        digest = self._token_digest(context.session_token)
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            now = self._now()
            self._purge_locked(connection, now)
            row = connection.execute(
                """
                SELECT 1 FROM authgraph_session
                WHERE token_digest = ? AND principal_id = ?
                """,
                (digest, context.principal_id),
            ).fetchone()
            if row is None:
                raise SessionUnavailable()
            connection.execute(
                "UPDATE authgraph_session SET revoked = 1 WHERE token_digest = ?",
                (digest,),
            )
            connection.execute(
                """
                DELETE FROM authgraph_session AS session
                WHERE token_digest = ? AND NOT EXISTS (
                    SELECT 1 FROM authgraph_session_lease AS lease
                    WHERE lease.token_digest = session.token_digest
                      AND lease.expires_at > ?
                )
                """,
                (digest, now),
            )
            connection.commit()
        except SessionUnavailable:
            if connection is not None:
                connection.rollback()
            raise
        except Exception:
            if connection is not None:
                connection.rollback()
            raise SessionUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    def revoke_vault(self, principal_id: str, vault_id: str) -> int:
        if not self._valid_identifier(principal_id) or not self._valid_identifier(
            vault_id
        ):
            raise ValidationError("Invalid secure-session scope.")
        with self.vault_guard(principal_id, vault_id) as raw_guard:
            if not isinstance(raw_guard, _DurableVaultGuard):
                raise SessionUnavailable()
            connection: sqlite3.Connection | None = None
            try:
                connection = self._connect()
                connection.execute("BEGIN IMMEDIATE")
                now = self._now()
                self._purge_locked(connection, now)
                self._assert_guard_locked(connection, raw_guard, now)
                revoked = self._revoke_vault_locked(
                    connection,
                    principal_id,
                    vault_id,
                    now,
                )
                self._assert_guard_locked(
                    connection,
                    raw_guard,
                    self._now(),
                )
                connection.commit()
                return revoked
            except Exception:
                if connection is not None:
                    connection.rollback()
                raise SessionUnavailable() from None
            finally:
                if connection is not None:
                    connection.close()

    @staticmethod
    def _revoke_vault_locked(
        connection: sqlite3.Connection,
        principal_id: str,
        vault_id: str,
        now: float,
    ) -> int:
        rows = connection.execute(
            """
            SELECT token_digest FROM authgraph_session
            WHERE principal_id = ? AND vault_id = ? AND revoked = 0
            """,
            (principal_id, vault_id),
        ).fetchall()
        connection.execute(
            """
            UPDATE authgraph_session SET revoked = 1
            WHERE principal_id = ? AND vault_id = ?
            """,
            (principal_id, vault_id),
        )
        connection.execute(
            """
            DELETE FROM authgraph_session AS session
            WHERE principal_id = ? AND vault_id = ?
              AND revoked = 1 AND NOT EXISTS (
                SELECT 1 FROM authgraph_session_lease AS lease
                WHERE lease.token_digest = session.token_digest
                  AND lease.expires_at > ?
              )
            """,
            (principal_id, vault_id, now),
        )
        return len(rows)

    @contextmanager
    def _lifecycle_write(
        self,
        principal_id: str,
        vault_id: str,
    ) -> Iterator[tuple[sqlite3.Connection, float]]:
        """Run one lifecycle commit under the current monotonic guard."""

        with self.vault_guard(principal_id, vault_id) as raw_guard:
            if not isinstance(raw_guard, _DurableVaultGuard):
                raise SessionUnavailable()
            connection: sqlite3.Connection | None = None
            try:
                connection = self._connect()
                connection.execute("BEGIN IMMEDIATE")
                now = self._now()
                self._purge_locked(connection, now)
                self._assert_guard_locked(connection, raw_guard, now)
                yield connection, now
                commit_time = self._now()
                self._assert_guard_locked(connection, raw_guard, commit_time)
                connection.commit()
            except BaseException:
                if connection is not None:
                    connection.rollback()
                raise
            finally:
                if connection is not None:
                    connection.close()

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

    @staticmethod
    def _set_legacy_revision_locked(
        connection: sqlite3.Connection,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> None:
        connection.execute(
            """
            INSERT INTO authgraph_vault_revision(
                principal_id, vault_id, minimum_envelope_revision
            ) VALUES (?, ?, ?)
            ON CONFLICT(principal_id, vault_id) DO UPDATE SET
                minimum_envelope_revision = excluded.minimum_envelope_revision
            WHERE excluded.minimum_envelope_revision >=
                  authgraph_vault_revision.minimum_envelope_revision
            """,
            (principal_id, vault_id, envelope_revision),
        )

    def prepare_revision_change(
        self,
        principal_id: str,
        vault_id: str,
        current_revision: int,
        next_revision: int,
    ) -> VaultRevisionTransition:
        """Commit PENDING and revoke sessions before the graph envelope CAS."""

        if not self._valid_identifier(principal_id) or not self._valid_identifier(
            vault_id
        ):
            raise ValidationError("Invalid secure-session scope.")
        self._validate_revision_pair(current_revision, next_revision)
        try:
            with self._lifecycle_write(
                principal_id,
                vault_id,
            ) as (connection, now):
                state = self._ensure_active_revision_locked(
                    connection,
                    principal_id,
                    vault_id,
                    current_revision,
                    allow_advance=False,
                )
                generation = state.generation + 1
                cursor = connection.execute(
                    """
                    UPDATE authgraph_vault_lifecycle
                    SET phase = 'REVISION_PENDING', next_revision = ?,
                        generation = ?
                    WHERE principal_id = ? AND vault_id = ?
                      AND phase = 'ACTIVE' AND current_revision = ?
                      AND next_revision IS NULL AND generation = ?
                    """,
                    (
                        next_revision,
                        generation,
                        principal_id,
                        vault_id,
                        current_revision,
                        state.generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SessionUnavailable()
                self._revoke_vault_locked(
                    connection,
                    principal_id,
                    vault_id,
                    now,
                )
            return VaultRevisionTransition(
                principal_id,
                vault_id,
                current_revision,
                next_revision,
                generation,
            )
        except (ValidationError, SessionUnavailable):
            raise
        except Exception:
            raise SessionUnavailable() from None

    def finalize_revision_change(
        self,
        transition: VaultRevisionTransition,
    ) -> VaultLifecycleState:
        if not isinstance(transition, VaultRevisionTransition):
            raise ValidationError("Invalid envelope revision transition.")
        try:
            with self._lifecycle_write(
                transition.principal_id,
                transition.vault_id,
            ) as (connection, _):
                generation = transition.generation + 1
                cursor = connection.execute(
                    """
                    UPDATE authgraph_vault_lifecycle
                    SET phase = 'ACTIVE', current_revision = ?,
                        next_revision = NULL, generation = ?
                    WHERE principal_id = ? AND vault_id = ?
                      AND phase = 'REVISION_PENDING'
                      AND current_revision = ? AND next_revision = ?
                      AND generation = ?
                    """,
                    (
                        transition.next_revision,
                        generation,
                        transition.principal_id,
                        transition.vault_id,
                        transition.current_revision,
                        transition.next_revision,
                        transition.generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SessionUnavailable()
                self._set_legacy_revision_locked(
                    connection,
                    transition.principal_id,
                    transition.vault_id,
                    transition.next_revision,
                )
            return VaultLifecycleState(
                transition.principal_id,
                transition.vault_id,
                VaultLifecyclePhase.ACTIVE,
                transition.next_revision,
                None,
                generation,
            )
        except (ValidationError, SessionUnavailable):
            raise
        except Exception:
            raise SessionUnavailable() from None

    def reconcile_revision_change(
        self,
        principal_id: str,
        vault_id: str,
        authoritative_revision: int,
    ) -> VaultLifecycleState:
        """Resolve PENDING only for its exact stored current or next revision."""

        if (
            not self._valid_identifier(principal_id)
            or not self._valid_identifier(vault_id)
            or type(authoritative_revision) is not int
            or authoritative_revision <= 0
        ):
            raise ValidationError("Invalid revision reconciliation.")
        try:
            with self._lifecycle_write(
                principal_id,
                vault_id,
            ) as (connection, now):
                row = connection.execute(
                    """
                    SELECT current_revision, next_revision, generation
                    FROM authgraph_vault_lifecycle
                    WHERE principal_id = ? AND vault_id = ?
                      AND phase = 'REVISION_PENDING'
                    """,
                    (principal_id, vault_id),
                ).fetchone()
                if row is None or row["next_revision"] is None:
                    raise SessionUnavailable()
                allowed = (
                    int(row["current_revision"]),
                    int(row["next_revision"]),
                )
                if authoritative_revision not in allowed:
                    raise SessionUnavailable()
                generation = int(row["generation"]) + 1
                cursor = connection.execute(
                    """
                    UPDATE authgraph_vault_lifecycle
                    SET phase = 'ACTIVE', current_revision = ?,
                        next_revision = NULL, generation = ?
                    WHERE principal_id = ? AND vault_id = ?
                      AND phase = 'REVISION_PENDING' AND generation = ?
                    """,
                    (
                        authoritative_revision,
                        generation,
                        principal_id,
                        vault_id,
                        int(row["generation"]),
                    ),
                )
                if cursor.rowcount != 1:
                    raise SessionUnavailable()
                self._set_legacy_revision_locked(
                    connection,
                    principal_id,
                    vault_id,
                    authoritative_revision,
                )
                self._revoke_vault_locked(
                    connection,
                    principal_id,
                    vault_id,
                    now,
                )
            return VaultLifecycleState(
                principal_id,
                vault_id,
                VaultLifecyclePhase.ACTIVE,
                authoritative_revision,
                None,
                generation,
            )
        except (ValidationError, SessionUnavailable):
            raise
        except Exception:
            raise SessionUnavailable() from None

    def begin_management_transition(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> VaultManagementTransition:
        """Persist BLOCKED and revoke sessions before management mutation."""

        if (
            not self._valid_identifier(principal_id)
            or not self._valid_identifier(vault_id)
            or type(envelope_revision) is not int
            or envelope_revision <= 0
        ):
            raise ValidationError("Invalid management transition.")
        try:
            with self._lifecycle_write(
                principal_id,
                vault_id,
            ) as (connection, now):
                existing = connection.execute(
                    """
                    SELECT phase, current_revision, generation
                    FROM authgraph_vault_lifecycle
                    WHERE principal_id = ? AND vault_id = ?
                    """,
                    (principal_id, vault_id),
                ).fetchone()
                if (
                    existing is not None
                    and str(existing["phase"])
                    == VaultLifecyclePhase.BLOCKED.value
                ):
                    raise SessionUnavailable()
                state = self._ensure_active_revision_locked(
                    connection,
                    principal_id,
                    vault_id,
                    envelope_revision,
                    allow_advance=False,
                )
                generation = state.generation + 1
                cursor = connection.execute(
                    """
                    UPDATE authgraph_vault_lifecycle
                    SET phase = 'BLOCKED', generation = ?
                    WHERE principal_id = ? AND vault_id = ?
                      AND phase = 'ACTIVE' AND current_revision = ?
                      AND generation = ?
                    """,
                    (
                        generation,
                        principal_id,
                        vault_id,
                        envelope_revision,
                        state.generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SessionUnavailable()
                self._revoke_vault_locked(
                    connection,
                    principal_id,
                    vault_id,
                    now,
                )
            return VaultManagementTransition(
                principal_id,
                vault_id,
                envelope_revision,
                generation,
            )
        except (ValidationError, SessionUnavailable):
            raise
        except Exception:
            raise SessionUnavailable() from None

    def finalize_management_transition(
        self,
        transition: VaultManagementTransition,
    ) -> VaultLifecycleState:
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
        """Explicitly unblock one exact verified BLOCKED generation."""

        if (
            not self._valid_identifier(principal_id)
            or not self._valid_identifier(vault_id)
            or type(authoritative_revision) is not int
            or authoritative_revision <= 0
            or type(blocked_generation) is not int
            or blocked_generation <= 0
        ):
            raise ValidationError("Invalid management reconciliation.")
        try:
            with self._lifecycle_write(
                principal_id,
                vault_id,
            ) as (connection, _):
                generation = blocked_generation + 1
                cursor = connection.execute(
                    """
                    UPDATE authgraph_vault_lifecycle
                    SET phase = 'ACTIVE', generation = ?
                    WHERE principal_id = ? AND vault_id = ?
                      AND phase = 'BLOCKED' AND current_revision = ?
                      AND next_revision IS NULL AND generation = ?
                    """,
                    (
                        generation,
                        principal_id,
                        vault_id,
                        authoritative_revision,
                        blocked_generation,
                    ),
                )
                if cursor.rowcount != 1:
                    raise SessionUnavailable()
                self._set_legacy_revision_locked(
                    connection,
                    principal_id,
                    vault_id,
                    authoritative_revision,
                )
            return VaultLifecycleState(
                principal_id,
                vault_id,
                VaultLifecyclePhase.ACTIVE,
                authoritative_revision,
                None,
                generation,
            )
        except (ValidationError, SessionUnavailable):
            raise
        except Exception:
            raise SessionUnavailable() from None

    def get_lifecycle_state(
        self,
        principal_id: str,
        vault_id: str,
    ) -> VaultLifecycleState | None:
        if not self._valid_identifier(principal_id) or not self._valid_identifier(
            vault_id
        ):
            raise ValidationError("Invalid secure-session scope.")
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT phase, current_revision, next_revision, generation
                FROM authgraph_vault_lifecycle
                WHERE principal_id = ? AND vault_id = ?
                """,
                (principal_id, vault_id),
            ).fetchone()
            if row is None:
                return None
            try:
                phase = VaultLifecyclePhase(str(row["phase"]))
            except ValueError:
                raise SessionUnavailable() from None
            return VaultLifecycleState(
                principal_id,
                vault_id,
                phase,
                int(row["current_revision"]),
                (
                    None
                    if row["next_revision"] is None
                    else int(row["next_revision"])
                ),
                int(row["generation"]),
            )
        finally:
            connection.close()

    def advance_envelope_revision(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> int:
        if (
            not self._valid_identifier(principal_id)
            or not self._valid_identifier(vault_id)
            or type(envelope_revision) is not int
            or envelope_revision <= 0
        ):
            raise ValidationError("Invalid secure-session revision.")
        try:
            with self._lifecycle_write(
                principal_id,
                vault_id,
            ) as (connection, now):
                rows = connection.execute(
                    """
                    SELECT token_digest FROM authgraph_session
                    WHERE principal_id = ? AND vault_id = ?
                      AND envelope_revision < ? AND revoked = 0
                    """,
                    (principal_id, vault_id, envelope_revision),
                ).fetchall()
                self._ensure_active_revision_locked(
                    connection,
                    principal_id,
                    vault_id,
                    envelope_revision,
                    allow_advance=True,
                )
                self._delete_revoked_vault_locked(
                    connection,
                    principal_id,
                    vault_id,
                    now,
                )
            return len(rows)
        except (ValidationError, SessionUnavailable):
            raise
        except Exception:
            raise SessionUnavailable() from None

    @staticmethod
    def _delete_revoked_vault_locked(
        connection: sqlite3.Connection,
        principal_id: str,
        vault_id: str,
        now: float,
    ) -> None:
        connection.execute(
            """
            DELETE FROM authgraph_session AS session
            WHERE principal_id = ? AND vault_id = ? AND revoked = 1
              AND NOT EXISTS (
                SELECT 1 FROM authgraph_session_lease AS lease
                WHERE lease.token_digest = session.token_digest
                  AND lease.expires_at > ?
              )
            """,
            (principal_id, vault_id, now),
        )

    def purge_expired(self) -> int:
        now = self._now()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            purged = self._purge_locked(connection, now)
            connection.commit()
            return purged
        except Exception:
            if connection is not None:
                connection.rollback()
            raise SessionUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    @property
    def active_count(self) -> int:
        self.purge_expired()
        connection = self._connect()
        try:
            return int(
                connection.execute(
                    "SELECT count(*) FROM authgraph_session WHERE revoked = 0"
                ).fetchone()[0]
            )
        finally:
            connection.close()

    @property
    def resident_scope_ciphertext_count(self) -> int:
        connection = self._connect()
        try:
            return int(
                connection.execute(
                    "SELECT count(*) FROM authgraph_session_scope"
                ).fetchone()[0]
            )
        finally:
            connection.close()

    @property
    def sweeper_alive(self) -> bool:
        return not self.closed

    @property
    def sweeper_failed(self) -> bool:
        return False

    @property
    def closed(self) -> bool:
        with self._state_lock:
            return self._closed

    def close_all(self) -> int:
        """Stop admission, then drain guards and local plaintext-key leases."""

        if self._guard_state.guards or self._lease_state.depth:
            raise SessionUnavailable()
        with self._state_changed:
            if not self._closed:
                self._closed = True
            while self._active_guards or self._active_local_leases:
                self._state_changed.wait()
            clear_bytearray(self._token_key)
        return 0
