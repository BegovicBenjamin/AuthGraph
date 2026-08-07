"""Restart-safe single-use scope grants backed by SQLite.

The store contains only HMAC digests of grant capabilities and authorization
fields.  It never stores the raw grant id, principal, vault, scope ids, client
binding, or OTP evidence id.  Separate worker processes sharing the database
and HMAC key atomically consume one grant exactly once.

SQLite is the included durable single-host reference.  Multi-host deployments
need the same operations implemented by a shared transactional service.
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
from contextlib import contextmanager
from pathlib import Path

from .errors import ValidationError
from .otp import OneTimeCodeEvidence, OneTimeCodeEvidenceConsumer
from .unlock_policy import (
    MAX_ACTIVE_GRANTS,
    MAX_EVIDENCE_AGE_SECONDS,
    ScopeGrantDenied,
    ScopeUnlockGrant,
    UnlockProfile,
)

GRANT_KEY_BYTES = 32
GRANT_TOKEN_LENGTH = 43
GRANT_TOKEN_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


class DurableScopeGrantPolicy:
    """Persist and atomically consume fixed-scope unlock grants."""

    def __init__(
        self,
        profiles: Mapping[str, UnlockProfile],
        database_path: str | os.PathLike[str],
        grant_key: bytes | bytearray | memoryview,
        *,
        policy_revision: int = 1,
        max_evidence_age_seconds: int = 60,
        max_active_grants: int = MAX_ACTIVE_GRANTS,
        busy_timeout_seconds: float = 5.0,
        clock: Callable[[], float] = time.time,
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
        try:
            key = bytearray(grant_key)
        except (TypeError, ValueError):
            raise ValidationError("Invalid durable grant key.") from None
        if (
            len(key) < GRANT_KEY_BYTES
            or type(policy_revision) is not int
            or not 0 < policy_revision <= 2**63 - 1
            or type(max_evidence_age_seconds) is not int
            or not 0 < max_evidence_age_seconds <= MAX_EVIDENCE_AGE_SECONDS
            or type(max_active_grants) is not int
            or not 0 < max_active_grants <= MAX_ACTIVE_GRANTS
            or type(busy_timeout_seconds) not in (int, float)
            or not math.isfinite(busy_timeout_seconds)
            or not 0 < busy_timeout_seconds <= 60
            or not callable(clock)
        ):
            key[:] = b"\x00" * len(key)
            raise ValidationError("Invalid durable grant policy configuration.")
        self._profiles = copied
        self._path = Path(database_path)
        self._key = key
        self._policy_revision = policy_revision
        self._max_evidence_age = max_evidence_age_seconds
        self._max_active = max_active_grants
        self._timeout = float(busy_timeout_seconds)
        self._clock = clock
        self._state_lock = threading.Lock()
        self._closed = False
        self._prepare_database_file()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            self._initialize(connection)
        except Exception:
            self._key[:] = b"\x00" * len(self._key)
            raise ScopeGrantDenied() from None
        finally:
            if connection is not None:
                connection.close()

    def __enter__(self) -> DurableScopeGrantPolicy:
        with self._state_lock:
            if self._closed:
                raise ScopeGrantDenied()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def _prepare_database_file(self) -> None:
        try:
            parent = self._path.parent
            if not parent.is_dir():
                raise ScopeGrantDenied()
            parent_metadata = parent.lstat()
            if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
                parent_metadata.st_mode
            ):
                raise ScopeGrantDenied()
            if os.name == "posix" and (
                parent_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(parent_metadata.st_mode) & 0o022
            ):
                raise ScopeGrantDenied()
            if self._path.exists() or self._path.is_symlink():
                metadata = self._path.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
                    metadata.st_mode
                ):
                    raise ScopeGrantDenied()
                if os.name == "posix" and (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise ScopeGrantDenied()
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
        except ScopeGrantDenied:
            raise
        except OSError:
            raise ScopeGrantDenied() from None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=self._timeout,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {int(self._timeout * 1000)}")
        return connection

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS authgraph_scope_grant (
                grant_digest BLOB PRIMARY KEY,
                principal_digest BLOB NOT NULL,
                profile_digest BLOB NOT NULL,
                vault_digest BLOB NOT NULL,
                scopes_digest BLOB NOT NULL,
                scope_count INTEGER NOT NULL,
                client_digest BLOB NOT NULL,
                authorization_epoch INTEGER NOT NULL,
                evidence_provider TEXT NOT NULL,
                evidence_digest BLOB NOT NULL,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                policy_revision INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS authgraph_scope_grant_expiry
                ON authgraph_scope_grant(expires_at);
            """
        )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._state_lock:
            if self._closed:
                raise ScopeGrantDenied()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except ScopeGrantDenied:
            if connection is not None:
                connection.rollback()
            raise
        except Exception:
            if connection is not None:
                connection.rollback()
            raise ScopeGrantDenied() from None
        finally:
            if connection is not None:
                connection.close()

    def _now(self) -> float:
        try:
            now = self._clock()
        except Exception:
            raise ScopeGrantDenied() from None
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ScopeGrantDenied()
        return float(now)

    @staticmethod
    def _valid_opaque(value: object) -> bool:
        return (
            isinstance(value, str)
            and bool(value)
            and len(value) <= 256
            and not any(
                unicodedata.category(char).startswith("C") for char in value
            )
        )

    @staticmethod
    def _valid_token(value: object) -> bool:
        return (
            type(value) is str
            and len(value) == GRANT_TOKEN_LENGTH
            and value.isascii()
            and all(char in GRANT_TOKEN_ALPHABET for char in value)
        )

    def _digest(self, domain: bytes, value: bytes) -> bytes:
        digest = hmac.new(bytes(self._key), digestmod=hashlib.sha256)
        digest.update(b"authgraph-durable-grant-v1")
        digest.update(len(domain).to_bytes(4, "big"))
        digest.update(domain)
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
        return digest.digest()

    def _text_digest(self, domain: bytes, value: str) -> bytes:
        return self._digest(domain, value.encode("utf-8"))

    def _scopes_digest(self, scope_ids: tuple[str, ...]) -> bytes:
        encoded = json.dumps(
            list(scope_ids),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        return self._digest(b"scopes", encoded)

    @staticmethod
    def _purge(connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            "DELETE FROM authgraph_scope_grant WHERE expires_at <= ?",
            (now,),
        )

    def authorize_one_time_code(
        self,
        evidence: OneTimeCodeEvidence,
        *,
        vault_id: str,
        evidence_consumer: OneTimeCodeEvidenceConsumer,
    ) -> ScopeUnlockGrant:
        if (
            not isinstance(evidence, OneTimeCodeEvidence)
            or not isinstance(evidence_consumer, OneTimeCodeEvidenceConsumer)
            or not self._valid_opaque(vault_id)
        ):
            raise ScopeGrantDenied()
        try:
            consumed = evidence_consumer.consume_evidence(evidence)
            if not isinstance(consumed, OneTimeCodeEvidence) or consumed is evidence:
                raise ScopeGrantDenied()
            now = self._now()
            profile = self._profiles.get(consumed.profile_id)
            expires_at = now + (
                profile.session_ttl_seconds if profile is not None else 0
            )
            if (
                profile is None
                or not profile.allow_one_time_code
                or not self._valid_opaque(consumed.principal_id)
                or not self._valid_opaque(consumed.profile_id)
                or not self._valid_opaque(consumed.client_binding)
                or not self._valid_opaque(consumed.challenge_id)
                or consumed.authorization_context != vault_id
                or type(consumed.authorization_epoch) is not int
                or consumed.authorization_epoch <= 0
                or type(consumed.verified_at) not in (int, float)
                or type(consumed.challenge_expires_at) not in (int, float)
                or not math.isfinite(consumed.verified_at)
                or not math.isfinite(consumed.challenge_expires_at)
                or consumed.verified_at > now
                or now - consumed.verified_at > self._max_evidence_age
                or consumed.challenge_expires_at <= now
                or consumed.verified_at > consumed.challenge_expires_at
                or not math.isfinite(expires_at)
                or expires_at <= now
            ):
                raise ScopeGrantDenied()
            grant_id = secrets.token_urlsafe(32)
            grant = ScopeUnlockGrant(
                principal_id=consumed.principal_id,
                profile_id=profile.profile_id,
                vault_id=vault_id,
                scope_ids=profile.scope_ids,
                client_binding=consumed.client_binding,
                authorization_epoch=consumed.authorization_epoch,
                evidence_provider="one_time_code",
                evidence_id=consumed.challenge_id,
                issued_at=now,
                expires_at=expires_at,
                grant_id=grant_id,
            )
            with self._transaction() as connection:
                self._purge(connection, now)
                count = int(
                    connection.execute(
                        "SELECT count(*) FROM authgraph_scope_grant"
                    ).fetchone()[0]
                )
                if count >= self._max_active:
                    raise ScopeGrantDenied()
                connection.execute(
                    """
                    INSERT INTO authgraph_scope_grant(
                        grant_digest, principal_digest, profile_digest,
                        vault_digest, scopes_digest, scope_count,
                        client_digest, authorization_epoch,
                        evidence_provider, evidence_digest,
                        issued_at, expires_at, policy_revision
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        self._text_digest(b"grant", grant.grant_id),
                        self._text_digest(b"principal", grant.principal_id),
                        self._text_digest(b"profile", grant.profile_id),
                        self._text_digest(b"vault", grant.vault_id),
                        self._scopes_digest(grant.scope_ids),
                        len(grant.scope_ids),
                        self._text_digest(b"client", grant.client_binding),
                        grant.authorization_epoch,
                        grant.evidence_provider,
                        self._text_digest(b"evidence", grant.evidence_id),
                        grant.issued_at,
                        grant.expires_at,
                        self._policy_revision,
                    ),
                )
            return grant
        except ScopeGrantDenied:
            raise
        except Exception:
            raise ScopeGrantDenied() from None

    def consume(self, grant: ScopeUnlockGrant) -> ScopeUnlockGrant:
        now = self._now()
        valid_token = isinstance(grant, ScopeUnlockGrant) and self._valid_token(
            grant.grant_id
        )
        token = grant.grant_id if valid_token else "invalid"
        digest = self._text_digest(b"grant", token)
        accepted = False
        try:
            with self._transaction() as connection:
                self._purge(connection, now)
                row = connection.execute(
                    "SELECT * FROM authgraph_scope_grant WHERE grant_digest = ?",
                    (digest,),
                ).fetchone()
                if row is not None:
                    connection.execute(
                        "DELETE FROM authgraph_scope_grant WHERE grant_digest = ?",
                        (digest,),
                    )
                profile = (
                    self._profiles.get(grant.profile_id)
                    if isinstance(grant, ScopeUnlockGrant)
                    else None
                )
                if row is not None and isinstance(grant, ScopeUnlockGrant):
                    comparisons = (
                        (
                            row["principal_digest"],
                            self._text_digest(b"principal", grant.principal_id),
                        ),
                        (
                            row["profile_digest"],
                            self._text_digest(b"profile", grant.profile_id),
                        ),
                        (
                            row["vault_digest"],
                            self._text_digest(b"vault", grant.vault_id),
                        ),
                        (
                            row["scopes_digest"],
                            self._scopes_digest(grant.scope_ids),
                        ),
                        (
                            row["client_digest"],
                            self._text_digest(b"client", grant.client_binding),
                        ),
                        (
                            row["evidence_digest"],
                            self._text_digest(b"evidence", grant.evidence_id),
                        ),
                    )
                    digests_match = all(
                        hmac.compare_digest(bytes(stored), expected)
                        for stored, expected in comparisons
                    )
                    accepted = (
                        valid_token
                        and digests_match
                        and int(row["scope_count"]) == len(grant.scope_ids)
                        and int(row["authorization_epoch"]) == grant.authorization_epoch
                        and row["evidence_provider"] == grant.evidence_provider
                        and float(row["issued_at"]) == grant.issued_at
                        and float(row["expires_at"]) == grant.expires_at
                        and float(row["expires_at"]) > now
                        and int(row["policy_revision"]) == self._policy_revision
                        and profile is not None
                        and profile.allow_one_time_code
                        and profile.scope_ids == grant.scope_ids
                        and grant.expires_at
                        <= grant.issued_at + profile.session_ttl_seconds
                    )
            if not accepted:
                raise ScopeGrantDenied()
            return ScopeUnlockGrant(
                principal_id=grant.principal_id,
                profile_id=grant.profile_id,
                vault_id=grant.vault_id,
                scope_ids=grant.scope_ids,
                client_binding=grant.client_binding,
                authorization_epoch=grant.authorization_epoch,
                evidence_provider=grant.evidence_provider,
                evidence_id=grant.evidence_id,
                issued_at=grant.issued_at,
                expires_at=grant.expires_at,
                grant_id=grant.grant_id,
            )
        except ScopeGrantDenied:
            raise
        except Exception:
            raise ScopeGrantDenied() from None

    def purge_expired(self) -> int:
        now = self._now()
        with self._transaction() as connection:
            before = connection.total_changes
            self._purge(connection, now)
            return connection.total_changes - before

    @property
    def active_count(self) -> int:
        now = self._now()
        with self._transaction() as connection:
            self._purge(connection, now)
            return int(
                connection.execute(
                    "SELECT count(*) FROM authgraph_scope_grant"
                ).fetchone()[0]
            )

    @property
    def closed(self) -> bool:
        with self._state_lock:
            return self._closed

    def close(self) -> int:
        with self._state_lock:
            if self._closed:
                return 0
            self._closed = True
            self._key[:] = b"\x00" * len(self._key)
        return 0
