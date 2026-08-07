"""Restart-safe, multi-process one-time-code broker backed by SQLite.

This is a durable single-host reference implementation.  Every verification,
attempt decrement, resend replacement, evidence creation, and evidence consume
is serialized with ``BEGIN IMMEDIATE`` so separate worker processes sharing the
same database observe one winner.  A multi-host deployment should implement
the same atomic boundary with a shared transactional database.

The database stores only HMAC-keyed challenge/evidence indexes and code
verifiers.  It never stores a plaintext code or bearer evidence token.  The
stable verifier key must come from a secret manager and be identical in every
worker that shares this database.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import secrets
import sqlite3
import stat
import threading
import time
import unicodedata
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ValidationError
from .otp import (
    CHALLENGE_TOKEN_ALPHABET,
    CHALLENGE_TOKEN_LENGTH,
    DEFAULT_CODE_DIGITS,
    DEFAULT_MAX_ACTIVE_CHALLENGES,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_TTL_SECONDS,
    MAX_ACTIVE_CHALLENGES,
    MAX_ATTEMPTS,
    MAX_CODE_DIGITS,
    MAX_OPAQUE_ID_CHARS,
    MAX_TTL_SECONDS,
    MIN_CODE_DIGITS,
    VERIFIER_KEY_BYTES,
    IssuedOneTimeCode,
    OneTimeCodeDenied,
    OneTimeCodeEvidence,
    OneTimeCodeUnavailable,
)

DEFAULT_ISSUE_WINDOW_SECONDS = 15 * 60
DEFAULT_MAX_ISSUES_PER_WINDOW = 5
MAX_ISSUE_WINDOW_SECONDS = 24 * 60 * 60
MAX_ISSUES_PER_WINDOW = 100


@dataclass(frozen=True, slots=True)
class DurableOneTimeCodeEvidence(OneTimeCodeEvidence):
    """Broker evidence with an opaque durable single-use capability."""

    evidence_token: str = field(repr=False)


class DurableOneTimeCodeBroker:
    """SQLite-backed OTP broker safe across restarts and local workers."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        verifier_key: bytes | bytearray | memoryview,
        *,
        code_digits: int = DEFAULT_CODE_DIGITS,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        max_active_challenges: int = DEFAULT_MAX_ACTIVE_CHALLENGES,
        issue_window_seconds: int = DEFAULT_ISSUE_WINDOW_SECONDS,
        max_issues_per_window: int = DEFAULT_MAX_ISSUES_PER_WINDOW,
        busy_timeout_seconds: float = 5.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        try:
            key = bytearray(verifier_key)
        except (TypeError, ValueError):
            raise ValidationError("Invalid durable OTP verifier key.") from None
        if (
            len(key) < VERIFIER_KEY_BYTES
            or type(code_digits) is not int
            or not MIN_CODE_DIGITS <= code_digits <= MAX_CODE_DIGITS
            or type(ttl_seconds) is not int
            or not 0 < ttl_seconds <= MAX_TTL_SECONDS
            or type(max_attempts) is not int
            or not 0 < max_attempts <= MAX_ATTEMPTS
            or type(max_active_challenges) is not int
            or not 0 < max_active_challenges <= MAX_ACTIVE_CHALLENGES
            or type(issue_window_seconds) is not int
            or not 0 < issue_window_seconds <= MAX_ISSUE_WINDOW_SECONDS
            or type(max_issues_per_window) is not int
            or not 0 < max_issues_per_window <= MAX_ISSUES_PER_WINDOW
            or type(busy_timeout_seconds) not in (int, float)
            or not math.isfinite(busy_timeout_seconds)
            or busy_timeout_seconds <= 0
            or busy_timeout_seconds > 60
            or not callable(clock)
        ):
            key[:] = b"\x00" * len(key)
            raise ValidationError("Invalid durable OTP broker configuration.")

        self._path = Path(database_path)
        self._key = key
        self._code_digits = code_digits
        self._ttl_seconds = ttl_seconds
        self._max_attempts = max_attempts
        self._max_active = max_active_challenges
        self._issue_window = issue_window_seconds
        self._max_issues = max_issues_per_window
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
            raise OneTimeCodeUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    def __enter__(self) -> DurableOneTimeCodeBroker:
        with self._state_lock:
            if self._closed:
                raise OneTimeCodeUnavailable()
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
            if not parent.exists() or not parent.is_dir():
                raise OneTimeCodeUnavailable()
            parent_metadata = parent.lstat()
            if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
                parent_metadata.st_mode
            ):
                raise OneTimeCodeUnavailable()
            if os.name == "posix" and (
                parent_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(parent_metadata.st_mode) & 0o022
            ):
                raise OneTimeCodeUnavailable()
            if self._path.exists() or self._path.is_symlink():
                metadata = self._path.lstat()
                if (
                    stat.S_ISLNK(metadata.st_mode)
                    or not stat.S_ISREG(metadata.st_mode)
                ):
                    raise OneTimeCodeUnavailable()
                if os.name == "posix" and (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise OneTimeCodeUnavailable()
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
        except OneTimeCodeUnavailable:
            raise
        except OSError:
            raise OneTimeCodeUnavailable() from None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=self._timeout,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {int(self._timeout * 1000)}")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _initialize(connection: sqlite3.Connection) -> None:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS authgraph_otp_challenge (
                challenge_digest BLOB PRIMARY KEY,
                binding_digest BLOB NOT NULL UNIQUE,
                verifier BLOB NOT NULL,
                principal_id TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                client_binding TEXT NOT NULL,
                authorization_context TEXT,
                authorization_epoch INTEGER NOT NULL,
                expires_at REAL NOT NULL,
                attempts_remaining INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS authgraph_otp_challenge_expiry
                ON authgraph_otp_challenge(expires_at);

            CREATE TABLE IF NOT EXISTS authgraph_otp_evidence (
                evidence_digest BLOB PRIMARY KEY,
                challenge_digest BLOB NOT NULL UNIQUE,
                binding_digest BLOB NOT NULL UNIQUE,
                principal_id TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                client_binding TEXT NOT NULL,
                authorization_context TEXT,
                authorization_epoch INTEGER NOT NULL,
                verified_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS authgraph_otp_evidence_expiry
                ON authgraph_otp_evidence(expires_at);

            CREATE TABLE IF NOT EXISTS authgraph_otp_issue_limit (
                binding_digest BLOB PRIMARY KEY,
                window_started_at REAL NOT NULL,
                issue_count INTEGER NOT NULL
            );
            """
        )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._state_lock:
            if self._closed:
                raise OneTimeCodeUnavailable()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except (OneTimeCodeDenied, OneTimeCodeUnavailable):
            if connection is not None:
                connection.rollback()
            raise
        except Exception:
            if connection is not None:
                connection.rollback()
            raise OneTimeCodeUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _validate_opaque(value: object, description: str) -> str:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_OPAQUE_ID_CHARS
            or any(unicodedata.category(char).startswith("C") for char in value)
        ):
            raise ValidationError(description)
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValidationError(description) from None
        return value

    @staticmethod
    def _valid_token(value: object) -> bool:
        return (
            type(value) is str
            and len(value) == CHALLENGE_TOKEN_LENGTH
            and value.isascii()
            and all(char in CHALLENGE_TOKEN_ALPHABET for char in value)
        )

    def _now(self) -> float:
        try:
            now = self._clock()
        except Exception:
            raise OneTimeCodeUnavailable() from None
        if type(now) not in (int, float) or not math.isfinite(now):
            raise OneTimeCodeUnavailable()
        return float(now)

    def _digest(self, domain: bytes, *parts: object) -> bytes:
        digest = hmac.new(bytes(self._key), digestmod=hashlib.sha256)
        digest.update(b"authgraph-durable-otp-v1")
        digest.update(len(domain).to_bytes(4, "big"))
        digest.update(domain)
        for part in parts:
            encoded = part.encode("utf-8") if isinstance(part, str) else part
            if not isinstance(encoded, (bytes, bytearray, memoryview)):
                raise TypeError("OTP digest parts must be bytes-like.")
            view = memoryview(encoded).cast("B")
            digest.update(len(view).to_bytes(4, "big"))
            digest.update(view)
        return digest.digest()

    def _binding_digest(
        self,
        principal_id: str,
        profile_id: str,
        client_binding: str,
        authorization_context: str | None,
    ) -> bytes:
        return self._digest(
            b"binding",
            principal_id,
            profile_id,
            client_binding,
            b"none" if authorization_context is None else b"value",
            b"" if authorization_context is None else authorization_context,
        )

    def _token_digest(self, domain: bytes, token: str) -> bytes:
        return self._digest(domain, token)

    def _verifier(
        self,
        challenge_id: str,
        binding_digest: bytes,
        authorization_epoch: int,
        code: bytes | bytearray | memoryview,
    ) -> bytes:
        return self._digest(
            b"code-verifier",
            challenge_id,
            binding_digest,
            authorization_epoch.to_bytes(8, "big"),
            code,
        )

    def _normalize_code(self, code: object) -> bytes | None:
        if isinstance(code, str):
            if (
                len(code) != self._code_digits
                or not code.isascii()
                or not code.isdigit()
            ):
                return None
            return code.encode("ascii")
        if not isinstance(code, (bytes, bytearray, memoryview)):
            return None
        try:
            view = memoryview(code).cast("B")
        except (TypeError, ValueError):
            return None
        if len(view) != self._code_digits or any(
            octet < 48 or octet > 57 for octet in view
        ):
            return None
        return bytes(view)

    @staticmethod
    def _purge(connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            "DELETE FROM authgraph_otp_challenge WHERE expires_at <= ?",
            (now,),
        )
        connection.execute(
            "DELETE FROM authgraph_otp_evidence WHERE expires_at <= ?",
            (now,),
        )

    def issue(
        self,
        principal_id: str,
        profile_id: str,
        client_binding: str,
        *,
        authorization_context: str | None = None,
        authorization_epoch: int = 1,
    ) -> IssuedOneTimeCode:
        principal = self._validate_opaque(
            principal_id,
            "principal_id must be a non-PII opaque identifier.",
        )
        profile = self._validate_opaque(
            profile_id,
            "profile_id must be an opaque configured profile identifier.",
        )
        client = self._validate_opaque(
            client_binding,
            "client_binding must be an opaque application-session identifier.",
        )
        context = (
            None
            if authorization_context is None
            else self._validate_opaque(
                authorization_context,
                "authorization_context must be opaque.",
            )
        )
        if (
            type(authorization_epoch) is not int
            or not 0 < authorization_epoch <= 2**63 - 1
        ):
            raise ValidationError("Invalid authorization epoch.")
        code = bytearray(
            f"{secrets.randbelow(10**self._code_digits):0{self._code_digits}d}".encode(
                "ascii"
            )
        )
        try:
            now = self._now()
            expires_at = now + self._ttl_seconds
            binding_digest = self._binding_digest(
                principal,
                profile,
                client,
                context,
            )
            challenge_id = secrets.token_urlsafe(32)
            challenge_digest = self._token_digest(
                b"challenge-index",
                challenge_id,
            )
            verifier = self._verifier(
                challenge_id,
                binding_digest,
                authorization_epoch,
                code,
            )
            with self._transaction() as connection:
                self._purge(connection, now)
                limit = connection.execute(
                    """
                    SELECT window_started_at, issue_count
                    FROM authgraph_otp_issue_limit
                    WHERE binding_digest = ?
                    """,
                    (binding_digest,),
                ).fetchone()
                if limit is None or now - float(limit[0]) >= self._issue_window:
                    connection.execute(
                        """
                        INSERT INTO authgraph_otp_issue_limit(
                            binding_digest, window_started_at, issue_count
                        ) VALUES (?, ?, 1)
                        ON CONFLICT(binding_digest) DO UPDATE SET
                            window_started_at = excluded.window_started_at,
                            issue_count = 1
                        """,
                        (binding_digest, now),
                    )
                elif int(limit[1]) >= self._max_issues:
                    raise OneTimeCodeUnavailable()
                else:
                    connection.execute(
                        """
                        UPDATE authgraph_otp_issue_limit
                        SET issue_count = issue_count + 1
                        WHERE binding_digest = ?
                        """,
                        (binding_digest,),
                    )
                active = connection.execute(
                    """
                    SELECT
                      (SELECT count(*) FROM authgraph_otp_challenge) +
                      (SELECT count(*) FROM authgraph_otp_evidence)
                    """
                ).fetchone()[0]
                existing = connection.execute(
                    """
                    SELECT 1 FROM authgraph_otp_challenge
                    WHERE binding_digest = ?
                    UNION ALL
                    SELECT 1 FROM authgraph_otp_evidence
                    WHERE binding_digest = ?
                    LIMIT 1
                    """,
                    (binding_digest, binding_digest),
                ).fetchone()
                if existing is None and int(active) >= self._max_active:
                    raise OneTimeCodeUnavailable()
                connection.execute(
                    "DELETE FROM authgraph_otp_challenge WHERE binding_digest = ?",
                    (binding_digest,),
                )
                connection.execute(
                    "DELETE FROM authgraph_otp_evidence WHERE binding_digest = ?",
                    (binding_digest,),
                )
                connection.execute(
                    """
                    INSERT INTO authgraph_otp_challenge(
                        challenge_digest, binding_digest, verifier,
                        principal_id, profile_id, client_binding,
                        authorization_context, authorization_epoch,
                        expires_at, attempts_remaining
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        challenge_digest,
                        binding_digest,
                        verifier,
                        principal,
                        profile,
                        client,
                        context,
                        authorization_epoch,
                        expires_at,
                        self._max_attempts,
                    ),
                )
            return IssuedOneTimeCode(
                challenge_id=challenge_id,
                code=code,
                expires_at=expires_at,
            )
        except Exception:
            code[:] = b"\x00" * len(code)
            raise

    def verify(
        self,
        challenge_id: str,
        code: str | bytes | bytearray | memoryview,
        *,
        principal_id: str,
        profile_id: str,
        client_binding: str,
    ) -> DurableOneTimeCodeEvidence:
        normalized = self._normalize_code(code)
        valid_token = self._valid_token(challenge_id)
        try:
            principal = self._validate_opaque(principal_id, "Invalid principal.")
            profile = self._validate_opaque(profile_id, "Invalid profile.")
            client = self._validate_opaque(client_binding, "Invalid client.")
            valid_binding = True
        except ValidationError:
            principal = profile = client = "invalid"
            valid_binding = False
        challenge_part = challenge_id if valid_token else "invalid"
        challenge_digest = self._token_digest(
            b"challenge-index",
            challenge_part,
        )
        now = self._now()
        evidence: DurableOneTimeCodeEvidence | None = None
        try:
            with self._transaction() as connection:
                self._purge(connection, now)
                row = connection.execute(
                    """
                    SELECT * FROM authgraph_otp_challenge
                    WHERE challenge_digest = ?
                    """,
                    (challenge_digest,),
                ).fetchone()
                context = None if row is None else row["authorization_context"]
                epoch = 1 if row is None else int(row["authorization_epoch"])
                binding_digest = self._binding_digest(
                    principal,
                    profile,
                    client,
                    context,
                )
                candidate = self._verifier(
                    challenge_part,
                    binding_digest,
                    epoch,
                    b"invalid" if normalized is None else normalized,
                )
                expected = b"\x00" * 32 if row is None else bytes(row["verifier"])
                matches = (
                    row is not None
                    and valid_binding
                    and valid_token
                    and normalized is not None
                    and hmac.compare_digest(
                        binding_digest,
                        bytes(row["binding_digest"]),
                    )
                    and hmac.compare_digest(candidate, expected)
                    and float(row["expires_at"]) > now
                )
                if row is not None and not matches:
                    attempts = int(row["attempts_remaining"]) - 1
                    if attempts <= 0:
                        connection.execute(
                            """
                            DELETE FROM authgraph_otp_challenge
                            WHERE challenge_digest = ?
                            """,
                            (challenge_digest,),
                        )
                    else:
                        connection.execute(
                            """
                            UPDATE authgraph_otp_challenge
                            SET attempts_remaining = ?
                            WHERE challenge_digest = ?
                            """,
                            (attempts, challenge_digest),
                        )
                if matches and row is not None:
                    evidence_token = secrets.token_urlsafe(32)
                    evidence_digest = self._token_digest(
                        b"evidence-index",
                        evidence_token,
                    )
                    connection.execute(
                        """
                        DELETE FROM authgraph_otp_challenge
                        WHERE challenge_digest = ?
                        """,
                        (challenge_digest,),
                    )
                    connection.execute(
                        """
                        INSERT INTO authgraph_otp_evidence(
                            evidence_digest, challenge_digest, binding_digest,
                            principal_id, profile_id, client_binding,
                            authorization_context, authorization_epoch,
                            verified_at, expires_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            evidence_digest,
                            challenge_digest,
                            bytes(row["binding_digest"]),
                            row["principal_id"],
                            row["profile_id"],
                            row["client_binding"],
                            row["authorization_context"],
                            row["authorization_epoch"],
                            now,
                            row["expires_at"],
                        ),
                    )
                    evidence = DurableOneTimeCodeEvidence(
                        principal_id=row["principal_id"],
                        profile_id=row["profile_id"],
                        client_binding=row["client_binding"],
                        authorization_context=row["authorization_context"],
                        challenge_id=challenge_id,
                        authorization_epoch=int(row["authorization_epoch"]),
                        verified_at=now,
                        challenge_expires_at=float(row["expires_at"]),
                        evidence_token=evidence_token,
                    )
            if evidence is None:
                raise OneTimeCodeDenied()
            return evidence
        except OneTimeCodeDenied:
            raise
        except OneTimeCodeUnavailable:
            raise OneTimeCodeDenied() from None
        except Exception:
            raise OneTimeCodeDenied() from None

    def consume_evidence(
        self,
        evidence: OneTimeCodeEvidence,
    ) -> DurableOneTimeCodeEvidence:
        now = self._now()
        if not isinstance(evidence, DurableOneTimeCodeEvidence):
            raise OneTimeCodeDenied()
        valid_token = self._valid_token(evidence.evidence_token)
        digest = self._token_digest(
            b"evidence-index",
            evidence.evidence_token if valid_token else "invalid",
        )
        accepted = False
        try:
            with self._transaction() as connection:
                self._purge(connection, now)
                row = connection.execute(
                    "SELECT * FROM authgraph_otp_evidence WHERE evidence_digest = ?",
                    (digest,),
                ).fetchone()
                if row is not None:
                    connection.execute(
                        "DELETE FROM authgraph_otp_evidence WHERE evidence_digest = ?",
                        (digest,),
                    )
                expected = None
                if row is not None:
                    expected = (
                        row["principal_id"],
                        row["profile_id"],
                        row["client_binding"],
                        row["authorization_context"],
                        bytes(row["challenge_digest"]),
                        int(row["authorization_epoch"]),
                        float(row["verified_at"]),
                        float(row["expires_at"]),
                    )
                actual = (
                    evidence.principal_id,
                    evidence.profile_id,
                    evidence.client_binding,
                    evidence.authorization_context,
                    self._token_digest(b"challenge-index", evidence.challenge_id),
                    evidence.authorization_epoch,
                    evidence.verified_at,
                    evidence.challenge_expires_at,
                )
                accepted = not (
                    not valid_token
                    or expected is None
                    or len(actual) != len(expected)
                    or any(
                        type(candidate) is not type(original)
                        or candidate != original
                        for candidate, original in zip(actual, expected, strict=True)
                    )
                    or expected[-1] <= now
                )
            if not accepted:
                raise OneTimeCodeDenied()
            return DurableOneTimeCodeEvidence(
                principal_id=evidence.principal_id,
                profile_id=evidence.profile_id,
                client_binding=evidence.client_binding,
                authorization_context=evidence.authorization_context,
                challenge_id=evidence.challenge_id,
                authorization_epoch=evidence.authorization_epoch,
                verified_at=evidence.verified_at,
                challenge_expires_at=evidence.challenge_expires_at,
                evidence_token=evidence.evidence_token,
            )
        except OneTimeCodeDenied:
            raise
        except Exception:
            raise OneTimeCodeDenied() from None

    def purge_expired(self) -> int:
        now = self._now()
        with self._transaction() as connection:
            before = connection.total_changes
            self._purge(connection, now)
            return connection.total_changes - before

    def _count(self, table: str) -> int:
        if table not in (
            "authgraph_otp_challenge",
            "authgraph_otp_evidence",
        ):
            raise AssertionError("Invalid internal OTP table.")
        now = self._now()
        with self._transaction() as connection:
            self._purge(connection, now)
            return int(
                connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            )

    @property
    def active_count(self) -> int:
        return self._count("authgraph_otp_challenge")

    @property
    def pending_evidence_count(self) -> int:
        return self._count("authgraph_otp_evidence")

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
