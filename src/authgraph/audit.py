"""Pseudonymous, allowlisted security audit events.

The application supplies opaque identifiers and a dedicated audit HMAC key.
Only keyed references are written to a sink; graph semantics, credentials,
tokens, one-time codes, key material, ciphertext, and exception strings are
not accepted by this API.

The JSON-lines sink provides a locally hash-chained, fsync-backed reference
implementation.  It is useful for a single host, but a production deployment
should forward events to append-only/WORM storage with independent retention
and access controls.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import stat
import threading
import time
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, TextIO, runtime_checkable

from .errors import AuthGraphError, ValidationError

LEGACY_AUDIT_FORMAT_VERSION = 1
AUDIT_FORMAT_VERSION = 2
MIN_AUDIT_KEY_BYTES = 32
MAX_AUDIT_METADATA_ITEMS = 16
MAX_AUDIT_TEXT_CHARS = 128
ZERO_HASH = "0" * 64

_INTEGER_METADATA_KEYS = frozenset(
    {"count", "revision", "key_version", "schema_version", "batch_number"}
)
_BOOLEAN_METADATA_KEYS = frozenset({"recovery_used", "multi_factor"})
_TEXT_METADATA_VALUES = {
    "provider": frozenset(
        {"password", "one_time_code", "aws_kms", "pkcs11", "test"}
    ),
    "reason_code": frozenset(
        {
            "generic_denial",
            "expired",
            "revoked",
            "conflict",
            "integrity_failure",
            "unavailable",
        }
    ),
    "phase": frozenset(
        {"prepare", "activate", "reencrypt", "verify", "finalize"}
    ),
}


class AuditUnavailable(AuthGraphError):
    """A required security event could not be committed."""

    def __init__(self) -> None:
        super().__init__("The security audit service is unavailable.")


class SecurityEventType(StrEnum):
    VAULT_CREATED = "vault_created"
    SCOPE_CREATED = "scope_created"
    UNLOCK_SUCCEEDED = "unlock_succeeded"
    UNLOCK_DENIED = "unlock_denied"
    SESSION_LOCKED = "session_locked"
    VAULT_REVOKED = "vault_revoked"
    PASSPHRASE_CHANGED = "passphrase_changed"
    OTP_ISSUED = "otp_issued"
    OTP_VERIFIED = "otp_verified"
    OTP_DENIED = "otp_denied"
    KEY_ENROLLED = "key_enrolled"
    KEY_RELEASED = "key_released"
    KEY_REVOKED = "key_revoked"
    KEY_REWRAPPED = "key_rewrapped"
    MIGRATION_STARTED = "migration_started"
    MIGRATION_COMPLETED = "migration_completed"
    MIGRATION_FAILED = "migration_failed"


class SecurityEventOutcome(StrEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class SecurityAuditRecord:
    """One event whose identifiers have already been pseudonymized."""

    format_version: int
    event_id: str
    occurred_at: float
    event_type: SecurityEventType
    outcome: SecurityEventOutcome
    principal_ref: str | None
    vault_ref: str | None
    scope_refs: tuple[str, ...]
    session_ref: str | None
    metadata: Mapping[str, str | int | bool]
    operation_ref: str | None = None
    source_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PreparedSecurityAuditOperation:
    """Opaque capability linking one management intent to its outcome."""

    operation_id: str = field(repr=False)
    event_type: SecurityEventType


@dataclass(frozen=True, slots=True)
class SecurityAuditVerificationReport:
    """Integrity result plus crash-detectable unfinished operations."""

    event_count: int
    completed_operation_count: int
    pending_operation_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CommittedSecurityAuditEvent:
    """A record plus its append-order hash-chain fields."""

    record: SecurityAuditRecord
    previous_hash: str
    event_hash: str

    def canonical_json_bytes(self) -> bytes:
        return _event_json(self).encode("utf-8")


@runtime_checkable
class AuditSink(Protocol):
    """Append one prepared record and return its committed chain event."""

    def append(
        self,
        record: SecurityAuditRecord,
        *,
        signing_key: bytes,
    ) -> CommittedSecurityAuditEvent: ...


def _valid_text(value: object, *, max_chars: int = MAX_AUDIT_TEXT_CHARS) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= max_chars
        and not any(
            unicodedata.category(char).startswith("C") for char in value
        )
    )


def _record_dict(record: SecurityAuditRecord) -> dict[str, object]:
    value: dict[str, object] = {
        "format_version": record.format_version,
        "event_id": record.event_id,
        "occurred_at": record.occurred_at,
        "event_type": record.event_type.value,
        "outcome": record.outcome.value,
        "principal_ref": record.principal_ref,
        "vault_ref": record.vault_ref,
        "scope_refs": list(record.scope_refs),
        "session_ref": record.session_ref,
        "metadata": dict(record.metadata),
    }
    if record.format_version >= AUDIT_FORMAT_VERSION:
        value["operation_ref"] = record.operation_ref
        value["source_refs"] = list(record.source_refs)
    return value


def _canonical_record(record: SecurityAuditRecord) -> bytes:
    return json.dumps(
        _record_dict(record),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _event_json(event: CommittedSecurityAuditEvent) -> str:
    value = _record_dict(event.record)
    value["previous_hash"] = event.previous_hash
    value["event_hash"] = event.event_hash
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _event_hash(
    record: SecurityAuditRecord,
    previous_hash: str,
    signing_key: bytes,
) -> str:
    if (
        not isinstance(signing_key, bytes)
        or len(signing_key) < MIN_AUDIT_KEY_BYTES
        or len(previous_hash) != 64
    ):
        raise AuditUnavailable()
    digest = hmac.new(signing_key, digestmod=hashlib.sha256)
    digest.update(b"authgraph-security-audit-v1")
    digest.update(bytes.fromhex(previous_hash))
    payload = _canonical_record(record)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.hexdigest()


class InMemoryAuditSink:
    """Thread-safe sink for tests and local development."""

    def __init__(self) -> None:
        self._events: list[CommittedSecurityAuditEvent] = []
        self._lock = threading.Lock()

    def append(
        self,
        record: SecurityAuditRecord,
        *,
        signing_key: bytes,
    ) -> CommittedSecurityAuditEvent:
        with self._lock:
            previous = (
                self._events[-1].event_hash if self._events else ZERO_HASH
            )
            event = CommittedSecurityAuditEvent(
                record=record,
                previous_hash=previous,
                event_hash=_event_hash(record, previous, signing_key),
            )
            self._events.append(event)
            return event

    @property
    def events(self) -> tuple[CommittedSecurityAuditEvent, ...]:
        with self._lock:
            return tuple(self._events)


def _validate_audit_parent(path: Path) -> None:
    try:
        metadata = path.parent.lstat()
    except OSError:
        raise AuditUnavailable() from None
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise AuditUnavailable()
    if os.name == "posix" and (
        metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise AuditUnavailable()


class JsonLinesAuditSink:
    """Mode-0600 local hash-chain sink with no-follow file opening."""

    def __init__(self, path: str | os.PathLike[str], *, fsync: bool = True) -> None:
        self._path = Path(path)
        self._fsync = bool(fsync)
        self._lock = threading.Lock()

    @staticmethod
    def _previous_hash(file_object: TextIO) -> str:
        file_object.seek(0)
        previous = ZERO_HASH
        for raw_line in file_object:
            try:
                value = json.loads(raw_line)
                candidate = value["event_hash"]
            except (json.JSONDecodeError, KeyError, TypeError):
                raise AuditUnavailable() from None
            if (
                not isinstance(candidate, str)
                or len(candidate) != 64
                or any(char not in "0123456789abcdef" for char in candidate)
            ):
                raise AuditUnavailable()
            previous = candidate
        return previous

    def append(
        self,
        record: SecurityAuditRecord,
        *,
        signing_key: bytes,
    ) -> CommittedSecurityAuditEvent:
        flags = os.O_RDWR | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            _validate_audit_parent(self._path)
            descriptor = os.open(self._path, flags, 0o600)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise AuditUnavailable()
            if os.name == "posix" and (
                metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
            ):
                raise AuditUnavailable()
            with os.fdopen(
                descriptor,
                "r+",
                encoding="ascii",
                newline="\n",
            ) as audit_file:
                descriptor = None
                with self._lock:
                    try:
                        import fcntl

                        fcntl.flock(audit_file.fileno(), fcntl.LOCK_EX)
                    except ImportError:
                        pass
                    previous = self._previous_hash(audit_file)
                    event = CommittedSecurityAuditEvent(
                        record=record,
                        previous_hash=previous,
                        event_hash=_event_hash(
                            record,
                            previous,
                            signing_key,
                        ),
                    )
                    audit_file.seek(0, os.SEEK_END)
                    audit_file.write(_event_json(event) + "\n")
                    audit_file.flush()
                    if self._fsync:
                        os.fsync(audit_file.fileno())
                    return event
        except AuditUnavailable:
            raise
        except (OSError, UnicodeError, ValueError):
            raise AuditUnavailable() from None
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _is_hex_reference(value: object, *, length: int = 64) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _audit_record_from_json(value: object) -> SecurityAuditRecord:
    if not isinstance(value, dict):
        raise AuditUnavailable()
    try:
        version = value["format_version"]
        if version not in (LEGACY_AUDIT_FORMAT_VERSION, AUDIT_FORMAT_VERSION):
            raise AuditUnavailable()
        expected = {
            "format_version",
            "event_id",
            "occurred_at",
            "event_type",
            "outcome",
            "principal_ref",
            "vault_ref",
            "scope_refs",
            "session_ref",
            "metadata",
            "previous_hash",
            "event_hash",
        }
        if version == AUDIT_FORMAT_VERSION:
            expected.update({"operation_ref", "source_refs"})
        if set(value) != expected:
            raise AuditUnavailable()
        metadata = value["metadata"]
        scope_refs = value["scope_refs"]
        source_refs = (
            value["source_refs"]
            if version == AUDIT_FORMAT_VERSION
            else []
        )
        if (
            not isinstance(metadata, dict)
            or not isinstance(scope_refs, list)
            or not isinstance(source_refs, list)
        ):
            raise AuditUnavailable()
        record = SecurityAuditRecord(
            format_version=version,
            event_id=value["event_id"],
            occurred_at=value["occurred_at"],
            event_type=SecurityEventType(value["event_type"]),
            outcome=SecurityEventOutcome(value["outcome"]),
            principal_ref=value["principal_ref"],
            vault_ref=value["vault_ref"],
            scope_refs=tuple(scope_refs),
            session_ref=value["session_ref"],
            operation_ref=(
                value["operation_ref"]
                if version == AUDIT_FORMAT_VERSION
                else None
            ),
            source_refs=tuple(source_refs),
            metadata=MappingProxyType(dict(metadata)),
        )
    except (
        AuditUnavailable,
        KeyError,
        TypeError,
        ValueError,
    ):
        raise AuditUnavailable() from None
    nullable_refs = (
        record.principal_ref,
        record.vault_ref,
        record.session_ref,
        record.operation_ref,
    )
    if (
        not _is_hex_reference(record.event_id, length=32)
        or type(record.occurred_at) not in (int, float)
        or not math.isfinite(record.occurred_at)
        or any(ref is not None and not _is_hex_reference(ref) for ref in nullable_refs)
        or any(not _is_hex_reference(ref) for ref in record.scope_refs)
        or any(not _is_hex_reference(ref) for ref in record.source_refs)
        or (
            record.outcome is SecurityEventOutcome.PENDING
            and (
                record.format_version != AUDIT_FORMAT_VERSION
                or record.operation_ref is None
            )
        )
    ):
        raise AuditUnavailable()
    return record


def _operation_report(
    records: tuple[SecurityAuditRecord, ...],
) -> SecurityAuditVerificationReport:
    pending: dict[
        str,
        tuple[
            SecurityEventType,
            str | None,
            str | None,
            tuple[str, ...],
        ],
    ] = {}
    completed: set[str] = set()
    for record in records:
        operation_ref = record.operation_ref
        if operation_ref is None:
            continue
        linkage = (
            record.event_type,
            record.principal_ref,
            record.vault_ref,
            record.scope_refs,
        )
        if record.outcome is SecurityEventOutcome.PENDING:
            if operation_ref in pending or operation_ref in completed:
                raise AuditUnavailable()
            pending[operation_ref] = linkage
            continue
        expected = pending.pop(operation_ref, None)
        if expected is None or expected != linkage:
            raise AuditUnavailable()
        completed.add(operation_ref)
    return SecurityAuditVerificationReport(
        event_count=len(records),
        completed_operation_count=len(completed),
        pending_operation_refs=tuple(sorted(pending)),
    )


def verify_json_lines_audit_report(
    path: str | os.PathLike[str],
    signing_key: bytes | bytearray | memoryview,
) -> SecurityAuditVerificationReport:
    """Verify the chain and report any prepared operation lacking an outcome."""

    try:
        key = bytes(signing_key)
    except (TypeError, ValueError):
        raise AuditUnavailable() from None
    if len(key) < MIN_AUDIT_KEY_BYTES:
        raise AuditUnavailable()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        audit_path = Path(path)
        _validate_audit_parent(audit_path)
        descriptor = os.open(audit_path, flags)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AuditUnavailable()
        if os.name == "posix" and (
            metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise AuditUnavailable()
        previous = ZERO_HASH
        records: list[SecurityAuditRecord] = []
        with os.fdopen(descriptor, "r", encoding="ascii") as audit_file:
            descriptor = None
            for line in audit_file:
                try:
                    value = json.loads(line)
                    record = _audit_record_from_json(value)
                    observed_previous = value["previous_hash"]
                    observed_hash = value["event_hash"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    raise AuditUnavailable() from None
                if (
                    observed_previous != previous
                    or not _is_hex_reference(observed_hash)
                    or not hmac.compare_digest(
                        observed_hash,
                        _event_hash(record, previous, key),
                    )
                ):
                    raise AuditUnavailable()
                previous = observed_hash
                records.append(record)
        return _operation_report(tuple(records))
    except AuditUnavailable:
        raise
    except (OSError, UnicodeError):
        raise AuditUnavailable() from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def verify_json_lines_audit(
    path: str | os.PathLike[str],
    signing_key: bytes | bytearray | memoryview,
) -> int:
    """Verify every local audit event and return the event count."""

    return verify_json_lines_audit_report(path, signing_key).event_count


class SecurityAuditLogger:
    """Turn raw opaque identifiers into safe, committed audit records."""

    def __init__(
        self,
        sink: AuditSink,
        signing_key: bytes | bytearray | memoryview,
        *,
        clock: Callable[[], float] = time.time,
        required: bool = True,
    ) -> None:
        if not isinstance(sink, AuditSink):
            raise TypeError("sink must implement AuditSink.")
        try:
            key = bytes(signing_key)
        except (TypeError, ValueError):
            raise ValidationError("Invalid audit signing key.") from None
        if len(key) < MIN_AUDIT_KEY_BYTES or not callable(clock):
            raise ValidationError("Invalid audit logger configuration.")
        self._sink = sink
        self._signing_key = key
        self._clock = clock
        self._required = bool(required)

    def _reference(
        self,
        domain: bytes,
        value: str | None,
        *,
        max_chars: int = 256,
    ) -> str | None:
        if value is None:
            return None
        if not _valid_text(value, max_chars=max_chars):
            raise ValidationError("Invalid opaque audit identifier.")
        digest = hmac.new(
            self._signing_key,
            b"authgraph-audit-reference-v1\x00" + domain + b"\x00"
            + value.encode("utf-8"),
            hashlib.sha256,
        )
        return digest.hexdigest()

    @staticmethod
    def _metadata(
        metadata: Mapping[str, str | int | bool] | None,
    ) -> Mapping[str, str | int | bool]:
        copied = {} if metadata is None else dict(metadata)
        if len(copied) > MAX_AUDIT_METADATA_ITEMS:
            raise ValidationError("Too many audit metadata fields.")
        for key, value in copied.items():
            if not _valid_text(key, max_chars=64):
                raise ValidationError("Invalid audit metadata key.")
            if type(value) is int and key in _INTEGER_METADATA_KEYS:
                if value < 0:
                    raise ValidationError("Invalid audit metadata value.")
                continue
            if type(value) is bool and key in _BOOLEAN_METADATA_KEYS:
                continue
            if (
                isinstance(value, str)
                and key in _TEXT_METADATA_VALUES
                and value in _TEXT_METADATA_VALUES[key]
            ):
                continue
            if type(value) not in (str, int, bool):
                raise ValidationError("Invalid audit metadata value.")
            raise ValidationError("Audit metadata is not allowlisted.")
        return MappingProxyType(copied)

    def _commit(
        self,
        event_type: SecurityEventType,
        outcome: SecurityEventOutcome,
        *,
        principal_id: str | None = None,
        vault_id: str | None = None,
        scope_ids: tuple[str, ...] = (),
        session_token: str | None = None,
        operation_id: str | None = None,
        source_ids: tuple[str, ...] = (),
        metadata: Mapping[str, str | int | bool] | None = None,
        force_required: bool = False,
    ) -> CommittedSecurityAuditEvent | None:
        if (
            type(event_type) is not SecurityEventType
            or type(outcome) is not SecurityEventOutcome
            or not isinstance(scope_ids, tuple)
            or len(scope_ids) > 32
            or not isinstance(source_ids, tuple)
            or len(source_ids) > 32
        ):
            raise ValidationError("Invalid security audit event.")
        try:
            occurred_at = self._clock()
            if (
                type(occurred_at) not in (int, float)
                or not math.isfinite(occurred_at)
            ):
                raise AuditUnavailable()
            event_id = os.urandom(16).hex()
            record = SecurityAuditRecord(
                format_version=AUDIT_FORMAT_VERSION,
                event_id=event_id,
                occurred_at=float(occurred_at),
                event_type=event_type,
                outcome=outcome,
                principal_ref=self._reference(b"principal", principal_id),
                vault_ref=self._reference(b"vault", vault_id),
                scope_refs=tuple(
                    self._reference(b"scope", scope_id) or ""
                    for scope_id in scope_ids
                ),
                session_ref=self._reference(b"session", session_token),
                operation_ref=self._reference(b"operation", operation_id),
                source_refs=tuple(
                    self._reference(b"recovery-source", source_id, max_chars=4096)
                    or ""
                    for source_id in source_ids
                ),
                metadata=self._metadata(metadata),
            )
            return self._sink.append(
                record,
                signing_key=self._signing_key,
            )
        except (AuditUnavailable, ValidationError):
            if force_required or self._required:
                raise
            return None
        except Exception:
            if force_required or self._required:
                raise AuditUnavailable() from None
            return None

    def record(
        self,
        event_type: SecurityEventType,
        outcome: SecurityEventOutcome,
        *,
        principal_id: str | None = None,
        vault_id: str | None = None,
        scope_ids: tuple[str, ...] = (),
        session_token: str | None = None,
        metadata: Mapping[str, str | int | bool] | None = None,
    ) -> CommittedSecurityAuditEvent | None:
        """Commit one standalone event without management-operation linkage."""

        if outcome is SecurityEventOutcome.PENDING:
            raise ValidationError(
                "Pending events require a prepared security operation."
            )
        return self._commit(
            event_type,
            outcome,
            principal_id=principal_id,
            vault_id=vault_id,
            scope_ids=scope_ids,
            session_token=session_token,
            metadata=metadata,
        )

    def prepare_operation(
        self,
        event_type: SecurityEventType,
        *,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
        metadata: Mapping[str, str | int | bool] | None = None,
    ) -> PreparedSecurityAuditOperation:
        """Durably record management intent before the first mutation."""

        operation = PreparedSecurityAuditOperation(
            operation_id=os.urandom(16).hex(),
            event_type=event_type,
        )
        committed = self._commit(
            event_type,
            SecurityEventOutcome.PENDING,
            principal_id=principal_id,
            vault_id=vault_id,
            scope_ids=scope_ids,
            operation_id=operation.operation_id,
            metadata=metadata,
            force_required=True,
        )
        if committed is None:
            raise AuditUnavailable()
        return operation

    def complete_operation(
        self,
        operation: PreparedSecurityAuditOperation,
        outcome: SecurityEventOutcome,
        *,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
        source_ids: tuple[str, ...] = (),
        metadata: Mapping[str, str | int | bool] | None = None,
    ) -> CommittedSecurityAuditEvent:
        """Durably link a management operation to its terminal outcome."""

        if (
            not isinstance(operation, PreparedSecurityAuditOperation)
            or not _is_hex_reference(operation.operation_id, length=32)
            or type(operation.event_type) is not SecurityEventType
            or outcome is SecurityEventOutcome.PENDING
        ):
            raise ValidationError("Invalid prepared security operation.")
        committed = self._commit(
            operation.event_type,
            outcome,
            principal_id=principal_id,
            vault_id=vault_id,
            scope_ids=scope_ids,
            operation_id=operation.operation_id,
            source_ids=source_ids,
            metadata=metadata,
            force_required=True,
        )
        if committed is None:
            raise AuditUnavailable()
        return committed
