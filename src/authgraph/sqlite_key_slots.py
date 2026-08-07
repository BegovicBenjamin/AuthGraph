"""Durable single-host key-slot storage for ``EnvelopeScopeKeyProvider``.

SQLite serializes compare-and-swap batches across local worker processes.  The
database stores only provider-wrapped key blobs and ciphertext-free revocation
tombstones, never plaintext DEKs.  Multi-host deployments should provide the
same ``KeySlotStore`` contract with a shared strongly consistent database.
"""

from __future__ import annotations

import math
import os
import sqlite3
import stat
import threading
from collections.abc import Mapping
from pathlib import Path

from .errors import ValidationError
from .key_custody import (
    MAX_SCOPES_PER_SESSION,
    KeyCustodyUnavailable,
    KeySlotIdentity,
    KeySlotRow,
    KeySlotState,
    WrappedKeyBlob,
)


class SqliteKeySlotStore:
    """Process-safe, restart-safe SQLite implementation of ``KeySlotStore``."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        busy_timeout_seconds: float = 5.0,
    ) -> None:
        if (
            type(busy_timeout_seconds) not in (int, float)
            or not math.isfinite(busy_timeout_seconds)
            or busy_timeout_seconds <= 0
            or busy_timeout_seconds > 60
        ):
            raise ValidationError("Invalid key-slot store configuration.")
        self._path = Path(database_path)
        self._timeout = float(busy_timeout_seconds)
        self._state_lock = threading.Lock()
        self._prepare_database_file()
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS authgraph_key_slot (
                    principal_id TEXT NOT NULL,
                    vault_id TEXT NOT NULL,
                    scope_id TEXT NOT NULL,
                    slot_version INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    enrolled_envelope_revision INTEGER,
                    root_key_version INTEGER,
                    scope_key_version INTEGER,
                    wrapped_format_version INTEGER,
                    backend_id TEXT,
                    provider_key_id TEXT,
                    algorithm TEXT,
                    ciphertext BLOB,
                    PRIMARY KEY (principal_id, vault_id, scope_id)
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS authgraph_key_slot_vault
                ON authgraph_key_slot(principal_id, vault_id)
                """
            )
        except Exception:
            raise KeyCustodyUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    def _prepare_database_file(self) -> None:
        try:
            parent = self._path.parent
            if not parent.is_dir():
                raise KeyCustodyUnavailable()
            parent_metadata = parent.lstat()
            if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
                parent_metadata.st_mode
            ):
                raise KeyCustodyUnavailable()
            if os.name == "posix" and (
                parent_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(parent_metadata.st_mode) & 0o022
            ):
                raise KeyCustodyUnavailable()
            if self._path.exists() or self._path.is_symlink():
                metadata = self._path.lstat()
                if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(
                    metadata.st_mode
                ):
                    raise KeyCustodyUnavailable()
                if os.name == "posix" and (
                    metadata.st_uid != os.geteuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                ):
                    raise KeyCustodyUnavailable()
                return
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(self._path, flags, 0o600)
            os.close(descriptor)
        except KeyCustodyUnavailable:
            raise
        except OSError:
            raise KeyCustodyUnavailable() from None

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
    def _identity(
        principal_id: str,
        vault_id: str,
        scope_id: str,
    ) -> KeySlotIdentity:
        return KeySlotIdentity(principal_id, vault_id, scope_id)

    @staticmethod
    def _row(record: sqlite3.Row) -> KeySlotRow:
        try:
            state = KeySlotState(record["state"])
            wrapped = None
            if state is KeySlotState.ACTIVE:
                wrapped = WrappedKeyBlob(
                    backend_id=record["backend_id"],
                    key_id=record["provider_key_id"],
                    algorithm=record["algorithm"],
                    ciphertext=bytes(record["ciphertext"]),
                    format_version=int(record["wrapped_format_version"]),
                )
            return KeySlotRow(
                identity=KeySlotIdentity(
                    record["principal_id"],
                    record["vault_id"],
                    record["scope_id"],
                ),
                slot_version=int(record["slot_version"]),
                state=state,
                enrolled_envelope_revision=record[
                    "enrolled_envelope_revision"
                ],
                root_key_version=record["root_key_version"],
                scope_key_version=record["scope_key_version"],
                wrapped_key=wrapped,
            )
        except (KeyError, TypeError, ValueError, ValidationError):
            raise KeyCustodyUnavailable() from None

    @staticmethod
    def _parameters(row: KeySlotRow) -> tuple[object, ...]:
        wrapped = row.wrapped_key
        return (
            row.identity.principal_id,
            row.identity.vault_id,
            row.identity.scope_id,
            row.slot_version,
            row.state.value,
            row.enrolled_envelope_revision,
            row.root_key_version,
            row.scope_key_version,
            None if wrapped is None else wrapped.format_version,
            None if wrapped is None else wrapped.backend_id,
            None if wrapped is None else wrapped.key_id,
            None if wrapped is None else wrapped.algorithm,
            None if wrapped is None else wrapped.ciphertext,
        )

    @staticmethod
    def _validate_cas(
        expected_versions: Mapping[KeySlotIdentity, int | None],
        replacement_rows: tuple[KeySlotRow, ...],
    ) -> tuple[
        dict[KeySlotIdentity, int | None],
        dict[KeySlotIdentity, KeySlotRow],
    ]:
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
            if not isinstance(row, KeySlotRow) or row.identity in replacements:
                raise ValidationError(
                    "Invalid key-slot compare-and-swap request."
                )
            replacements[row.identity] = row
        if set(expected) != set(replacements):
            raise ValidationError("Invalid key-slot compare-and-swap request.")
        for identity, expected_version in expected.items():
            replacement_version = replacements[identity].slot_version
            allowed = (
                replacement_version == 1
                if expected_version is None
                else replacement_version in (
                    expected_version,
                    expected_version + 1,
                )
            )
            if not allowed:
                raise ValidationError(
                    "Invalid key-slot compare-and-swap revision."
                )
        return expected, replacements

    def get_slots(
        self,
        *,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
    ) -> tuple[KeySlotRow, ...]:
        if (
            not isinstance(scope_ids, tuple)
            or not scope_ids
            or len(scope_ids) > MAX_SCOPES_PER_SESSION
            or len(set(scope_ids)) != len(scope_ids)
        ):
            raise ValidationError("Invalid protection-scope set.")
        identities = tuple(
            self._identity(principal_id, vault_id, scope_id)
            for scope_id in scope_ids
        )
        placeholders = ",".join("?" for _ in scope_ids)
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            records = connection.execute(
                f"""
                SELECT * FROM authgraph_key_slot
                WHERE principal_id = ? AND vault_id = ?
                  AND scope_id IN ({placeholders})
                """,
                (principal_id, vault_id, *scope_ids),
            ).fetchall()
            by_identity = {
                row.identity: row
                for row in (self._row(record) for record in records)
            }
            return tuple(
                by_identity[identity]
                for identity in identities
                if identity in by_identity
            )
        except (ValidationError, KeyCustodyUnavailable):
            raise
        except Exception:
            raise KeyCustodyUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    def compare_and_swap_slots(
        self,
        *,
        expected_versions: Mapping[KeySlotIdentity, int | None],
        replacement_rows: tuple[KeySlotRow, ...],
    ) -> bool:
        expected, replacements = self._validate_cas(
            expected_versions,
            replacement_rows,
        )
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            for identity, expected_version in expected.items():
                record = connection.execute(
                    """
                    SELECT slot_version FROM authgraph_key_slot
                    WHERE principal_id = ? AND vault_id = ? AND scope_id = ?
                    """,
                    (
                        identity.principal_id,
                        identity.vault_id,
                        identity.scope_id,
                    ),
                ).fetchone()
                current_version = None if record is None else int(record[0])
                if current_version != expected_version:
                    connection.rollback()
                    return False
                replacement = replacements[identity]
                if (
                    expected_version is not None
                    and replacement.slot_version == expected_version
                ):
                    current = connection.execute(
                        """
                        SELECT * FROM authgraph_key_slot
                        WHERE principal_id = ? AND vault_id = ? AND scope_id = ?
                        """,
                        (
                            identity.principal_id,
                            identity.vault_id,
                            identity.scope_id,
                        ),
                    ).fetchone()
                    if current is None or self._row(current) != replacement:
                        raise ValidationError(
                            "A changed key-slot row must advance its revision."
                        )
            for identity in expected:
                row = replacements[identity]
                connection.execute(
                    """
                    INSERT INTO authgraph_key_slot(
                        principal_id, vault_id, scope_id, slot_version, state,
                        enrolled_envelope_revision, root_key_version,
                        scope_key_version, wrapped_format_version, backend_id,
                        provider_key_id, algorithm, ciphertext
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(principal_id, vault_id, scope_id) DO UPDATE SET
                        slot_version = excluded.slot_version,
                        state = excluded.state,
                        enrolled_envelope_revision =
                            excluded.enrolled_envelope_revision,
                        root_key_version = excluded.root_key_version,
                        scope_key_version = excluded.scope_key_version,
                        wrapped_format_version = excluded.wrapped_format_version,
                        backend_id = excluded.backend_id,
                        provider_key_id = excluded.provider_key_id,
                        algorithm = excluded.algorithm,
                        ciphertext = excluded.ciphertext
                    """,
                    self._parameters(row),
                )
            connection.commit()
            return True
        except (ValidationError, KeyCustodyUnavailable):
            if connection is not None:
                connection.rollback()
            raise
        except Exception:
            if connection is not None:
                connection.rollback()
            raise KeyCustodyUnavailable() from None
        finally:
            if connection is not None:
                connection.close()

    def list_vault_slots(
        self,
        *,
        principal_id: str,
        vault_id: str,
    ) -> tuple[KeySlotRow, ...]:
        self._identity(principal_id, vault_id, "validation-scope")
        connection: sqlite3.Connection | None = None
        try:
            connection = self._connect()
            records = connection.execute(
                """
                SELECT * FROM authgraph_key_slot
                WHERE principal_id = ? AND vault_id = ?
                ORDER BY scope_id
                """,
                (principal_id, vault_id),
            ).fetchall()
            return tuple(self._row(record) for record in records)
        except (ValidationError, KeyCustodyUnavailable):
            raise
        except Exception:
            raise KeyCustodyUnavailable() from None
        finally:
            if connection is not None:
                connection.close()
