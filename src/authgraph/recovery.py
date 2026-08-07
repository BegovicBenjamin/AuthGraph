"""Independent recovery wrapping for KMS/HSM-protected scope keys.

``MirroredKeyWrappingBackend`` writes two independently wrapped copies of the
same 256-bit key: one through a primary backend and one through a separately
controlled recovery backend.  Ordinary reads use only the primary copy.  The
recovery copy is reachable only through the explicit recovery API, so routine
session release can never invoke break-glass credentials.

Recovery access is security-critical.  Keep the recovery backend in a
different account/security domain, require strong human authorization, audit
every use, and rewrap to a fresh primary immediately after recovery.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager

from .crypto import AES_KEY_BYTES, clear_bytearray
from .errors import ValidationError
from .key_custody import (
    MAX_WRAPPED_KEY_BYTES,
    KeyCustodyUnavailable,
    KeyWrappingBackend,
    RecoveredKeyMaterial,
    RecoveryKeyProvenance,
    WrappedKeyBlob,
)

MIRRORED_ALGORITHM = "AUTHGRAPH-MIRRORED-KEY-V1"
MIRRORED_FORMAT_VERSION = 1


def _blob_json(blob: WrappedKeyBlob) -> dict[str, object]:
    return {
        "format_version": blob.format_version,
        "backend_id": blob.backend_id,
        "key_id": blob.key_id,
        "algorithm": blob.algorithm,
        "ciphertext": base64.b64encode(blob.ciphertext).decode("ascii"),
    }


def _decode_blob(value: object) -> WrappedKeyBlob:
    if not isinstance(value, dict) or set(value) != {
        "format_version",
        "backend_id",
        "key_id",
        "algorithm",
        "ciphertext",
    }:
        raise KeyCustodyUnavailable()
    try:
        ciphertext_text = value["ciphertext"]
        if not isinstance(ciphertext_text, str):
            raise KeyCustodyUnavailable()
        ciphertext = base64.b64decode(
            ciphertext_text.encode("ascii"),
            validate=True,
        )
        return WrappedKeyBlob(
            format_version=value["format_version"],
            backend_id=value["backend_id"],
            key_id=value["key_id"],
            algorithm=value["algorithm"],
            ciphertext=ciphertext,
        )
    except (KeyCustodyUnavailable, ValidationError):
        raise KeyCustodyUnavailable() from None
    except (TypeError, ValueError, UnicodeError):
        raise KeyCustodyUnavailable() from None


class MirroredKeyWrappingBackend:
    """Compose primary and recovery backends into one wrapped-key backend."""

    def __init__(
        self,
        primary: KeyWrappingBackend,
        recovery: KeyWrappingBackend,
        *,
        backend_id: str,
    ) -> None:
        if (
            not isinstance(primary, KeyWrappingBackend)
            or not isinstance(recovery, KeyWrappingBackend)
            or primary.backend_id == recovery.backend_id
            or not isinstance(backend_id, str)
            or not backend_id
            or len(backend_id) > 128
            or backend_id in (primary.backend_id, recovery.backend_id)
        ):
            raise ValidationError("Invalid mirrored recovery backend.")
        self._primary = primary
        self._recovery = recovery
        self._backend_id = backend_id

    @property
    def backend_id(self) -> str:
        return self._backend_id

    @staticmethod
    def _validated_plaintext(
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
        if type(aad) is not bytes or not aad:
            raise ValidationError("Invalid key-slot associated data.")
        copied = self._validated_plaintext(plaintext)
        try:
            primary_blob = self._primary.wrap_key(copied, aad=aad)
            recovery_blob = self._recovery.wrap_key(copied, aad=aad)
            if (
                not isinstance(primary_blob, WrappedKeyBlob)
                or not isinstance(recovery_blob, WrappedKeyBlob)
                or primary_blob.backend_id != self._primary.backend_id
                or recovery_blob.backend_id != self._recovery.backend_id
            ):
                raise KeyCustodyUnavailable()
            payload = json.dumps(
                {
                    "version": MIRRORED_FORMAT_VERSION,
                    "primary": _blob_json(primary_blob),
                    "recovery": _blob_json(recovery_blob),
                },
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
            if len(payload) > MAX_WRAPPED_KEY_BYTES:
                raise KeyCustodyUnavailable()
            key_fingerprint = hashlib.sha256(
                (
                    primary_blob.key_id
                    + "\x00"
                    + recovery_blob.key_id
                ).encode("utf-8")
            ).hexdigest()
            return WrappedKeyBlob(
                backend_id=self._backend_id,
                key_id=f"mirror-{key_fingerprint}",
                algorithm=MIRRORED_ALGORITHM,
                ciphertext=payload,
            )
        except (ValidationError, KeyCustodyUnavailable):
            raise
        except Exception:
            raise KeyCustodyUnavailable() from None
        finally:
            clear_bytearray(copied)

    @staticmethod
    def _children(wrapped_key: WrappedKeyBlob) -> tuple[WrappedKeyBlob, WrappedKeyBlob]:
        if (
            not isinstance(wrapped_key, WrappedKeyBlob)
            or wrapped_key.algorithm != MIRRORED_ALGORITHM
        ):
            raise KeyCustodyUnavailable()
        try:
            value = json.loads(wrapped_key.ciphertext)
        except (json.JSONDecodeError, UnicodeError, RecursionError):
            raise KeyCustodyUnavailable() from None
        if (
            not isinstance(value, dict)
            or set(value) != {"version", "primary", "recovery"}
            or value["version"] != MIRRORED_FORMAT_VERSION
        ):
            raise KeyCustodyUnavailable()
        return _decode_blob(value["primary"]), _decode_blob(value["recovery"])

    @contextmanager
    def unwrap_key(
        self,
        wrapped_key: WrappedKeyBlob,
        *,
        aad: bytes,
    ) -> Iterator[bytearray]:
        if (
            type(aad) is not bytes
            or not aad
            or not isinstance(wrapped_key, WrappedKeyBlob)
            or wrapped_key.backend_id != self._backend_id
        ):
            raise KeyCustodyUnavailable()
        primary_blob, _ = self._children(wrapped_key)
        try:
            with self._primary.unwrap_key(primary_blob, aad=aad) as plaintext:
                if (
                    not isinstance(plaintext, bytearray)
                    or len(plaintext) != AES_KEY_BYTES
                ):
                    raise KeyCustodyUnavailable()
                output = bytearray(plaintext)
                try:
                    yield output
                finally:
                    clear_bytearray(output)
        except KeyCustodyUnavailable:
            raise
        except Exception:
            raise KeyCustodyUnavailable() from None

    @contextmanager
    def unwrap_key_for_recovery(
        self,
        wrapped_key: WrappedKeyBlob,
        *,
        aad: bytes,
    ) -> Iterator[RecoveredKeyMaterial]:
        """Use only the independently controlled break-glass copy."""

        if (
            type(aad) is not bytes
            or not aad
            or not isinstance(wrapped_key, WrappedKeyBlob)
            or wrapped_key.backend_id != self._backend_id
        ):
            raise KeyCustodyUnavailable()
        _, recovery_blob = self._children(wrapped_key)
        try:
            with self._recovery.unwrap_key(
                recovery_blob,
                aad=aad,
            ) as plaintext:
                material = RecoveredKeyMaterial(
                    dek=plaintext,
                    provenance=RecoveryKeyProvenance(
                        backend_id=recovery_blob.backend_id,
                        key_id=recovery_blob.key_id,
                    ),
                )
                yield material
        except KeyCustodyUnavailable:
            raise
        except Exception:
            raise KeyCustodyUnavailable() from None
