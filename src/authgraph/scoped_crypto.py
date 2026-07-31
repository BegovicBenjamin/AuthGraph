"""Cryptographic helpers for independent private protection scopes."""

from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import AES_KEY_BYTES, NONCE_BYTES
from .errors import IntegrityViolation, ValidationError
from .models import ScopeKeyEnvelope


SCOPE_ENVELOPE_VERSION = 1
SCOPE_WRAPPING_ALGORITHM = "AES-256-GCM"
SCOPE_DEK_CIPHERTEXT_BYTES = AES_KEY_BYTES + 16


def _buffer_size(value: bytes | bytearray | memoryview) -> int:
    return value.nbytes if isinstance(value, memoryview) else len(value)


def _scope_aad(
    principal_id: str,
    vault_id: str,
    scope_id: str,
    *,
    version: int,
    root_key_version: int,
    scope_key_version: int,
    algorithm: str,
) -> bytes:
    return json.dumps(
        [
            "authgraph",
            "scope-key-envelope",
            version,
            principal_id,
            vault_id,
            scope_id,
            root_key_version,
            scope_key_version,
            algorithm,
        ],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")


def generate_scope_dek() -> bytearray:
    """Return a new mutable random 256-bit scope data-encryption key."""

    return bytearray(AESGCM.generate_key(bit_length=256))


def wrap_scope_dek(
    root_dek: bytes | bytearray | memoryview,
    scope_dek: bytes | bytearray | memoryview,
    *,
    principal_id: str,
    vault_id: str,
    scope_id: str,
    root_key_version: int,
    scope_key_version: int = 1,
) -> ScopeKeyEnvelope:
    """Wrap one scope DEK with the vault's random root DEK."""

    if (
        not isinstance(root_dek, (bytes, bytearray, memoryview))
        or _buffer_size(root_dek) != AES_KEY_BYTES
        or not isinstance(scope_dek, (bytes, bytearray, memoryview))
        or _buffer_size(scope_dek) != AES_KEY_BYTES
        or type(root_key_version) is not int
        or root_key_version <= 0
        or type(scope_key_version) is not int
        or scope_key_version <= 0
    ):
        raise ValidationError("Invalid protection-scope key material.")
    nonce = os.urandom(NONCE_BYTES)
    aad = _scope_aad(
        principal_id,
        vault_id,
        scope_id,
        version=SCOPE_ENVELOPE_VERSION,
        root_key_version=root_key_version,
        scope_key_version=scope_key_version,
        algorithm=SCOPE_WRAPPING_ALGORITHM,
    )
    wrapped = AESGCM(bytes(root_dek)).encrypt(
        nonce,
        bytes(scope_dek),
        aad,
    )
    return ScopeKeyEnvelope(
        version=SCOPE_ENVELOPE_VERSION,
        root_key_version=root_key_version,
        scope_key_version=scope_key_version,
        algorithm=SCOPE_WRAPPING_ALGORITHM,
        nonce=nonce,
        wrapped_scope_dek=wrapped,
    )


def unwrap_scope_dek(
    root_dek: bytes | bytearray | memoryview,
    envelope: ScopeKeyEnvelope,
    *,
    principal_id: str,
    vault_id: str,
    scope_id: str,
    expected_root_key_version: int,
) -> bytearray:
    """Authenticate and unwrap one scope DEK."""

    if (
        not isinstance(root_dek, (bytes, bytearray, memoryview))
        or _buffer_size(root_dek) != AES_KEY_BYTES
        or not isinstance(envelope, ScopeKeyEnvelope)
        or envelope.version != SCOPE_ENVELOPE_VERSION
        or envelope.root_key_version != expected_root_key_version
        or type(envelope.scope_key_version) is not int
        or envelope.scope_key_version <= 0
        or envelope.algorithm != SCOPE_WRAPPING_ALGORITHM
        or not isinstance(envelope.nonce, bytes)
        or len(envelope.nonce) != NONCE_BYTES
        or not isinstance(envelope.wrapped_scope_dek, bytes)
        or len(envelope.wrapped_scope_dek) != SCOPE_DEK_CIPHERTEXT_BYTES
    ):
        raise IntegrityViolation()
    aad = _scope_aad(
        principal_id,
        vault_id,
        scope_id,
        version=envelope.version,
        root_key_version=envelope.root_key_version,
        scope_key_version=envelope.scope_key_version,
        algorithm=envelope.algorithm,
    )
    try:
        plaintext = AESGCM(bytes(root_dek)).decrypt(
            envelope.nonce,
            envelope.wrapped_scope_dek,
            aad,
        )
    except (InvalidTag, ValueError, TypeError):
        raise IntegrityViolation() from None
    if len(plaintext) != AES_KEY_BYTES:
        raise IntegrityViolation()
    return bytearray(plaintext)
