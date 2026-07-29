"""Application-layer envelope encryption for AuthGraph.

This module intentionally uses a small set of well-reviewed primitives:

* a random 256-bit data-encryption key (DEK) per vault;
* Argon2id to derive a key-encryption key (KEK) from a passphrase;
* AES-256-GCM for both DEK wrapping and record encryption; and
* associated data (AAD) that binds ciphertext to its vault and object IDs.

It is still security-sensitive code and requires independent review before
real personal, confidential, financial, or other regulated data is used.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .errors import IntegrityViolation, UnlockDenied, ValidationError
from .models import EncryptedPayload, KdfParameters, KeyEnvelope


AES_KEY_BYTES = 32
NONCE_BYTES = 12
SALT_BYTES = 16
MIN_NEW_PASSPHRASE_BYTES = 15
MAX_PASSPHRASE_BYTES = 1024
MAX_ENCRYPTED_JSON_BYTES = 64 * 1024
MIN_PRODUCTION_MEMORY_KIB = 19 * 1024
MIN_PRODUCTION_ITERATIONS = 2
MAX_ACCEPTED_MEMORY_KIB = 256 * 1024
MAX_ACCEPTED_ITERATIONS = 10
MAX_ACCEPTED_LANES = 8


def clear_bytearray(value: bytearray) -> None:
    """Best-effort overwrite of a mutable secret buffer."""

    value[:] = b"\x00" * len(value)


def _aad(*parts: object) -> bytes:
    """Create an unambiguous, canonical AAD encoding."""

    return json.dumps(
        ["authgraph", *parts],
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("ascii")


def _buffer_size(value: bytes | bytearray | memoryview) -> int:
    return value.nbytes if isinstance(value, memoryview) else len(value)


def _passphrase_bytes(
    passphrase: bytes | bytearray | memoryview,
) -> bytes | bytearray | memoryview:
    if not isinstance(passphrase, (bytes, bytearray, memoryview)):
        raise ValidationError("Passphrases must be supplied as bytes-like data.")
    if (
        isinstance(passphrase, memoryview)
        and not passphrase.contiguous
    ):
        raise ValidationError("Passphrase buffers must be contiguous.")
    if _buffer_size(passphrase) > MAX_PASSPHRASE_BYTES:
        raise ValidationError("Passphrase input is too large.")
    return passphrase


def _validate_new_passphrase(passphrase: bytes | bytearray | memoryview) -> None:
    material = _passphrase_bytes(passphrase)
    if _buffer_size(material) < MIN_NEW_PASSPHRASE_BYTES:
        raise ValidationError(
            f"A new vault passphrase must contain at least "
            f"{MIN_NEW_PASSPHRASE_BYTES} UTF-8 bytes."
        )


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValidationError("Encrypted payloads must be valid JSON objects.") from exc
    if len(encoded) > MAX_ENCRYPTED_JSON_BYTES:
        raise ValidationError(
            f"An encrypted payload may contain at most "
            f"{MAX_ENCRYPTED_JSON_BYTES} bytes."
        )
    return encoded


class CryptoEngine:
    """Creates key envelopes and authenticated record ciphertexts."""

    def __init__(
        self,
        kdf_parameters: KdfParameters | None = None,
        *,
        allow_insecure_kdf_for_testing: bool = False,
    ) -> None:
        if type(allow_insecure_kdf_for_testing) is not bool:
            raise ValidationError(
                "The insecure-KDF override must be an explicit boolean."
            )
        self._kdf = (
            KdfParameters() if kdf_parameters is None else kdf_parameters
        )
        self._allow_insecure_kdf_for_testing = allow_insecure_kdf_for_testing
        self._validate_kdf(self._kdf, allow_insecure_kdf_for_testing)

    @staticmethod
    def _validate_kdf(parameters: KdfParameters, allow_insecure: bool) -> None:
        if (
            not isinstance(parameters, KdfParameters)
            or not isinstance(parameters.algorithm, str)
            or parameters.algorithm != "argon2id"
        ):
            raise ValidationError("Only Argon2id key derivation is supported.")
        if (
            type(parameters.memory_cost_kib) is not int
            or type(parameters.iterations) is not int
            or type(parameters.lanes) is not int
            or type(parameters.output_length) is not int
            or parameters.memory_cost_kib <= 0
            or parameters.iterations <= 0
            or parameters.lanes <= 0
            or parameters.output_length != AES_KEY_BYTES
            or parameters.memory_cost_kib > MAX_ACCEPTED_MEMORY_KIB
            or parameters.iterations > MAX_ACCEPTED_ITERATIONS
            or parameters.lanes > MAX_ACCEPTED_LANES
        ):
            raise ValidationError("Invalid Argon2id parameters.")
        if not allow_insecure and (
            parameters.memory_cost_kib < MIN_PRODUCTION_MEMORY_KIB
            or parameters.iterations < MIN_PRODUCTION_ITERATIONS
        ):
            raise ValidationError(
                "KDF parameters are below AuthGraph's production safety floor."
            )

    @staticmethod
    def _derive_kek(
        passphrase: bytes | bytearray | memoryview,
        salt: bytes,
        parameters: KdfParameters,
    ) -> bytearray:
        material = _passphrase_bytes(passphrase)
        kdf = Argon2id(
            salt=salt,
            length=parameters.output_length,
            iterations=parameters.iterations,
            lanes=parameters.lanes,
            memory_cost=parameters.memory_cost_kib,
        )
        return bytearray(kdf.derive(material))

    @staticmethod
    def _envelope_aad(
        principal_id: str,
        vault_id: str,
        *,
        version: int,
        envelope_revision: int,
        key_version: int,
        wrapping_algorithm: str,
        kdf: KdfParameters,
        salt: bytes,
    ) -> bytes:
        return _aad(
            "key-envelope",
            version,
            principal_id,
            vault_id,
            envelope_revision,
            key_version,
            wrapping_algorithm,
            kdf.algorithm,
            kdf.memory_cost_kib,
            kdf.iterations,
            kdf.lanes,
            kdf.output_length,
            salt.hex(),
        )

    @staticmethod
    def _payload_aad(
        *,
        version: int,
        key_version: int,
        algorithm: str,
        aad_parts: tuple[object, ...],
    ) -> bytes:
        return _aad(
            "encrypted-payload",
            version,
            key_version,
            algorithm,
            *aad_parts,
        )

    def provision_vault(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
    ) -> tuple[KeyEnvelope, bytearray]:
        """Generate a new random DEK and its passphrase-wrapped envelope."""

        _validate_new_passphrase(passphrase)
        dek = bytearray(AESGCM.generate_key(bit_length=256))
        try:
            envelope = self.wrap_dek(
                principal_id,
                vault_id,
                passphrase,
                dek,
                envelope_revision=1,
                key_version=1,
            )
        except Exception:
            clear_bytearray(dek)
            raise
        return envelope, dek

    def wrap_dek(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
        dek: bytes | bytearray | memoryview,
        *,
        envelope_revision: int,
        key_version: int,
    ) -> KeyEnvelope:
        """Wrap an existing DEK, normally for initial setup or password change."""

        _validate_new_passphrase(passphrase)
        if (
            not isinstance(dek, (bytes, bytearray, memoryview))
            or _buffer_size(dek) != AES_KEY_BYTES
        ):
            raise ValidationError("A vault DEK must be exactly 256 bits.")
        if (
            type(envelope_revision) is not int
            or envelope_revision <= 0
            or type(key_version) is not int
            or key_version <= 0
        ):
            raise ValidationError("Vault key versions must be positive integers.")
        salt = os.urandom(SALT_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        kek = self._derive_kek(passphrase, salt, self._kdf)
        try:
            wrapped = AESGCM(kek).encrypt(
                nonce,
                dek,
                self._envelope_aad(
                    principal_id,
                    vault_id,
                    version=1,
                    envelope_revision=envelope_revision,
                    key_version=key_version,
                    wrapping_algorithm="AES-256-GCM",
                    kdf=self._kdf,
                    salt=salt,
                ),
            )
        finally:
            clear_bytearray(kek)
        return KeyEnvelope(
            version=1,
            envelope_revision=envelope_revision,
            key_version=key_version,
            wrapping_algorithm="AES-256-GCM",
            kdf=self._kdf,
            salt=salt,
            nonce=nonce,
            wrapped_dek=wrapped,
        )

    def unwrap_dek(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
        envelope: KeyEnvelope,
    ) -> bytearray:
        """Unlock a vault DEK or raise the same generic error for every failure."""

        try:
            material = _passphrase_bytes(passphrase)
            if (
                not isinstance(envelope, KeyEnvelope)
                or type(envelope.version) is not int
                or envelope.version != 1
                or type(envelope.envelope_revision) is not int
                or envelope.envelope_revision <= 0
                or type(envelope.key_version) is not int
                or envelope.key_version <= 0
                or not isinstance(envelope.wrapping_algorithm, str)
                or envelope.wrapping_algorithm != "AES-256-GCM"
                or not isinstance(envelope.kdf, KdfParameters)
                or not isinstance(envelope.salt, bytes)
                or len(envelope.salt) != SALT_BYTES
                or not isinstance(envelope.nonce, bytes)
                or len(envelope.nonce) != NONCE_BYTES
                or not isinstance(envelope.wrapped_dek, bytes)
                or len(envelope.wrapped_dek) != AES_KEY_BYTES + 16
            ):
                raise UnlockDenied()
            self._validate_kdf(
                envelope.kdf,
                self._allow_insecure_kdf_for_testing,
            )
            kek = self._derive_kek(material, envelope.salt, envelope.kdf)
            try:
                plaintext = bytearray(
                    AESGCM(kek).decrypt(
                        envelope.nonce,
                        envelope.wrapped_dek,
                        self._envelope_aad(
                            principal_id,
                            vault_id,
                            version=envelope.version,
                            envelope_revision=envelope.envelope_revision,
                            key_version=envelope.key_version,
                            wrapping_algorithm=envelope.wrapping_algorithm,
                            kdf=envelope.kdf,
                            salt=envelope.salt,
                        ),
                    )
                )
            finally:
                clear_bytearray(kek)
            if len(plaintext) != AES_KEY_BYTES:
                clear_bytearray(plaintext)
                raise UnlockDenied()
            return plaintext
        except (
            InvalidTag,
            MemoryError,
            ValidationError,
            ValueError,
            TypeError,
            OverflowError,
            AttributeError,
            UnlockDenied,
        ):
            raise UnlockDenied() from None

    def burn_failed_unlock(
        self, passphrase: bytes | bytearray | memoryview
    ) -> None:
        """Spend KDF work when a vault is absent to reduce timing disclosure."""

        try:
            salt = os.urandom(SALT_BYTES)
            kek = self._derive_kek(passphrase, salt, self._kdf)
            clear_bytearray(kek)
        except (ValidationError, ValueError, TypeError):
            # The public caller still receives only UnlockDenied.
            return

    @staticmethod
    def encrypt_json(
        dek: bytes | bytearray | memoryview,
        value: Mapping[str, Any],
        *,
        aad_parts: tuple[object, ...],
        key_version: int = 1,
    ) -> EncryptedPayload:
        if (
            not isinstance(dek, (bytes, bytearray, memoryview))
            or _buffer_size(dek) != AES_KEY_BYTES
            or type(key_version) is not int
            or key_version <= 0
        ):
            raise ValidationError("A vault DEK must be exactly 256 bits.")
        plaintext = bytearray(_canonical_json(value))
        nonce = os.urandom(NONCE_BYTES)
        try:
            ciphertext = AESGCM(dek).encrypt(
                nonce,
                plaintext,
                CryptoEngine._payload_aad(
                    version=1,
                    key_version=key_version,
                    algorithm="AES-256-GCM",
                    aad_parts=aad_parts,
                ),
            )
        finally:
            clear_bytearray(plaintext)
        return EncryptedPayload(
            version=1,
            key_version=key_version,
            algorithm="AES-256-GCM",
            nonce=nonce,
            ciphertext=ciphertext,
        )

    @staticmethod
    def decrypt_json(
        dek: bytes | bytearray | memoryview,
        payload: EncryptedPayload,
        *,
        aad_parts: tuple[object, ...],
    ) -> dict[str, Any]:
        if (
            not isinstance(dek, (bytes, bytearray, memoryview))
            or _buffer_size(dek) != AES_KEY_BYTES
            or not isinstance(payload, EncryptedPayload)
            or type(payload.version) is not int
            or payload.version != 1
            or type(payload.key_version) is not int
            or payload.key_version <= 0
            or not isinstance(payload.algorithm, str)
            or payload.algorithm != "AES-256-GCM"
            or not isinstance(payload.nonce, bytes)
            or len(payload.nonce) != NONCE_BYTES
            or not isinstance(payload.ciphertext, bytes)
            or len(payload.ciphertext) < 16
            or len(payload.ciphertext) > MAX_ENCRYPTED_JSON_BYTES + 16
        ):
            raise IntegrityViolation()
        try:
            plaintext = bytearray(
                AESGCM(dek).decrypt(
                    payload.nonce,
                    payload.ciphertext,
                    CryptoEngine._payload_aad(
                        version=payload.version,
                        key_version=payload.key_version,
                        algorithm=payload.algorithm,
                        aad_parts=aad_parts,
                    ),
                )
            )
        except (InvalidTag, ValueError, TypeError):
            raise IntegrityViolation() from None
        try:
            decoded = json.loads(plaintext.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise IntegrityViolation()
            return decoded
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            IntegrityViolation,
        ):
            raise IntegrityViolation() from None
        finally:
            clear_bytearray(plaintext)
