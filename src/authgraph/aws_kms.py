"""AWS KMS wrapping backend with an injected, boto3-compatible client.

The module intentionally does not import or depend on boto3.  Applications
construct their authenticated regional KMS client and inject it here.  Only a
digest of AuthGraph's slot AAD is sent as an AWS encryption context, because
AWS records encryption contexts in CloudTrail.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any, Protocol, runtime_checkable

from .crypto import AES_KEY_BYTES, clear_bytearray
from .errors import ValidationError
from .key_custody import (
    MAX_BACKEND_ID_CHARS,
    MAX_KEY_ID_CHARS,
    KeyCustodyUnavailable,
    WrappedKeyBlob,
    _validate_text,
)

AWS_KMS_ALGORITHM = "SYMMETRIC_DEFAULT"
AWS_KMS_PURPOSE = "authgraph-scope-key-slot-v1"

__all__ = [
    "AWS_KMS_ALGORITHM",
    "AWS_KMS_PURPOSE",
    "AwsKmsKeyWrappingBackend",
]


@runtime_checkable
class _KmsClient(Protocol):
    def encrypt(self, **kwargs: object) -> object: ...

    def decrypt(self, **kwargs: object) -> object: ...


class AwsKmsKeyWrappingBackend:
    """Wrap scope keys through a synchronous AWS KMS-compatible client.

    ``backend_id`` must identify the exact configured provider-key generation
    (for example ``aws-kms-primary-2026``).  That makes provider rewrap safely
    idempotent even when AWS aliases later move to another key.
    """

    def __init__(
        self,
        client: object,
        *,
        key_id: str,
        backend_id: str = "aws-kms",
    ) -> None:
        if not isinstance(client, _KmsClient):
            raise TypeError(
                "client must provide synchronous encrypt() and decrypt()."
            )
        self._client = client
        self._key_id = _validate_text(
            key_id,
            maximum=MAX_KEY_ID_CHARS,
            message="Invalid AWS KMS key identifier.",
        )
        self._backend_id = _validate_text(
            backend_id,
            maximum=MAX_BACKEND_ID_CHARS,
            message="Invalid key-wrapping backend identifier.",
        )

    @property
    def backend_id(self) -> str:
        return self._backend_id

    @staticmethod
    def _validated_aad(aad: object) -> bytes:
        if type(aad) is not bytes or not aad:
            raise ValidationError("Invalid key-slot associated data.")
        return aad

    @staticmethod
    def _copy_plaintext(
        plaintext: bytes | bytearray | memoryview,
    ) -> bytearray:
        try:
            view = memoryview(plaintext)
            if not view.contiguous or view.nbytes != AES_KEY_BYTES:
                raise ValidationError("Invalid scope key material.")
            return bytearray(view.cast("B"))
        except (TypeError, ValueError):
            raise ValidationError("Invalid scope key material.") from None

    @staticmethod
    def _encryption_context(aad: bytes) -> dict[str, str]:
        return {
            "authgraph-purpose": AWS_KMS_PURPOSE,
            "authgraph-aad-sha256": hashlib.sha256(aad).hexdigest(),
        }

    @staticmethod
    def _response_mapping(response: object) -> Mapping[str, Any]:
        if not isinstance(response, Mapping):
            raise KeyCustodyUnavailable()
        return response

    @staticmethod
    def _immutable_blob(value: object) -> bytes:
        try:
            view = memoryview(value)  # type: ignore[arg-type]
            if not view.contiguous or view.nbytes <= 0:
                raise KeyCustodyUnavailable()
            return bytes(view.cast("B"))
        except (TypeError, ValueError):
            raise KeyCustodyUnavailable() from None

    @staticmethod
    def _clear_mutable(value: object) -> None:
        if isinstance(value, bytearray):
            clear_bytearray(value)
            return
        if isinstance(value, memoryview) and not value.readonly:
            try:
                octets = value.cast("B")
                octets[:] = b"\x00" * len(octets)
            except (TypeError, ValueError):
                pass

    def wrap_key(
        self,
        plaintext: bytes | bytearray | memoryview,
        *,
        aad: bytes,
    ) -> WrappedKeyBlob:
        associated_data = self._validated_aad(aad)
        copied = self._copy_plaintext(plaintext)
        try:
            response = self._response_mapping(
                self._client.encrypt(
                    KeyId=self._key_id,
                    Plaintext=copied,
                    EncryptionContext=self._encryption_context(associated_data),
                    EncryptionAlgorithm=AWS_KMS_ALGORITHM,
                )
            )
            ciphertext = self._immutable_blob(response.get("CiphertextBlob"))
            response_key_id = _validate_text(
                response.get("KeyId"),
                maximum=MAX_KEY_ID_CHARS,
                message="Invalid AWS KMS response.",
            )
            if response.get("EncryptionAlgorithm") != AWS_KMS_ALGORITHM:
                raise KeyCustodyUnavailable()
            return WrappedKeyBlob(
                backend_id=self._backend_id,
                key_id=response_key_id,
                algorithm=AWS_KMS_ALGORITHM,
                ciphertext=ciphertext,
            )
        except KeyCustodyUnavailable:
            raise
        except Exception:
            # Provider exception text can contain infrastructure identifiers.
            raise KeyCustodyUnavailable() from None
        finally:
            clear_bytearray(copied)

    @contextmanager
    def unwrap_key(
        self,
        wrapped_key: WrappedKeyBlob,
        *,
        aad: bytes,
    ) -> Iterator[bytearray]:
        associated_data = self._validated_aad(aad)
        plaintext: bytearray | None = None
        raw_plaintext: object = None
        try:
            if (
                not isinstance(wrapped_key, WrappedKeyBlob)
                or wrapped_key.backend_id != self._backend_id
                or wrapped_key.algorithm != AWS_KMS_ALGORITHM
            ):
                raise KeyCustodyUnavailable()
            response = self._response_mapping(
                self._client.decrypt(
                    KeyId=wrapped_key.key_id,
                    CiphertextBlob=wrapped_key.ciphertext,
                    EncryptionContext=self._encryption_context(associated_data),
                    EncryptionAlgorithm=AWS_KMS_ALGORITHM,
                )
            )
            if (
                response.get("KeyId") != wrapped_key.key_id
                or response.get("EncryptionAlgorithm") != AWS_KMS_ALGORITHM
            ):
                raise KeyCustodyUnavailable()
            raw_plaintext = response.get("Plaintext")
            plaintext = self._copy_plaintext(raw_plaintext)  # type: ignore[arg-type]
            self._clear_mutable(raw_plaintext)
        except (ValidationError, KeyCustodyUnavailable):
            raise KeyCustodyUnavailable() from None
        except Exception:
            raise KeyCustodyUnavailable() from None
        assert plaintext is not None
        try:
            yield plaintext
        finally:
            clear_bytearray(plaintext)
            self._clear_mutable(raw_plaintext)
