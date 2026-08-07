"""Provider-neutral, short-lived one-time-code challenges.

This module verifies possession of a code delivered by a trusted host
application.  It deliberately does not know an email address, send messages,
unwrap a key, or use a code as cryptographic key material.  A successful
verification produces identity-bound evidence for a separate authorization
and key-release policy.

The broker is intentionally in-memory.  Restarting or closing it invalidates
every outstanding challenge.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
import threading
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from .errors import AuthGraphError, ValidationError

DEFAULT_CODE_DIGITS = 6
MIN_CODE_DIGITS = 6
MAX_CODE_DIGITS = 10
DEFAULT_TTL_SECONDS = 300
MAX_TTL_SECONDS = 15 * 60
DEFAULT_MAX_ATTEMPTS = 5
MAX_ATTEMPTS = 10
DEFAULT_MAX_ACTIVE_CHALLENGES = 100_000
MAX_ACTIVE_CHALLENGES = 1_000_000
DEFAULT_SWEEP_INTERVAL_SECONDS = 1.0
MIN_SWEEP_INTERVAL_SECONDS = 0.01
MAX_SWEEP_INTERVAL_SECONDS = 60.0
MAX_OPAQUE_ID_CHARS = 256
VERIFIER_KEY_BYTES = 32
CHALLENGE_TOKEN_LENGTH = 43
CHALLENGE_TOKEN_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)


class OneTimeCodeError(AuthGraphError):
    """Base class for expected one-time-code failures."""


class OneTimeCodeDenied(OneTimeCodeError):
    """A challenge could not be verified, for an intentionally generic reason."""

    def __init__(self) -> None:
        super().__init__("The one-time-code challenge could not be verified.")


class OneTimeCodeUnavailable(OneTimeCodeError):
    """The in-memory challenge service cannot accept new work."""

    def __init__(self) -> None:
        super().__init__("The one-time-code service is unavailable.")


@dataclass(slots=True)
class IssuedOneTimeCode:
    """A newly issued code that the trusted caller must deliver and then clear.

    The broker does not retain ``code``.  The caller owns this mutable buffer
    and should call :meth:`clear_code` after handing it to its delivery adapter.
    """

    challenge_id: str
    code: bytearray = field(repr=False)
    expires_at: float

    def clear_code(self) -> None:
        """Best-effort overwrite of the caller-owned delivery buffer."""

        self.code[:] = b"\x00" * len(self.code)


@dataclass(frozen=True, slots=True)
class OneTimeCodeEvidence:
    """Evidence of one successful, bound, single-use code verification.

    This value is not a key or a bearer capability.  It is intended to be
    consumed immediately by trusted in-process authorization code.  The
    client binding and consumed challenge identifier are hidden from ``repr``.
    """

    principal_id: str
    profile_id: str
    client_binding: str = field(repr=False)
    authorization_context: str | None = field(repr=False)
    challenge_id: str = field(repr=False)
    authorization_epoch: int
    verified_at: float
    challenge_expires_at: float


@runtime_checkable
class OneTimeCodeEvidenceConsumer(Protocol):
    """Trusted boundary that atomically consumes broker-issued evidence."""

    def consume_evidence(
        self,
        evidence: OneTimeCodeEvidence,
    ) -> OneTimeCodeEvidence: ...


@dataclass(slots=True)
class _ChallengeRecord:
    binding_digest: bytes = field(repr=False)
    verifier: bytes = field(repr=False)
    authorization_context: str | None = field(repr=False)
    authorization_epoch: int
    expires_at: float
    attempts_remaining: int


@dataclass(frozen=True, slots=True)
class _EvidenceSnapshot:
    """Broker-owned evidence fields that are never exposed to the caller."""

    principal_id: str
    profile_id: str
    client_binding: str
    authorization_context: str | None
    challenge_id: str
    authorization_epoch: int
    verified_at: float
    challenge_expires_at: float

    def exposed_copy(self) -> OneTimeCodeEvidence:
        return OneTimeCodeEvidence(
            principal_id=self.principal_id,
            profile_id=self.profile_id,
            client_binding=self.client_binding,
            authorization_context=self.authorization_context,
            challenge_id=self.challenge_id,
            authorization_epoch=self.authorization_epoch,
            verified_at=self.verified_at,
            challenge_expires_at=self.challenge_expires_at,
        )

    def matches(self, evidence: OneTimeCodeEvidence) -> bool:
        """Compare both values and concrete field types to detect mutation."""

        expected = (
            self.principal_id,
            self.profile_id,
            self.client_binding,
            self.authorization_context,
            self.challenge_id,
            self.authorization_epoch,
            self.verified_at,
            self.challenge_expires_at,
        )
        actual = (
            evidence.principal_id,
            evidence.profile_id,
            evidence.client_binding,
            evidence.authorization_context,
            evidence.challenge_id,
            evidence.authorization_epoch,
            evidence.verified_at,
            evidence.challenge_expires_at,
        )
        return all(
            type(candidate) is type(original) and candidate == original
            for candidate, original in zip(actual, expected, strict=True)
        )


@dataclass(frozen=True, slots=True)
class _PendingEvidence:
    """One exposed capability plus its independent broker-owned snapshot."""

    exposed: OneTimeCodeEvidence
    snapshot: _EvidenceSnapshot
    binding_digest: bytes = field(repr=False)


class InMemoryOneTimeCodeBroker:
    """Issues and verifies delivery-provider-neutral one-time codes.

    Challenges are bound to exact opaque ``principal_id``, ``profile_id``,
    optional ``authorization_context``, and ``client_binding`` values. Calling
    :meth:`issue` again for the same binding invalidates an earlier outstanding
    challenge or pending verified evidence. Every failed verification of a
    known challenge consumes an attempt, including a wrong binding.

    The host remains responsible for authenticating the surrounding
    application session, choosing a pre-verified delivery destination,
    delivering the returned code, rate-limiting issuance, and consuming
    :class:`OneTimeCodeEvidence` in its authorization policy.
    """

    def __init__(
        self,
        *,
        code_digits: int = DEFAULT_CODE_DIGITS,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        max_active_challenges: int = DEFAULT_MAX_ACTIVE_CHALLENGES,
        sweep_interval_seconds: float | None = DEFAULT_SWEEP_INTERVAL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            type(code_digits) is not int
            or code_digits < MIN_CODE_DIGITS
            or code_digits > MAX_CODE_DIGITS
            or type(ttl_seconds) is not int
            or ttl_seconds <= 0
            or ttl_seconds > MAX_TTL_SECONDS
            or type(max_attempts) is not int
            or max_attempts <= 0
            or max_attempts > MAX_ATTEMPTS
            or type(max_active_challenges) is not int
            or max_active_challenges <= 0
            or max_active_challenges > MAX_ACTIVE_CHALLENGES
            or not callable(clock)
        ):
            raise ValidationError("Invalid one-time-code broker configuration.")
        if (
            sweep_interval_seconds is not None
            and (
                type(sweep_interval_seconds) not in (int, float)
                or not math.isfinite(sweep_interval_seconds)
                or sweep_interval_seconds < MIN_SWEEP_INTERVAL_SECONDS
                or sweep_interval_seconds > MAX_SWEEP_INTERVAL_SECONDS
            )
        ):
            raise ValidationError("Invalid one-time-code sweep interval.")

        self._code_digits = code_digits
        self._ttl_seconds = ttl_seconds
        self._max_attempts = max_attempts
        self._max_active_challenges = max_active_challenges
        self._clock = clock
        self._verifier_key = bytearray(secrets.token_bytes(VERIFIER_KEY_BYTES))
        self._records: dict[bytes, _ChallengeRecord] = {}
        self._verified_evidence: dict[bytes, _PendingEvidence] = {}
        self._evidence_by_object_id: dict[int, bytes] = {}
        self._active_by_binding: dict[bytes, bytes] = {}
        self._verified_by_binding: dict[bytes, bytes] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._sweeper_failed = False
        self._sweep_interval = (
            None
            if sweep_interval_seconds is None
            else float(sweep_interval_seconds)
        )
        self._sweeper_stop = threading.Event()
        self._sweeper: threading.Thread | None = None
        if self._sweep_interval is not None:
            self._sweeper = threading.Thread(
                target=self._sweep_worker,
                name="authgraph-one-time-code-sweeper",
                daemon=True,
            )
            self._sweeper.start()

    def __enter__(self) -> InMemoryOneTimeCodeBroker:
        with self._lock:
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

    @staticmethod
    def _validate_opaque_id(value: str, description: str) -> None:
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

    @staticmethod
    def _valid_challenge_id(challenge_id: object) -> bool:
        return (
            type(challenge_id) is str
            and len(challenge_id) == CHALLENGE_TOKEN_LENGTH
            and challenge_id.isascii()
            and all(char in CHALLENGE_TOKEN_ALPHABET for char in challenge_id)
        )

    def _keyed_digest(self, domain: bytes, *parts: object) -> bytes:
        digest = hmac.new(
            self._verifier_key,
            digestmod=hashlib.sha256,
        )
        digest.update(b"authgraph-one-time-code-v1")
        digest.update(len(domain).to_bytes(4, "big"))
        digest.update(domain)
        for part in parts:
            if isinstance(part, str):
                encoded: object = part.encode("utf-8")
            else:
                encoded = part
            if not isinstance(encoded, (bytes, bytearray, memoryview)):
                raise TypeError("One-time-code digest parts must be bytes-like.")
            size = encoded.nbytes if isinstance(encoded, memoryview) else len(encoded)
            digest.update(size.to_bytes(4, "big"))
            digest.update(encoded)
        return digest.digest()

    def _binding_digest(
        self,
        principal_id: str,
        profile_id: str,
        client_binding: str,
        authorization_context: str | None,
    ) -> bytes:
        return self._keyed_digest(
            b"binding",
            principal_id,
            profile_id,
            client_binding,
            b"unbound" if authorization_context is None else b"bound",
            b"" if authorization_context is None else authorization_context,
        )

    def _challenge_digest(self, challenge_id: str) -> bytes:
        return self._keyed_digest(b"challenge-index", challenge_id)

    def _verifier(
        self,
        challenge_id: str,
        binding_digest: bytes,
        authorization_epoch: int,
        code: bytes | bytearray | memoryview,
    ) -> bytes:
        return self._keyed_digest(
            b"code-verifier",
            challenge_id,
            binding_digest,
            authorization_epoch.to_bytes(8, "big"),
            code,
        )

    @staticmethod
    def _clock_value(clock: Callable[[], float]) -> float:
        try:
            now = clock()
        except Exception:
            raise OneTimeCodeUnavailable() from None
        if type(now) not in (int, float) or not math.isfinite(now):
            raise OneTimeCodeUnavailable()
        return float(now)

    def issue(
        self,
        principal_id: str,
        profile_id: str,
        client_binding: str,
        *,
        authorization_context: str | None = None,
        authorization_epoch: int = 1,
    ) -> IssuedOneTimeCode:
        """Issue a code bound to an opaque context and authorization epoch."""

        self._validate_opaque_id(
            principal_id,
            "principal_id must be a non-PII opaque identifier.",
        )
        self._validate_opaque_id(
            profile_id,
            "profile_id must be an opaque configured profile identifier.",
        )
        self._validate_opaque_id(
            client_binding,
            "client_binding must be an opaque application-session identifier.",
        )
        if authorization_context is not None:
            self._validate_opaque_id(
                authorization_context,
                "authorization_context must be an opaque security identifier.",
            )
        if (
            type(authorization_epoch) is not int
            or authorization_epoch <= 0
            or authorization_epoch > (2**63 - 1)
        ):
            raise ValidationError("Invalid authorization epoch.")
        value = secrets.randbelow(10**self._code_digits)
        code = bytearray(
            f"{value:0{self._code_digits}d}".encode("ascii")
        )
        try:
            now = self._clock_value(self._clock)
            expires_at = now + self._ttl_seconds
            if not math.isfinite(expires_at):
                raise OneTimeCodeUnavailable()
            with self._lock:
                if self._closed:
                    raise OneTimeCodeUnavailable()
                self._remove_expired_locked(now)
                binding_digest = self._binding_digest(
                    principal_id,
                    profile_id,
                    client_binding,
                    authorization_context,
                )
                existing_digest = self._active_by_binding.get(binding_digest)
                existing_evidence_digest = self._verified_by_binding.get(
                    binding_digest
                )
                if (
                    existing_digest is None
                    and existing_evidence_digest is None
                    and (
                        len(self._records) + len(self._verified_evidence)
                        >= self._max_active_challenges
                    )
                ):
                    raise OneTimeCodeUnavailable()

                challenge_id: str | None = None
                challenge_digest: bytes | None = None
                for _ in range(3):
                    candidate_id = secrets.token_urlsafe(32)
                    candidate_digest = self._challenge_digest(candidate_id)
                    if (
                        candidate_digest not in self._records
                        and candidate_digest not in self._verified_evidence
                    ):
                        challenge_id = candidate_id
                        challenge_digest = candidate_digest
                        break
                if challenge_id is None or challenge_digest is None:
                    raise OneTimeCodeUnavailable()

                if existing_digest is not None:
                    self._remove_record_locked(existing_digest)
                if existing_evidence_digest is not None:
                    self._remove_evidence_locked(
                        existing_evidence_digest
                    )
                self._records[challenge_digest] = _ChallengeRecord(
                    binding_digest=binding_digest,
                    verifier=self._verifier(
                        challenge_id,
                        binding_digest,
                        authorization_epoch,
                        code,
                    ),
                    authorization_context=authorization_context,
                    authorization_epoch=authorization_epoch,
                    expires_at=expires_at,
                    attempts_remaining=self._max_attempts,
                )
                self._active_by_binding[binding_digest] = challenge_digest
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
    ) -> OneTimeCodeEvidence:
        """Consume a valid challenge or raise the same error for every failure."""

        try:
            valid_binding = True
            try:
                self._validate_opaque_id(
                    principal_id,
                    "Invalid principal binding.",
                )
                self._validate_opaque_id(profile_id, "Invalid profile binding.")
                self._validate_opaque_id(
                    client_binding,
                    "Invalid client binding.",
                )
            except ValidationError:
                valid_binding = False

            valid_challenge = self._valid_challenge_id(challenge_id)
            normalized_code = self._normalize_code(code)
            valid_code = normalized_code is not None
            challenge_part = challenge_id if valid_challenge else "invalid"
            code_part: bytes | bytearray | memoryview = (
                normalized_code if normalized_code is not None else b"invalid"
            )
            principal_part = principal_id if valid_binding else "invalid"
            profile_part = profile_id if valid_binding else "invalid"
            client_part = client_binding if valid_binding else "invalid"
            now = self._clock_value(self._clock)

            with self._lock:
                if self._closed:
                    raise OneTimeCodeDenied()
                self._remove_expired_locked(now)
                challenge_digest = self._challenge_digest(challenge_part)
                record = self._records.get(challenge_digest)
                binding_digest = self._binding_digest(
                    principal_part,
                    profile_part,
                    client_part,
                    (
                        record.authorization_context
                        if record is not None
                        else None
                    ),
                )
                candidate_verifier = self._verifier(
                    challenge_part,
                    binding_digest,
                    (
                        record.authorization_epoch
                        if record is not None
                        else 1
                    ),
                    code_part,
                )
                expected_verifier = (
                    record.verifier if record is not None else b"\x00" * 32
                )
                binding_matches = (
                    record is not None
                    and hmac.compare_digest(
                        binding_digest,
                        record.binding_digest,
                    )
                )
                verifier_matches = hmac.compare_digest(
                    candidate_verifier,
                    expected_verifier,
                )
                active_matches = (
                    record is not None
                    and self._active_by_binding.get(record.binding_digest)
                    == challenge_digest
                )
                accepted = (
                    valid_binding
                    and valid_challenge
                    and valid_code
                    and record is not None
                    and binding_matches
                    and verifier_matches
                    and active_matches
                )
                if accepted:
                    assert record is not None
                    expires_at = record.expires_at
                    self._remove_record_locked(challenge_digest)
                    snapshot = _EvidenceSnapshot(
                        principal_id=principal_id,
                        profile_id=profile_id,
                        client_binding=client_binding,
                        authorization_context=record.authorization_context,
                        challenge_id=challenge_id,
                        authorization_epoch=record.authorization_epoch,
                        verified_at=now,
                        challenge_expires_at=expires_at,
                    )
                    evidence = snapshot.exposed_copy()
                    self._verified_evidence[challenge_digest] = _PendingEvidence(
                        exposed=evidence,
                        snapshot=snapshot,
                        binding_digest=record.binding_digest,
                    )
                    self._evidence_by_object_id[id(evidence)] = challenge_digest
                    self._verified_by_binding[
                        record.binding_digest
                    ] = challenge_digest
                    return evidence
                if record is not None and active_matches:
                    record.attempts_remaining -= 1
                    if record.attempts_remaining <= 0:
                        self._remove_record_locked(challenge_digest)
        except OneTimeCodeDenied:
            raise
        except Exception:
            # Malformed input, clock failure, and internal availability all have
            # one external verification result.
            raise OneTimeCodeDenied() from None
        raise OneTimeCodeDenied()

    def consume_evidence(
        self,
        evidence: OneTimeCodeEvidence,
    ) -> OneTimeCodeEvidence:
        """Atomically consume the exact evidence object returned by ``verify``.

        Constructed copies, mutations, expired evidence, and replay all fail
        with the same generic result. A copy that names a real pending
        challenge also invalidates the original evidence. Success returns a
        new trusted copy built from the broker-owned field snapshot.
        """

        try:
            if not isinstance(evidence, OneTimeCodeEvidence):
                raise OneTimeCodeDenied()
            now = self._clock_value(self._clock)
            with self._lock:
                if self._closed:
                    raise OneTimeCodeDenied()
                self._remove_expired_locked(now)
                challenge_digest = self._evidence_by_object_id.get(id(evidence))
                pending = (
                    self._verified_evidence.get(challenge_digest)
                    if challenge_digest is not None
                    else None
                )
                if pending is None or pending.exposed is not evidence:
                    challenge_digest = None
                    if self._valid_challenge_id(evidence.challenge_id):
                        challenge_digest = self._challenge_digest(
                            evidence.challenge_id
                        )
                        pending = self._verified_evidence.get(
                            challenge_digest
                        )
                    else:
                        pending = None
                if pending is not None and challenge_digest is not None:
                    self._remove_evidence_locked(challenge_digest)
                if (
                    pending is None
                    or pending.exposed is not evidence
                    or not pending.snapshot.matches(evidence)
                    or pending.snapshot.challenge_expires_at <= now
                ):
                    raise OneTimeCodeDenied()
                return pending.snapshot.exposed_copy()
        except OneTimeCodeDenied:
            raise
        except Exception:
            raise OneTimeCodeDenied() from None

    def _normalize_code(
        self,
        code: object,
    ) -> bytes | memoryview | None:
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
            view = memoryview(code)
            if not view.contiguous:
                return None
            octets = view.cast("B")
        except (TypeError, ValueError):
            return None
        if len(octets) != self._code_digits or any(
            value < ord("0") or value > ord("9") for value in octets
        ):
            return None
        return octets

    def _remove_record_locked(self, challenge_digest: bytes) -> bool:
        record = self._records.pop(challenge_digest, None)
        if record is None:
            return False
        if (
            self._active_by_binding.get(record.binding_digest)
            == challenge_digest
        ):
            self._active_by_binding.pop(record.binding_digest, None)
        return True

    def _remove_evidence_locked(self, challenge_digest: bytes) -> bool:
        pending = self._verified_evidence.pop(challenge_digest, None)
        if pending is None:
            return False
        if (
            self._evidence_by_object_id.get(id(pending.exposed))
            == challenge_digest
        ):
            self._evidence_by_object_id.pop(id(pending.exposed), None)
        if (
            self._verified_by_binding.get(pending.binding_digest)
            == challenge_digest
        ):
            self._verified_by_binding.pop(pending.binding_digest, None)
        return True

    def _remove_expired_locked(self, now: float) -> int:
        removed = 0
        for challenge_digest, record in list(self._records.items()):
            if record.expires_at <= now:
                if self._remove_record_locked(challenge_digest):
                    removed += 1
        for challenge_digest, pending in list(
            self._verified_evidence.items()
        ):
            if pending.snapshot.challenge_expires_at <= now:
                if self._remove_evidence_locked(challenge_digest):
                    removed += 1
        return removed

    def purge_expired(self) -> int:
        """Remove expired challenges immediately."""

        with self._lock:
            if self._closed:
                return 0
        now = self._clock_value(self._clock)
        with self._lock:
            if self._closed:
                return 0
            return self._remove_expired_locked(now)

    def _sweep_worker(self) -> None:
        assert self._sweep_interval is not None
        while not self._sweeper_stop.wait(self._sweep_interval):
            try:
                self.purge_expired()
            except Exception:
                with self._lock:
                    self._sweeper_failed = True
                self.close()
                return

    def close(self) -> int:
        """Invalidate all challenges and best-effort clear the verifier key."""

        self._sweeper_stop.set()
        with self._lock:
            if self._closed:
                removed = 0
            else:
                self._closed = True
                removed = len(self._records) + len(self._verified_evidence)
                self._records.clear()
                self._verified_evidence.clear()
                self._evidence_by_object_id.clear()
                self._active_by_binding.clear()
                self._verified_by_binding.clear()
                self._verifier_key[:] = b"\x00" * len(self._verifier_key)
        if (
            self._sweeper is not None
            and self._sweeper is not threading.current_thread()
        ):
            self._sweeper.join()
        return removed

    @property
    def active_count(self) -> int:
        self.purge_expired()
        with self._lock:
            return len(self._records)

    @property
    def pending_evidence_count(self) -> int:
        self.purge_expired()
        with self._lock:
            return len(self._verified_evidence)

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    @property
    def sweeper_failed(self) -> bool:
        with self._lock:
            return self._sweeper_failed
