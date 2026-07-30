"""Public AuthGraph errors.

The messages are intentionally generic where a more precise response could
become an account, vault, record, or session existence oracle.
"""


class AuthGraphError(Exception):
    """Base class for expected AuthGraph failures."""


class ValidationError(AuthGraphError):
    """Input is not valid for the requested operation."""


class ConflictError(AuthGraphError):
    """An opaque identifier already exists."""


class UnlockDenied(AuthGraphError):
    """The vault could not be unlocked."""

    def __init__(self) -> None:
        super().__init__("Vault unlock was denied.")


class SessionUnavailable(AuthGraphError):
    """A session is invalid, expired, revoked, or belongs to another principal."""

    def __init__(self) -> None:
        super().__init__("The secure session is unavailable.")


class AuthorizationDenied(AuthGraphError):
    """The authenticated application context may not perform an operation."""

    def __init__(self) -> None:
        super().__init__("The operation is not authorized.")


class RecordNotFound(AuthGraphError):
    """A record is absent or outside the caller's authorized vault."""

    def __init__(self) -> None:
        super().__init__("The requested record is unavailable.")


class IntegrityViolation(AuthGraphError):
    """Authenticated ciphertext or its security context was modified."""

    def __init__(self) -> None:
        super().__init__("Encrypted data failed its integrity check.")
