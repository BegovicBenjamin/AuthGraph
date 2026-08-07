# OTP email adapter contract

AuthGraph creates and verifies one-time codes. It does not know an email
address and does not send email. The host application must provide this
adapter at the trusted backend boundary.

Any ignored/local demo that prints or displays an OTP is synthetic test UI
only. It is not an email adapter, a secure delivery channel, or evidence that
the deployment is ready for real accounts.

Email OTP is suitable only for a policy that accepts its assurance level. For
sensitive access, prefer an identity provider with phishing-resistant MFA or a
passkey.

## Host-owned contract

The following is an application contract, not an AuthGraph class:

```python
from typing import Protocol


class OtpEmailSender(Protocol):
    def send(
        self,
        *,
        destination_ref: str,
        code: memoryview,
        expires_at: float,
    ) -> None:
        """Return only after the provider accepted the message."""
```

`destination_ref` must resolve to a previously verified email address in the
server's identity/account store. Never accept the destination, principal,
vault, profile, or allowed scopes from chat text or a model tool call. The
email address should not be copied into AuthGraph identifiers or audit events.

The adapter must:

- use an authenticated email provider over TLS;
- render the code as data, not as an HTML/template instruction;
- avoid logging message bodies, addresses, codes, challenge IDs, or provider
  exceptions that contain them;
- apply provider timeouts and return a generic failure; and
- avoid putting plaintext codes in a normal persistent job queue.

## Ten-minute flow

Configure `DurableOneTimeCodeBroker(..., ttl_seconds=600)` for a ten-minute
challenge. Ten minutes is a maximum lifetime, not a promise that a code will
remain usable: successful verification, too many attempts, resend, policy
revision, or explicit account action may invalidate it sooner.

The trusted backend flow is:

1. Authenticate the application session and resolve an opaque `principal_id`,
   `vault_id`, verified `destination_ref`, and server-owned `profile_id`.
2. Read the current vault authorization epoch with
   `ScopedAuthGraphService.get_authorization_epoch()`.
3. Generate a random, opaque `client_binding` for this browser authentication
   transaction.
4. Issue the challenge with the vault as `authorization_context`.
5. Send `memoryview(issued.code)` through the adapter, then always call
   `issued.clear_code()` in `finally`.
6. Keep `challenge_id`, the binding, and account mapping in trusted server
   state. The AI must not receive them.
7. Accept the submitted code in a dedicated TLS form and call `verify()` with
   the same principal, profile, and client binding.
8. Immediately exchange the evidence for a fixed-scope grant, then use
   `ScopedAuthGraphService.unlock_with_provider()` to open the session.

The security-relevant calls look like this; account lookup, HTTP protection,
delivery, auditing, and generic user responses remain application code:

```python
issued = otp.issue(
    principal_id,
    profile_id,
    client_binding,
    authorization_context=vault_id,
    authorization_epoch=epoch,
)
try:
    email_sender.send(
        destination_ref=destination_ref,
        code=memoryview(issued.code),
        expires_at=issued.expires_at,
    )
finally:
    issued.clear_code()

evidence = otp.verify(
    challenge_id,
    submitted_code,
    principal_id=principal_id,
    profile_id=profile_id,
    client_binding=client_binding,
)
grant = grants.authorize_one_time_code(
    evidence,
    vault_id=vault_id,
    evidence_consumer=otp,
)
context = scoped_service.unlock_with_provider(grant, grants, key_provider)
```

The code authorizes one fixed scope grant. It is never an encryption key and
is never sent to Neo4j or the AI.

## Resend and expiry

Expiry does not automatically send another email. A user requests resend;
the backend repeats `issue()` with the same binding. Issuing a replacement
invalidates the previous challenge/evidence for that binding. The durable
broker also enforces a configurable issuance window and maximum issue count.
Apply additional per-account, per-destination, per-IP, and provider abuse
limits outside AuthGraph.

The current broker has no cancellation call. If delivery fails, do not expose
the challenge ID or report whether the account exists. Let the undisclosed
challenge expire; a later issue for the same binding replaces it. Return the
same generic user-facing response for unknown accounts, delivery failure, bad
codes, expired codes, and denied policy where practical.

## Durable-state boundary

`DurableOneTimeCodeBroker` stores HMAC-keyed indexes and verifiers, not the
plaintext code or bearer evidence token. It is restart-safe and atomic across
processes sharing one local SQLite file and the same secret key. It is not a
multi-host OTP service. A multi-host application must implement equivalent
atomic issue, replace, verify, attempt decrement, expiry, and single-use
evidence consumption in a shared transactional service.
