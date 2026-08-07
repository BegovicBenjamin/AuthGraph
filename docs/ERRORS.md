# Public errors

Catch error classes, not message text. Security-sensitive messages are
intentionally generic so they do not reveal whether an account, vault, record,
scope, challenge, or session exists.

AuthGraph is currently pre-1.0. The exported class names below are the public
error surface for this release, but compatibility can still change in a future
minor release. Pin and test the version you deploy.

## Runtime families

All of these inherit from `AuthGraphError`:

| Error | Meaning | Normal handling |
|---|---|---|
| `ValidationError` | Invalid API input or configuration value | Reject; do not retry unchanged |
| `ConflictError` | Identifier/create conflict | Return conflict or reconcile state |
| `UnlockDenied` | Password/vault unlock denied for a hidden reason | Generic denial; never reveal which check failed |
| `SessionUnavailable` | Session is invalid, expired, revoked, revision-mismatched, the vault is not `ACTIVE`, or its lifecycle guard was lost | Return a generic denial; trusted operations must inspect lifecycle state before reconciliation |
| `AuthorizationDenied` | Authenticated context lacks authority | Generic denial; do not retry unchanged |
| `RecordNotFound` | Record is absent or outside the authorized vault | Generic unavailable/not-found response |
| `IntegrityViolation` | Ciphertext or authenticated context was modified | Fail closed, alert, and investigate |
| `OneTimeCodeError` | Base OTP failure | Usually catch a more specific subtype |
| `OneTimeCodeDenied` | OTP verification denied for a hidden reason | Generic denial; never distinguish wrong/expired/unknown |
| `OneTimeCodeUnavailable` | OTP broker cannot accept new work | Fail closed; retry only under a bounded policy |
| `ScopeGrantDenied` | Evidence/grant/key release did not authorize scopes | Generic denial; start a new authorization flow |
| `KeyCustodyError` | Base custody failure | Usually catch a more specific subtype |
| `KeyCustodyConflict` | Key slot changed or was revoked concurrently | Re-read state before a bounded retry |
| `KeyCustodyUnavailable` | KMS/HSM or slot state is unavailable/invalid | Fail closed; retry only if the operation is safe |
| `AuditUnavailable` | A required intent or outcome record did not commit | Stop; if mutation may have started, keep the vault blocked and reconcile authoritative state |

`IntegrityViolation` is not a normal bad-request response. Do not return
ciphertext, partial plaintext, or detailed failure data. Preserve a correlation
ID and security evidence without logging the protected value.

## Schema errors

`Neo4jSchemaError` and its exported subclasses are deployment errors, not
normal request errors:

- `SchemaApplyError`
- `SchemaVerificationError`
- `SchemaMigrationError`

Stop deployment/startup until the exact schema is verified. The schema CLI
uses exit code `0` for success, `2` for invalid configuration or schema
verification failure, and `1` for apply, connectivity, driver, interruption,
or other runtime failure.

## HTTP mapping

AuthGraph does not include an HTTP layer. A common application mapping is:

- invalid input: `400`;
- expired/invalid application session: `401`;
- generic unlock/authorization denial: `403`;
- hidden record: `404`;
- state conflict: `409`; and
- required dependency unavailable or integrity failure: generic `5xx`.

Use the same body and comparable timing for security-equivalent denials. Do
not include exception text, provider response text, identifiers, or stack
traces in client responses. Your product may deliberately collapse several
statuses to reduce account and record enumeration.

## Retry rule

Retry only an operation documented as idempotent, or one carrying an
idempotency key, and only after re-reading authoritative state. A failed
pre-mutation audit intent means the protected mutation did not begin. After an
intent commits, a timeout, crash, or terminal-audit failure may leave state
changed and the operation pending or failed. Never blindly replay management
work. Verify the audit report, lifecycle generation, Neo4j revision, and
provider slots, then follow the reconciliation runbook. These stores are not
one distributed transaction.

AuthGraph does not normalize every Neo4j driver exception. Repository and
connectivity calls may propagate `neo4j` exceptions. Classify them with the
driver's documented retry rules, keep retries bounded, and never log query
parameters containing ciphertext or trusted identifiers.

Configuration/programming mistakes can also raise `TypeError` or `ValueError`.
Treat those as deployment defects, not user-facing authorization outcomes.

## Minimal catch boundary

```python
try:
    result = protected_operation()
except IntegrityViolation:
    alert_and_fail_closed()
except (UnlockDenied, SessionUnavailable, AuthorizationDenied, RecordNotFound):
    return generic_denial()
except AuthGraphError:
    return generic_service_failure()
```

Keep detailed diagnostics server-side and redacted. Do not use one broad catch
to automatically retry writes, key operations, or evidence consumption.
