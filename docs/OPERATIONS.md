# Operations, revocation, rotation, and recovery

These runbooks describe the included APIs. They do not make the library a
managed service. Assign owners, alerts, approval rules, and recovery targets
for your deployment before using real data.

## Inventory and health

Maintain an inventory of:

- deployed AuthGraph version and schema version;
- Neo4j database, runtime identity, backup set, and restore point;
- each wrapping `backend_id`, provider key ID, region/account, and status;
- key-slot, OTP, grant, and session state stores;
- secret-manager entries and their rotation owners; and
- audit sink, retention, export, and last verified hash chain.

Monitor authorization-store availability/capacity, KMS latency and denials,
OTP issue/deny rates, session expiry/revocation, Neo4j failures, integrity
violations, and required audit failures. A failed required dependency must
stop new unlocks and protected operations.

## Logout and access revocation

- Normal logout: call the session broker's `close(context)`.
- Revoke every session for a vault: call `revoke_vault(principal_id,
  vault_id)`.
- Remove future provider-based release of selected scope keys: use
  `SecurityOperations.revoke_scope_access()` with the trusted current envelope
  revision.

`revoke_scope_access()` first commits an audit intent, enters `BLOCKED` for the
trusted envelope revision, and revokes vault sessions before it atomically
writes key-slot tombstones. Provider unlock uses the same per-vault fence, so it
cannot mint a later session after blocking begins. Tombstones block later
cooperative release and silent re-enrollment.

This is provider-slot revocation, not global destruction of the scope key. The
separate passphrase-unlock path reads the scope-key envelope from Neo4j and is
unaffected unless the host disables that path. A product that must remove all
future access must also revoke the relevant application identity/credential and
may need scope-DEK rotation plus record re-encryption.

On success, the operation writes its linked terminal audit event while the
vault is still blocked, then restores `ACTIVE` for the exact blocked generation.
An interruption leaves the vault `BLOCKED`; do not reopen it or blindly retry.

Revocation cannot erase a key already copied outside AuthGraph. An operation
that already obtained a key lease may finish, and a key copied outside the
library may be used later. Rotate and re-encrypt the data key if it may have
escaped. A tombstoned provider slot has no automatic reactivation workflow.

## Crash reconciliation

Every vault has one lifecycle state:

- `ACTIVE(current_revision)` admits opens and leases only at that exact
  revision.
- `REVISION_PENDING(current_revision, next_revision)` denies access after a
  password-change intent and before its graph result is reconciled.
- `BLOCKED(current_revision, generation)` denies access during or after an
  interrupted management operation.

After a crash or ambiguous error:

1. Keep the vault unavailable.
2. Run `verify_json_lines_audit_report()` and record unmatched pending
   operation references.
3. For `REVISION_PENDING`, call the trusted service's
   `reconcile_passphrase_change(principal_id, vault_id)`. It reads Neo4j's
   authoritative envelope revision and accepts only the recorded current or
   next revision.
4. For `BLOCKED`, inspect session state, provider slots, Neo4j revision, and the
   linked audit intent.
5. Clear it only with `reconcile_management_transition()` using the exact
   authoritative revision and blocked generation after the result is proven.
   Otherwise leave it blocked and escalate.

Lifecycle inspection and reconciliation are trusted backend/operator actions.
Never expose them as chatbot or end-user tools.

## Provider-key rewrap

`SecurityOperations.rewrap_provider_keys()` takes the trusted current envelope
revision and changes the KMS/HSM key generation that wraps selected scope keys.
It does not change the scope data-encryption keys or re-encrypt graph records.
It uses the same `BLOCKED` lifecycle and audit ordering as revocation.

1. Configure both old and destination backends. Give the destination an exact,
   new `backend_id`.
2. Rewrap in bounded batches. Repeating a completed batch is an idempotent
   no-op.
3. Verify that every intended active slot names the destination generation.
4. Keep the old backend available until backups, rollback windows, and
   recovery copies have been handled.
5. Disable or schedule deletion of the old provider key under a separately
   approved provider runbook.

Do not remove an old backend merely because a KMS alias now points elsewhere;
existing rows record the backend generation used to wrap them.

## Scope-key compromise

Provider-key rewrap is not enough if a plaintext scope key may have leaked.
That incident requires a new scope key, a higher key version, re-encryption of
every affected node and relationship, verification, and retirement of the old
key. AuthGraph does not yet provide this complete online data-key rotation and
migration workflow. Keep affected access revoked until an application-owned,
reviewed migration completes.

## Recovery

`MirroredKeyWrappingBackend` can store independent primary and recovery wraps
of each scope key. Keep the recovery backend in another account or security
domain, require strong human approval, deny routine application access, and
alert on every use.

Routine `MirroredKeyWrappingBackend.unwrap_key()` uses the primary backend only
and never falls back to the recovery copy. Recovery is a separate explicit
path. KMS policy must also prevent the routine application identity from using
the low-level recovery unwrap.

`SecurityOperations.recover_provider_keys()` accepts only an exact, single-use
grant with the configured recovery profile. Principal, vault, and scope IDs
come from the consumed grant, never from chatbot arguments. It revokes vault
sessions and rewraps the selected keys to a configured destination backend.

Recovery procedure:

1. Declare the incident and freeze conflicting key operations.
2. Obtain the recovery grant through a separately protected operator flow.
3. Recover into a fresh primary provider-key generation.
4. Verify slot generations and a bounded decrypt/read test.
5. Revoke the grant/session, export the audit evidence, and rotate any
   credential used during recovery.
6. Investigate why primary access failed before returning to service.

Test recovery regularly with synthetic vaults. A recovery design first tested
during an outage is not a recovery design.

## Backup and restore

Neo4j ciphertext is useless without the matching active key slots. Back up
both, plus schema/configuration needed to interpret them. Keep KMS keys and
recovery wraps available for the full backup retention period.

The stores are separate and have no cross-store backup transaction. Define a
quiesced or versioned procedure that proves graph rows and key slots correspond
to the same logical point. Do not copy a live SQLite database file while
ignoring its WAL; use a supported transactional SQLite backup or stop writers.

### Upgrading an older durable session database

The migration from legacy scalar lease counters to expiry-bound lease rows is
not compatible with old and new workers using the file at the same time:

1. Stop every old AuthGraph worker and wait for its operations to end.
2. Take a transactional SQLite backup, including WAL state, or back up while all
   writers are stopped.
3. Start one new worker. Opening `DurableScopedSessionBroker` applies and
   verifies the local migration.
4. Check startup, lifecycle state, and a synthetic unlock/read/logout flow.
5. Only then start the remaining new workers.

Do not perform a rolling mixed-version upgrade of this SQLite reference.

Treat OTP, grant, and session capabilities as disposable after disaster
recovery: invalidate them unless an independently reviewed procedure proves
they are current. Lifecycle state and revocation tombstones are not disposable.
Do not delete or roll them back, and do not restore an old key-slot database
over newer tombstones. The included single-host stores have no external
anti-rollback authority, so production must keep monotonic revocation/version
state outside a restorable snapshot.

Keep audit records in independently controlled append-only/WORM storage.
`JsonLinesAuditSink` is a local, mode-0600, hash-chained, portable
reference. It is not WORM storage or a multi-host audit service. Management
operations commit a required `PENDING` intent before their first mutation and
then append a linked `SUCCEEDED` or `FAILED` outcome. Regularly run
`verify_json_lines_audit_report()`, investigate unmatched pending references,
and anchor or export the latest hash outside the application host. Audit and
security state are not one distributed transaction.

## Incident minimum

For suspected disclosure or unauthorized access:

1. stop new unlocks and isolate affected workers;
2. revoke vault sessions and affected key slots;
3. preserve provider, AuthGraph, Neo4j, identity, and model-access evidence;
4. determine whether a session token, provider key, scope key, or returned
   plaintext was exposed;
5. rewrap provider keys or perform full scope-key rotation as appropriate;
6. verify state before reopening access; and
7. follow legal, privacy, customer-notification, and provider procedures for
   your jurisdiction and data class.
