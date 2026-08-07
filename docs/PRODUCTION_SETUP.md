# Production setup

This is a deployment blueprint, not a production certification. AuthGraph has
not had an independent security review. Do not use real sensitive data until
your complete application has passed the review in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md).

## Trust boundary

```text
browser -> your authenticated backend -> AuthGraph -> Neo4j
                         |                 |
                         |                 +-> KMS/HSM + authorization state
                         +-> email/identity provider

your backend -> small, read-only GraphRAG result -> AI
```

Your backend, not the AI, must:

- authenticate the user and map the account to opaque principal and vault IDs;
- choose a server-configured unlock profile and protection scopes;
- hold the session capability and attach it to every AuthGraph call;
- receive passwords and OTPs through a dedicated TLS form, outside chat;
- send OTP email and enforce account-level abuse controls; and
- give the AI only a bounded, read-only retrieval tool.

Never give the model a Neo4j driver, arbitrary Cypher, a password, OTP, key,
vault ID, scope ID, or AuthGraph session token. Plaintext returned by a
retrieval tool is visible to the model provider.

## Neo4j

1. Use a TLS URI with certificate verification, normally `neo4j+s://`.
2. Use a schema-administration account only for `authgraph schema apply`.
3. Give the runtime account only the permissions required by AuthGraph's fixed
   queries. Do not expose it to browsers or the AI.
4. Run `authgraph schema verify` during deployment and fail startup if the
   expected schema is absent.
5. Configure Neo4j RBAC, private networking, encrypted backups, monitoring,
   and retention independently of AuthGraph.

Neo4j stores ciphertext for protected records, but it still exposes generic
labels, opaque identifiers, sizes, timestamps, topology, and access patterns.

## Key custody

For production-shaped custody, compose:

- `EnvelopeScopeKeyProvider`;
- a managed `KeyWrappingBackend`, such as `AwsKmsKeyWrappingBackend`; and
- a durable `KeySlotStore` with atomic compare-and-swap.

The AWS adapter accepts an already authenticated, regional, boto3-compatible
client. AuthGraph does not create credentials. Keep credentials and key policy
outside source control, restrict encrypt/decrypt permissions, and monitor KMS
use. Give every provider-key generation a distinct `backend_id`; do not depend
on a moving KMS alias as the only version identifier.

`SqliteKeySlotStore` is the included single-host reference. It stores wrapped
scope keys and provider-release tombstones, never plaintext scope keys. Those
tombstones do not disable direct passphrase unlock. A multi-host service must
supply a shared, strongly consistent `KeySlotStore` with the same atomic
compare-and-swap behavior.

`SecurityOperations.rewrap_provider_keys()` changes only the provider
KEK/generation wrapping a scope DEK. It does not rotate that scope DEK or
re-encrypt graph data. AuthGraph does not yet automate full scope-DEK rotation
and record re-encryption after a plaintext-key compromise.

Routine `MirroredKeyWrappingBackend.unwrap_key()` is primary-only; it never
falls back to the recovery copy. Recovery uses a separate API after an exact,
single-use recovery grant is consumed, and the destination must be a different
provider generation. Put the recovery backend in a separate security domain
and deny the routine application identity permission to use it.

## Authorization state

| State | In-memory/test implementation | Optional durable reference | Deployment boundary |
|---|---|---|---|
| OTP challenges/evidence | `InMemoryOneTimeCodeBroker` | `DurableOneTimeCodeBroker` | SQLite: processes on one host |
| Scope grants | `ScopeGrantPolicy` | `DurableScopeGrantPolicy` | SQLite: processes on one host |
| Scoped sessions, lifecycle, guards, and leases | in-memory brokers | `DurableScopedSessionBroker` | SQLite: processes sharing one local file |
| Wrapped key slots/revocation | `InMemoryKeySlotStore` | `SqliteKeySlotStore` | SQLite: processes on one host |
| Security audit | `InMemoryAuditSink` | `JsonLinesAuditSink` | portable single-process local reference |

The SQLite implementations use local transactions and owner-only files. They
survive a process restart and coordinate local worker processes that share the
same file and secret. They do not provide multi-host consensus, global fencing,
or a distributed availability guarantee. Putting the files on a network share
does not turn them into supported multi-host backends.

`JsonLinesAuditSink` is not a SQLite store. Treat it as a single-process
portable reference: its local hash chain and file locks do not make the file
WORM, remotely replicated, independently retained, or a distributed audit log.
Management operations write a required pending intent before mutation and a
linked terminal result before restoring vault access.

Durable guards are expiry-bound, heartbeat-renewed, and generation-fenced. A
worker that loses its guard must fail before continuing a protected transition.
Expiry permits recovery from a dead worker; it is not permission for the stale
worker to resume. Durable key leases use separate expiry-bound rows so a purge
can reclaim state left by a crashed worker.

For multiple application hosts, replace every row above with shared services
that preserve atomic issue/consume, expiry, revocation, fencing, bounded
capacity, and fail-closed behavior. Use synchronized clocks and test host loss,
retry, split-brain, and restore behavior.

## Secrets and files

Load these as separate, random values from a secret manager:

- OTP verifier HMAC key;
- durable grant HMAC key;
- durable session-token HMAC key;
- audit signing/reference key; and
- provider credentials or wrapping-key configuration.

Do not derive them from a user password or reuse one key for several purposes.
Workers sharing one SQLite database must use the same corresponding secret.
On POSIX, the included durable stores reject database files that are symlinks,
not owned by the process user, or accessible by group/other users.
The JSONL audit file and its parent directory must also be owner-controlled.
These local permission checks do not replace independent append-only/WORM audit
storage.

## Deployment gate

Before real data:

- configure the email/identity adapter described in
  [OTP_EMAIL_ADAPTER.md](OTP_EMAIL_ADAPTER.md);
- implement and rehearse [OPERATIONS.md](OPERATIONS.md);
- map errors using [ERRORS.md](ERRORS.md), without parsing messages;
- run unit tests and the live Neo4j suite against the exact supported version;
- test backup/restore, revocation, provider outage, recovery, guard loss, and
  worker death;
- alert on any `REVISION_PENDING`, unexpected `BLOCKED`, lost guard, or
  unmatched pending audit operation;
- rehearse password and management reconciliation using only trusted
  authoritative revisions and exact lifecycle generations;
- choose guard and lease TTLs from bounded operation durations and test their
  expiry behavior; and
- obtain an independent review of the exact release and deployment.

Startup should fail closed if schema verification, KMS access, required audit
commit, authorization-state access, or secret loading fails. Monitor capacity,
expiry cleanup, denied attempts, revocations, KMS errors, audit failures, and
Neo4j connectivity. No independent review of AuthGraph has occurred yet.
