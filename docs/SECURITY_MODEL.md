# AuthGraph security model

## Status and intended use

AuthGraph currently demonstrates a cryptographic and authorization boundary
using synthetic records. It does not by itself make any product safe,
compliant, or suitable as an authoritative system of record. Architecture
alone cannot establish GDPR, HIPAA, PCI DSS, or other legal or industry
compliance.

## Security goals

1. A stolen Neo4j data store or backup does not reveal semantic entity types,
   relationship types, or properties for records classified `PRIVATE` without
   a vault secret. Records explicitly classified `PUBLIC` are intentionally
   plaintext at AuthGraph's application-encryption layer.
2. A principal can retrieve records only from the vault bound to that
   principal's secure session. A v2 session can decrypt only its explicitly
   granted protection scopes.
3. A passphrase, KEK, DEK, Neo4j credential, or session token never enters an
   LLM prompt, tool argument, graph property, application log, or audit event.
4. Unlocking one vault never globally decrypts Neo4j.
5. Modification or truncation of a present ciphertext, record swapping, or
   cross-vault movement fails authenticated decryption.
6. Expiry, logout, password change, and session revocation prevent the affected
   session from obtaining a new key lease inside the selected broker's
   coordination boundary. New opens and leases require `ACTIVE` at the exact
   envelope revision; interrupted changes remain fail-closed until trusted
   reconciliation. Session revocation alone does not disable a future valid
   unlock.
7. A v2 private relationship is visible only when its relationship scope and
   both endpoint scopes are granted.

## Non-goals and unavoidable leakage

Application encryption is not magic searchable encryption.

Neo4j can see:

- every semantic kind and property deliberately stored in the public layer;
- opaque principal, vault, scope, entity, and relationship identifiers;
- that entities belong to the same vault;
- the number of protection scopes and which protected records share an opaque
  scope through `AG_HAS_SCOPE` and `AG_PROTECTS` topology;
- generic connectivity, direction, graph size, and access patterns;
- ciphertext sizes and key/KDF version metadata; and
- database operational metadata.

Neo4j cannot use randomized ciphertext for meaningful full-text, range, or
vector similarity search. A future per-vault blind index could support a small
number of carefully selected exact matches, but it would leak equality.
Embeddings are sensitive derivatives and cannot remain conventionally
encrypted while also supporting ordinary Neo4j vector search.
The gateway can build a sealed `EphemeralVectorIndex` in trusted memory from
only its policy-allowlisted entity projection. It rejects raw indexes and
indexes bound to another gateway or context. Encrypted embedding
storage/loading and automatic session-lifetime cleanup are not implemented.

A compromised trusted broker can capture active DEKs and plaintext. Encryption
cannot protect data from the component that is currently authorized to decrypt
it. Production must minimize, isolate, patch, monitor, and egress-restrict that
trusted computing base.

The layered API's term `PUBLIC` does not mean anonymously writable and does not
replace database security. It means that anyone who can read the applicable
Neo4j records or backups can read those semantics without the owner's
passphrase. TLS, Neo4j RBAC, disk encryption, private networking, and backup
controls remain required.

AES-GCM authenticates a record that is present; it does not prove completeness
or freshness. An attacker able to delete rows can cause unavailable or partial
results. An attacker able to restore an entire older, internally consistent
Neo4j snapshot can replay an old envelope and records. The authenticated
envelope revision and compare-and-swap prevent normal concurrent lost updates,
but a revision stored in the same rollback domain cannot detect malicious
snapshot rollback. Strong anti-rollback protection needs a monotonic version or
transparency record in a trusted system outside Neo4j and its backups.

Managed runtimes such as Python cannot guarantee complete memory zeroization.
This prototype overwrites mutable buffers on a best-effort basis and never
serializes raw DEKs. The default in-memory brokers invalidate sessions on
restart. The durable broker stores no plaintext session token or scope key. It
stores token HMAC digests, provider-wrapped scope keys, lifecycle/guard
metadata, and expiry-bound lease rows. A durable session survives restart only
while unexpired, unrevoked, and bound to the exact `ACTIVE` revision.

## Key hierarchy

AuthGraph has two version-fenced formats:

- v1 generates one random 256-bit DEK for the complete private vault.
- v2 generates one random 256-bit vault-wrapping key plus an independent
  random 256-bit DEK for every protection scope.

For both formats, a dedicated non-chat interface accepts a passphrase,
Argon2id derives a 256-bit KEK with a unique salt, and AES-256-GCM wraps the
random vault key. The envelope AAD binds the principal, vault, format version,
envelope revision, key version, KDF metadata, and salt.

In v2, the random vault key wraps scope DEKs but never encrypts graph records
directly. Each node or connection is encrypted by its assigned scope DEK with
a fresh nonce. AAD binds its owner, vault, scope, object ID, version, and—for a
relationship—direction, endpoints, and endpoint scopes.

AuthGraph stores neither the password nor raw keys in Neo4j. Password change
first prepares `REVISION_PENDING` and revokes existing sessions, then
compare-and-swaps the Neo4j envelope. After that commit it finalizes
`ACTIVE(next_revision)`. An interruption leaves the vault pending;
`reconcile_passphrase_change()` reads the authoritative graph revision and
accepts only the recorded current or next revision. Older grants become
unusable at provider unlock. Scope keys and record ciphertext do not change.
The caller still owns and must dispose of the passphrase input.

Re-wrapping is not cryptographic recovery from compromise. Anyone who copied a
vault or scope key keeps the corresponding decrypt capability. Suspected key
compromise requires rotation and re-encryption; that workflow is not
implemented.

This has two important consequences:

- A stolen envelope permits offline password guesses. Argon2id slows guessing
  but cannot make a weak password safe. Authentication rate limiting does not
  stop offline attacks. A production design should consider a second
  server/HSM-controlled factor.
- With no enrolled alternative provider or recovery wrap, losing the password
  or corrupting key metadata can permanently lose the data.
  `MirroredKeyWrappingBackend` is an independent-wrap building block, not a
  complete recovery product. Break-glass approval, custody, audit, drills, and
  immediate rewrap remain application and governance responsibilities.

Routine `MirroredKeyWrappingBackend.unwrap_key()` uses the primary backend only
and never falls back to recovery. Recovery is a separate explicit operation,
allowed only after consuming an exact single-use recovery grant. It records
pseudonymous source provenance and rewraps into a different provider generation.

## Owner and delegated access

The current MVP has one opaque owner principal per vault. It does not yet
implement delegated access for another user, employee, administrator, family
member, service account, or organization.

A production multi-user design should not make different people share one
password. Instead, the same vault DEK should be wrapped independently for each
authorized principal, normally using managed organization keys or public-key
credentials. Authorization and key slots must both be revoked. Strong
revocation may also require rotating the vault DEK.

The identity-provider subject-to-owner mapping should remain outside Neo4j.
Do not use names, emails, government identifiers, customer/account numbers, or
other PII as `principal_id` or `vault_id`.

Legacy v1 still has one private DEK, so a live v1 context can decrypt the whole
private vault. V2 creates cryptographic compartments with independent scope
DEKs. It does not yet implement delegated principals, shared key slots,
automatic legacy encrypted-data migration, or scope-key rotation. Packaged
Neo4j schema-version migrations are a separate mechanism. The broader design
is in [CHATBOT_GRAPHRAG_DESIGN.md](CHATBOT_GRAPHRAG_DESIGN.md).

## Layered public graph and private overlays

The main `AuthGraph` facade combines a physically separate public path with
scoped-v2 private storage:

```text
Public:   AGPublicGraph / AGPublicEntity / AG_PUBLIC_LINK
Private:  AGVault / AGProtectionScope / AGScopedEntity / AG_SCOPED_LINK
```

`LayeredGraphService` remains available only for the legacy v1
`AGEntity`/`AG_LINK` format.

The secure defaults classify every new entity and relationship as `PRIVATE`.
A `GraphPolicy` may select different defaults for a named graph.
`allow_public_overrides` must be explicitly enabled before one record can
weaken a private default to plaintext public. Tightening a public default to
private is always permitted. Unknown or malformed policy values fail rather
than falling back to public.

`get_public_view()` queries only the public repository. It does not enumerate
or decrypt the private repository and does not return private identifiers,
types, counts, per-record placeholders, or bridge topology. `GENERIC_BADGE`,
when configured, is one fixed policy result returned for both an empty and
populated overlay. It therefore says what the application supports, not
whether a private record exists. `get_unlocked_view()` is a separate explicit
operation requiring a live vault context. Public snapshots fail rather than
truncate when their fixed entity, relationship, or aggregate semantic-byte
limits are exceeded.

A public relationship is valid only between two public endpoints. A private
relationship may refer to a public endpoint through an encrypted anchor entity
inside the owner's vault. The anchor's public ID and the relationship semantics
are encrypted; Neo4j sees only opaque private IDs and generic private topology.
After unlock, the trusted service resolves anchors and rejects missing,
duplicate, cross-graph, or dangling endpoints before returning a composed view.

One composed read uses exactly one live owner `AccessContext`. It returns the
public base plus that context's vault overlay; it does not scan or combine other
owners' vaults. Authentication and the principal-to-vault lookup are external
identity functions kept outside the public graph. The flow is `authenticated
person -> authorized opaque vault ID -> unlock -> AccessContext ->
get_unlocked_view()`. A name in chat must never select the authorization scope.

The public repository accepts trusted backend writes without a vault password
because common application knowledge may not belong to one person. This is not
end-user authorization. `AuthGraph` additionally requires an
application publisher context accepted by `public_write_authorizer`; `graph_id`
is scope, not authorization or a secret. A web adapter must enforce its own
administrator/data-owner policy and must not expose publisher contexts or
public/private generic writes as AI tools.

Classification remains immutable. Private kind and property updates keep the
same encrypted scope; they do not reclassify the record. An existing private
record cannot be exposed merely by changing metadata, and missing or malformed
encryption fields are never interpreted as public. A future
private-to-public operation must decrypt and copy in one authenticated,
auditable, atomic transaction with explicit confirmation. Publication may
leave plaintext in clients, logs, transaction history, caches, and backups.
A future public-to-private operation protects only future access and cannot
recall those copies.

The main facade requests a bounded snapshot through the current scoped
session, so ciphertext outside its granted scopes cannot be decrypted. Private
wrappers are then filtered by their encrypted `graph_id`. Records from another
logical graph in the same granted scopes can therefore enter trusted transient
memory and count toward the limit, but they are not returned. A relationship
is visible only when its own scope and both endpoint scopes are present.
Production retrieval should ordinarily remain task-specific and return fewer
fields.

`ScopedGraphViewAdapter` remains as a lower-level compatibility adapter for raw
scoped records. New applications should use `AuthGraph`, which understands the
encrypted graph wrappers and public anchors directly.

Policies are in-process startup configuration, not persisted or revisioned
security records. Changing them affects future writes and the badge only. Each
private edge involving a public endpoint currently creates an encrypted helper
anchor. New anchors and their relationship are committed atomically, so a
failed write leaves neither. An idempotent replay reuses its helpers, but
separate logical creates can still produce duplicate anchors, and anchors count
toward the snapshot limit. Helper deletion is atomic only when they are not
shared; unexpected sharing fails closed.

The public repository cannot inspect encrypted private references. Deleting a
public endpoint can therefore leave an encrypted anchor and edge. Unlocked
composition hides that unresolved edge, and a trusted private-relationship
delete can later remove the edge and unshared helper. Applications need a
cross-store deletion/cleanup policy; a future deduplicated external-reference
design would reduce this gap.

## Required host-application unlock and session flow

The Python library implements key envelopes, password unlock, scoped sessions,
OTP challenges, fixed one-time-code profiles, a scope-key-provider interface,
an injected-client AWS KMS wrapping adapter, durable slot-store SPI, and
optional SQLite references for OTP, grant, session, and key-slot state. It does
not implement login, HTTP, cookies, password/code forms, email delivery,
passkeys, KMS credentials/policy, or a shared multi-host authorization service.

```text
1. User authenticates to the application, preferably with MFA/passkeys.
2. Chat receives only an `unlock_required` state.
3. A dedicated password form posts directly to the key broker over TLS.
4. The backend retrieves the key envelope using the authenticated principal
   and opaque vault ID.
5. Argon2id derives a transient KEK; AES-GCM unwraps the v1 DEK or v2
   vault-wrapping key.
6. For v2, the backend unwraps only policy-selected scope DEKs.
7. Temporary mutable KEK/DEK buffers owned by the broker are cleared
   best-effort. The HTTP/caller layer is responsible for disposing of its
   passphrase input buffer.
8. Only the selected key material enters a short-lived scoped session bound to
   principal + vault. The default broker holds it in memory; the durable
   single-host broker persists token digests, provider-wrapped session keys,
   lifecycle/guard metadata, and expiry-bound lease rows, never plaintext keys.
9. The browser receives a high-entropy opaque cookie, never a key or the
   internal `AccessContext`.
10. Every fixed graph operation obtains its vault and scope authority from that
    server session, not from user text or model-selected arguments.
11. Session creation and every new key lease require `ACTIVE` at the exact
    envelope revision. Logout, timeout, password change, or session revocation
    prevents the affected session from taking another lease. A provider-slot
    tombstone prevents future provider release, not direct passphrase unlock.
    Restart invalidates in-memory sessions; a valid durable session
    intentionally survives a same-host restart.
```

A one-time code must not be used as a KEK or entered in chatbot text. The
brokers store only HMAC-keyed verifiers, limit attempts, bind the challenge to
the principal, profile, opaque vault context, browser transaction, and current
authorization epoch, and produce evidence that can be consumed exactly once.
The durable broker adds a stable verifier key, issuance limits, and atomic
SQLite transitions across local processes; it stores neither plaintext codes
nor raw evidence capabilities.
The fixed policy then creates a single-use scope grant.

The code only authorizes a trusted provider to release keys.
`InMemoryScopeKeyProvider` is a process-local test helper.
`EnvelopeScopeKeyProvider` composes a provider wrapping backend with atomic key
slots; the included AWS KMS adapter accepts an already authenticated client,
and `SqliteKeySlotStore` is durable on one host. Production still requires
correct provider credentials and key policies, a shared strongly consistent
slot store for multiple hosts, issuance limits, monitoring, and reviewed
lifecycle operations.

Coordinated management commits a required audit intent, enters `BLOCKED` under
the same per-vault fence used by provider unlock, revokes existing sessions,
and keeps that fence through provider mutation. A provider unlock cannot mint a
session after blocking begins. A key already leased or copied before the fence
may still finish and cannot be recalled. Suspected scope-key compromise still
requires data-key rotation and record re-encryption, which is not automated.
Provider-slot tombstones do not disable the separate passphrase-unlock path;
the host must remove that credential path when its policy requires global
access revocation.

Email is only one possible host delivery channel. It is lower assurance and is
not accepted as out-of-band authentication by current NIST digital identity
guidance. Prefer passkeys or an identity provider with MFA for sensitive
deployments.

The in-memory session broker enforces expiry synchronously whenever a token
asks for a lease. It also sweeps and best-effort zeroes expired resident DEKs
every second by default, and removes them opportunistically on another session
open. The sweep
interval is bounded between 10 milliseconds and 60 seconds to prevent both a
tight-loop configuration and unbounded post-expiry residency; disabling it is
intended only for deterministic tests. If the worker fails unexpectedly, the
broker records a health flag, stops new work, drains guarded operations, and
clears all resident session keys. A production host must monitor
`sweeper_failed` and use the broker as a context manager or call `close_all()`
during graceful shutdown. Shutdown stops admission, waits for guarded
in-flight work, stops the sweeper, and clears resident DEKs. A DEK copy already
leased to an in-flight operation may live until that operation's `finally`
block completes. Local lifecycle operations do not preempt that work; the
vault guard makes logout or password change wait until it finishes.

Every vault has one fenced lifecycle state:

- `ACTIVE(current_revision)` admits new sessions and leases only at that exact
  revision.
- `REVISION_PENDING(current_revision, next_revision)` is written before a
  passphrase-envelope compare-and-swap and survives an interruption.
- `BLOCKED(current_revision, generation)` is written before revocation,
  provider rewrap, or recovery mutation and survives an interruption.

`REVISION_PENDING` is reconciled only from Neo4j's authoritative envelope
revision. `BLOCKED` is cleared only after an operator verifies provider,
session, graph, and audit state and supplies the exact blocked generation.
Reconciliation is a trusted backend/operator action, never a chatbot tool.

`DurableScopedSessionBroker` uses SQLite transactions plus heartbeat-renewed,
monotonic generation-fenced guards across processes sharing one local file. A
worker that loses its guard cannot commit protected lifecycle work. Each active
key lease has an expiry-bound row; after a worker crash, purge can reclaim stale
rows and remove revoked wrapped-session ciphertext. This cannot recall a
plaintext copy already held by a process. `close_all()` closes only that broker
handle and does not revoke persisted sessions.

The in-memory broker's striped lock and revision fence close password-change
races for service objects sharing that broker. Separate in-memory brokers do not
share state. Durable brokers sharing one SQLite file do coordinate local worker
processes, but a production multi-host deployment still needs a hardened shared
broker or distributed fencing/revocation protocol. The in-memory broker also
caps tracked vault lifecycle rows and fails closed when full.

The optional SQLite OTP, grant, session, and slot stores extend this boundary
to processes on one machine, not to multiple application hosts. A multi-host
deployment must replace each with shared transactional state that preserves
atomic consume, fencing, expiry, revocation, and bounded-capacity behavior.

`SecurityAuditLogger` writes only HMAC-pseudonymized references and allowlisted
metadata. Management operations commit a required `PENDING` audit intent before
their first mutation, then a linked `SUCCEEDED` or `FAILED` outcome. A successful
mutation records its outcome while the vault is still blocked and only then
restores access. `verify_json_lines_audit_report()` verifies the hash
chain and reports unmatched pending operation references. A pending reference
means the result is ambiguous and authoritative state must be inspected before
reconciliation or retry. `JsonLinesAuditSink` remains a local reference, not
WORM storage or a multi-host audit service; audit and state are not one
distributed transaction.

A future HTTP layer must use `Secure`, `HttpOnly`, and appropriate `SameSite`
cookies, CSRF protection, session rotation, a strict content-security policy,
and no credential storage in browser `localStorage` or `sessionStorage`.

## Neo4j complete mediation

All private repository operations require both `principal_id` and `vault_id`.
Every private Neo4j query:

- is a fixed application template;
- uses parameters rather than string concatenation;
- starts from the owned `AGVault`;
- matches the session's authenticated envelope revision on every entity,
  relationship, and neighborhood operation;
- requires every entity and link to carry the same vault scope; and
- returns only ciphertext and opaque metadata.

The service verifies both edge endpoints inside the same vault. It intentionally
uses generic `AGEntity` and `AG_LINK` semantics so a database reader cannot see
plaintext labels such as `PrivateCategory`, `SensitiveEvent`, or `RELATED_TO`.

V2 uses separate generic labels and links:

```text
AGProtectionScope / AGScopedEntity / AG_SCOPED_LINK
```

Its fixed queries also require envelope version 2, the current revision, and
an exact server-supplied scope allowlist. Scope envelopes bind their root key
version. Scoped entity payloads bind their scope-key version. A scoped
relationship read or write requires the relationship scope plus both endpoint
scopes. New scoped records start at record revision 1. The revision is stored
both as operational metadata and inside authenticated ciphertext. Updates use
compare-and-swap and keep entity scope, relationship scope, direction, and
endpoints immutable. Entity deletion refuses every incident scoped
relationship, including one outside the session's grant; it never uses an
unrestricted cascade delete.

The separate public adapter likewise exposes only fixed, graph-scoped query
templates. It stores properties as canonical plaintext JSON and never queries
private labels. Public graph IDs and public object IDs are opaque, bounded
values supplied as parameters rather than interpolated into Cypher. Cooperative
public writes, optimistic updates/deletes, and bounded snapshots take the same
transient public-graph lock so a snapshot cannot pair a new relationship with
an older entity collection. `AuthGraph` requires trusted publisher
authorization for every public write.

The adapter treats an exact row already present after a zero-row write or
`IncompleteCommit` as a successful retry. If it cannot verify the exact row,
the ambiguous error is propagated rather than silently generating another ID.
Private create methods also accept an application idempotency key. AuthGraph
derives a stable opaque object ID with HMAC-SHA256 under the selected scope key;
the raw idempotency key is not stored. An exact replay returns the same ID,
while reusing the key with changed semantics, scope, endpoints, or direction
fails. Public creates derive a stable ID from SHA-256 over the operation,
graph, and opaque retry key; mixed anchor-edge bundles use the protected scope
path. Exact replays are retry-safe and changed intent conflicts. Creates
without a key still generate a new random ID. Public retry keys are not secret
authentication evidence and should contain no PII or credentials. The schema
requires globally unique entity and relationship IDs.

Protected writes take an explicit temporary-property lock on the vault before
reading its envelope revision. This is required because Neo4j's default
read-committed isolation does not by itself make a revision predicate a
compare-and-swap. The temporary property is removed in the same transaction.
Layered public anchors and their encrypted relationship are created by one
fixed query in that same vault-locked transaction, so the bundle commits as a
whole or leaves no helper records.
The full-vault snapshot query takes the same lock before checking the revision,
so cooperative writes cannot produce a torn snapshot. The lock has no durable
semantic effect, but it is held for the transaction.

The packaged portable schema contains uniqueness constraints. Missing
properties are not covered by uniqueness, and `IF NOT EXISTS` may be hidden by
a conflicting same-named object. `authgraph schema apply` applies only the
packaged fixed statements and then verifies exact names, types, labels,
properties, and online index state. `authgraph schema verify` performs the same
read-only check. Production must prevent untrusted direct graph writes and use
Enterprise existence/key constraints where available.

These queries have recording-driver unit tests and an opt-in live integration
suite. A CI matrix is configured for explicit Neo4j compatibility points, but
configuration alone is not a passing result. Check the live result for the
exact commit, driver, and server version before release.

Neo4j/Aura storage encryption, TLS, RBAC, PBAC, private networking, backups,
and audit controls remain important defense in depth. They are not a
replacement for this application encryption. Current Neo4j documentation also
notes that fine-grained controls are tier-dependent. The adapter rejects a
driver whose `encrypted` property is not explicitly true; production should
still use trusted-certificate verification such as `neo4j+s`.

## AI integration contract

The broader target architecture and implementation order are in
[CHATBOT_GRAPHRAG_DESIGN.md](CHATBOT_GRAPHRAG_DESIGN.md).

The AI must have:

- no database driver or Neo4j credentials;
- no passphrase, KEK, DEK, vault ID, or session capability;
- no arbitrary Cypher or generic graph-query tool;
- no ability to select the owner security scope;
- only narrow read-only operations such as `get_my_order_timeline`;
- bounded results; and
- retrieved records treated as untrusted content that cannot issue commands.

The trusted tool executor attaches the current context, graph, policy, and
optional vector index out of band. Register only a wrapper whose model schema
accepts question text. Do not register the backend
`SessionVisibleGraphGateway.retrieve()` method directly because it also has
trusted-only parameters.

The default private retrieval path first decrypts a bounded complete snapshot
of every scope granted to the session in trusted memory. The optional
`SessionCandidateIndex` also starts with one complete policy-projected view,
then retains allowlisted lexical token counts and opaque semantic topology in
process. These token derivatives remain sensitive even though the index does
not keep the original property mapping.

Repeated searches with that exact gateway/context-bound index rank candidates
in process and use a fixed, revision- and scope-fenced repository query to read
only the selected current ciphertext rows and granted relationship endpoints.
A closed, expired, or wrong-context index fails and never becomes a public-only
fallback. Candidate tokens/topology are build-time state, so discovery may be
stale until rebuild. This reduces repeated full-snapshot decryption but does
not make encrypted properties semantically searchable in Neo4j and does not
remove the initial complete in-process projection.

The gateway projects allowed kinds and properties, ranks lexical and optional
vector seeds, performs bounded traversal, and returns provenance. Its canonical
serialized byte limit covers the complete returned payload. Its token value is
only a deterministic byte-based estimate; the host must apply the actual
selected model tokenizer and final prompt budget.

An external LLM necessarily sees those returned plaintext fields. Turning off
"memory" does not cryptographically prove that a model provider kept no logs.
For regulated data, review the exact model provider, region, retention,
training policy, subprocessors, and required contracts such as a DPA or BAA
when applicable. If zero sensitive plaintext may leave the trusted boundary,
use a local/on-premises model or deterministic output.

`get_vault_snapshot()` is the deliberate bounded full-authorized-scopes
operation used internally by the current facade and available for
small tests. It is authenticated out of band and returns either one complete
small view or an error under fixed count and aggregate-ciphertext ceilings. It
does not stream partial plaintext and AuthGraph does not cache its return
value. Once returned, however, all decrypted entities and relationships are
caller-owned plaintext; passing that snapshot directly to an LLM exposes the
whole snapshot to the model environment. It must not be offered as a
model-selectable tool. The current gateway filters the eventual model result,
while future storage-native candidate discovery should further minimize
plaintext inside the trusted process.
Its all-or-nothing guarantee covers the rows visible to the scoped repository
query and the configured bounds. It cannot detect a hostile storage actor that
deletes a row or removes the label, vault metadata, or ownership edge needed
to make that row query-visible; that requires an authenticated inventory
outside the mutable graph.

The current facade has revision-checked public/private updates and restrictive
physical deletes. Classification changes, encrypted embedding storage/loading,
hosted model integration, and an AI write policy are not implemented. The
temporary vector and candidate indexes are caller-managed and must be closed
before or with the secure session; automatic lifecycle binding is not
implemented.

## Tests required before real data

The included unit tests cover the first layer:

- cross-owner guessed-ID and forged-principal denial;
- ciphertext-only semantic storage;
- wrong-password behavior;
- synchronous expiry, background expired-key sweeping, and explicit lock;
- ciphertext tampering and object-swapping detection;
- encrypted relationship round trips;
- bounded all-or-nothing vault snapshots and cross-owner snapshot isolation;
- fail-closed password re-wrapping, crash-sticky pending state, exact trusted
  reconciliation, and session revocation;
- compare-and-swap envelope updates and a forced stale-unlock race;
- invalid/non-finite TTL rejection and strict storage-metadata decoding;
- in-flight lifecycle serialization, concurrent shutdown/key-zeroization
  ordering, fail-closed sweeper failure, and stale-replica repository
  fencing;
- fixed, vault-scoped Neo4j query templates;
- per-record public/private choices with private-by-default policies;
- locked public-only views that do not invoke private decryption;
- public/private endpoint and relationship visibility invariants;
- encrypted anchors for public-to-private and private public-to-public edges;
- atomic failure behavior for encrypted anchor/relationship bundles;
- two-owner overlay isolation over one shared public graph;
- policy-driven generic badges that reveal no private record count; and
- fixed, graph-scoped public Neo4j query templates and malformed-row rejection;
- independent v2 scope keys, wrong-scope denial, and relationship/endpoint
  scope visibility;
- fixed, owner-rooted, revision-fenced scoped Neo4j queries and strict
  ciphertext decoding;
- authenticated record revisions, optimistic update conflicts, restrictive
  entity deletion, and relationship CRUD across all required scopes;
- HMAC-derived private idempotent creates, exact replay, changed-intent
  rejection, and atomic scoped helper bundles;
- publisher-authorized public CRUD, optimistic revisions, deterministic public
  idempotency, mixed-edge idempotent bundles, and unshared helper cleanup;
- packaged schema application and exact constraint/index verification;
- OTP attempt, expiry, resend, concurrency, evidence-forgery, and replay
  behavior;
- restart-safe SQLite OTP/grant consumption and cross-process single-winner
  behavior on one host;
- fixed scope profiles, provider release, authorization-epoch invalidation,
  expiry-during-release, and provider-close ordering;
- durable same-host session restart, cross-worker logout/revocation, exact
  revision fencing, heartbeat guard renewal/stale-owner rejection, crashed-lease
  cleanup, and provider-wrapped resident keys;
- key-slot compare-and-swap, exact-scope release, tombstones, provider-key
  rewrap, injected-client AWS KMS behavior, primary-only routine unwrap,
  explicitly authorized recovery/provenance, crash-sticky blocked operations,
  pseudonymous hash-chained audit intents/outcomes, and unmatched-intent
  reporting; and
- GraphRAG kind/property filtering, bounded traversal, complete payload
  budgets, provenance, vector intersection, session-bound candidate indexes,
  exact targeted ciphertext reads, fail-closed context mismatch, and
  public/private merge validation.

Production also needs:

- property/fuzz tests for every URL, body, nested traversal, search, export,
  batch operation, and error path;
- nonce uniqueness under concurrency, retries, and process failure;
- session fixation, replay, cookie theft, CSRF, XSS, logout, and restart tests;
- production KMS key-slot enrollment, grant, revoke, and rotation tests;
- log, trace, analytics, crash report, and model-payload redaction assertions;
- prompt-injection tests using malicious text stored in graph records;
- backup/restore and key-loss drills;
- deletion and whole-snapshot rollback detection using an external trusted
  revision source;
- KDF performance calibration and unlock denial-of-service protection;
- live Neo4j two-vault, constraint, transient-retry, and malformed/orphan data
  integration tests; and
- independent security and privacy assessment.

Production responsibilities and the explicit review gate are in
[PRODUCTION_SETUP.md](PRODUCTION_SETUP.md),
[OPERATIONS.md](OPERATIONS.md), and
[SECURITY_REVIEW.md](SECURITY_REVIEW.md). No independent signoff has occurred.

## Primary references

- [Neo4j Aura encryption](https://neo4j.com/docs/aura/security/encryption/)
- [Neo4j property-based access control](https://neo4j.com/docs/operations-manual/current/authentication-authorization/property-based-access-control/)
- [Neo4j Python query parameters](https://neo4j.com/docs/python-manual/current/query-simple/)
- [Neo4j concurrent data access and explicit locking](https://neo4j.com/docs/operations-manual/current/database-internals/concurrent-data-access/)
- [Neo4j Python connection security](https://neo4j.com/docs/python-manual/current/connect-advanced/)
- [Neo4j Python driver exceptions](https://neo4j.com/docs/api/python-driver/current/api.html#neo4j.exceptions.IncompleteCommit)
- [RFC 9106: Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [NIST SP 800-38D: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
