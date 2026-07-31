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
   principal's secure session.
3. A passphrase, KEK, DEK, Neo4j credential, or session token never enters an
   LLM prompt, tool argument, graph property, application log, or audit event.
4. Unlocking one vault never globally decrypts Neo4j.
5. Modification or truncation of a present ciphertext, record swapping, or
   cross-vault movement fails authenticated decryption.
6. Expiry, logout, password change, and session revocation prevent the affected
   session from obtaining a new DEK lease in the supported single-process
   design. Session revocation does not disable a future password unlock.

## Non-goals and unavoidable leakage

Application encryption is not magic searchable encryption.

Neo4j can see:

- every semantic kind and property deliberately stored in the public layer;
- opaque principal, vault, entity, and relationship identifiers;
- that entities belong to the same vault;
- generic connectivity, direction, graph size, and access patterns;
- ciphertext sizes and key/KDF version metadata; and
- database operational metadata.

Neo4j cannot use randomized ciphertext for meaningful full-text, range, or
vector similarity search. A future per-vault blind index could support a small
number of carefully selected exact matches, but it would leak equality.
Embeddings are sensitive derivatives and cannot remain conventionally
encrypted while also supporting ordinary Neo4j vector search. A future trusted
retriever could decrypt embeddings only from scopes granted to one session,
build a temporary in-memory index, and destroy it at session end. That
retriever is not implemented.

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
This prototype overwrites mutable buffers on a best-effort basis, never
serializes raw DEKs, and intentionally locks all vaults on process restart.

## Key hierarchy

For each vault:

1. Generate a random 256-bit DEK.
2. Accept a strong passphrase through a dedicated non-chat security interface.
3. Generate a unique 128-bit salt.
4. Derive a 256-bit KEK with Argon2id.
5. Wrap the DEK using AES-256-GCM and AAD containing the principal, vault,
   envelope format version, envelope revision, and key version.
6. Store only the salt, KDF parameters, wrap nonce, wrapped DEK, and versions.
7. Encrypt each entity and relationship independently with the random DEK,
   a fresh nonce, and object-specific AAD.

AuthGraph does not persist the password. Password change unwraps the DEK using
the old password and re-wraps it using the new one. The caller still owns the
input buffer and must dispose of it after the call.

Re-wrapping is not cryptographic recovery from compromise. Anyone who copied
the old DEK can decrypt old and future records while the vault keeps using that
DEK, regardless of a later passphrase change. Suspected passphrase, envelope,
or DEK compromise requires generating a new DEK and re-encrypting every vault
record; that rotation workflow is not implemented in this prototype.

This has two important consequences:

- A stolen envelope permits offline password guesses. Argon2id slows guessing
  but cannot make a weak password safe. Authentication rate limiting does not
  stop offline attacks. A production design should consider a second
  server/HSM-controlled factor.
- With no recovery wrap, losing the password or corrupting envelope metadata
  permanently loses the data. A break-glass or recovery key is a product,
  governance, and legal decision—not something to improvise later.

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

The current vault also has only one private DEK. A live context can therefore
decrypt every private record in that vault. Returning fewer records limits
disclosure but does not create cryptographic compartments. The planned
protection-scope and pluggable-unlock design is documented in
[CHATBOT_GRAPHRAG_DESIGN.md](CHATBOT_GRAPHRAG_DESIGN.md).

## Layered public graph and private overlays

`LayeredGraphService` keeps the existing encrypted storage path unchanged and
adds a physically separate public path:

```text
Public:   AGPublicGraph / AGPublicEntity / AG_PUBLIC_LINK
Private:  AGVault / AGEntity / AG_LINK
```

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
end-user authorization. `LayeredGraphService` additionally requires an
application publisher context accepted by `public_write_authorizer`; `graph_id`
is scope, not authorization or a secret. A web adapter must enforce its own
administrator/data-owner policy and must not expose publisher contexts or
public/private generic writes as AI tools.

Classification is immutable in the current layered prototype. An existing
private record cannot be exposed merely by changing metadata, and missing or
malformed encryption fields are never interpreted as public. A future
private-to-public operation must decrypt and copy in one authenticated,
auditable, atomic transaction with explicit confirmation. Publication may
leave plaintext in clients, logs, transaction history, caches, and backups.
A future public-to-private operation protects only future access and cannot
recall those copies.

The layered composer uses a bounded full-vault snapshot because the requested
test behavior gives the chatbot all of one owner's data after unlock. That
snapshot is decrypted before layered records are filtered by `graph_id`, so
unrelated records enter trusted transient memory and count toward the limits.
Prefer one layered graph per vault in this prototype. Production retrieval
should ordinarily remain task-specific and return fewer fields.

Policies are in-process startup configuration, not persisted or revisioned
security records. Changing them affects future writes and the badge only. Each
private edge involving a public endpoint currently creates an encrypted helper
anchor. New anchors and their relationship are committed atomically, so a
failed write leaves neither. Successful connections can still create duplicate
anchors, and anchors count toward the snapshot limit. Production needs a
deduplicated external-reference design.

## Required host-application unlock and session flow

The current Python library implements the key-envelope, unlock, and in-memory
broker operations. It does not implement the login, browser, HTTP, cookie,
password-form, MFA, passkey, or one-time-code parts in this flow.

```text
1. User authenticates to the application, preferably with MFA/passkeys.
2. Chat receives only an `unlock_required` state.
3. A dedicated password form posts directly to the key broker over TLS.
4. The broker retrieves the key envelope using the authenticated principal
   and opaque vault ID.
5. Argon2id derives a transient KEK; AES-GCM unwraps the vault DEK.
6. Temporary mutable KEK/DEK buffers owned by the broker are cleared
   best-effort. The HTTP/caller layer is responsible for disposing of its
   passphrase input buffer.
7. The DEK enters a short-lived in-memory session bound to principal + vault.
8. The browser receives a high-entropy opaque cookie, never the DEK.
9. Every fixed graph operation obtains its vault scope from that server
   session, not from user text or model-selected arguments.
10. Logout, timeout, password change, revocation, or restart prevents a future
    operation from acquiring a session key lease.
```

An email code must not be used as a KEK or entered in chatbot text. A future
email-code option would verify a short-lived challenge outside the model and
authorize a trusted KMS/key service to release only policy-approved keys.
Email is a lower-assurance channel and is not accepted as out-of-band
authentication by current NIST digital identity guidance. Prefer passkeys or
an identity provider with MFA for sensitive deployments.

Expiry is enforced synchronously whenever a token asks for a lease. The broker
also sweeps and best-effort zeroes expired resident DEKs every second by
default, and removes them opportunistically on another session open. The sweep
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

The local striped lock, envelope compare-and-swap, and broker revision fence
close password-change races inside one process, including multiple service
objects sharing that broker. Separate brokers in separate replicas do not
share revision state. A production multi-replica deployment therefore needs a
hardened shared broker or distributed fencing/revocation protocol.
The prototype also places a configurable hard cap on tracked vault revisions
and fails closed when full; production should keep this authority in bounded,
durable shared state.

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

The separate public adapter likewise exposes only fixed, graph-scoped query
templates. It stores properties as canonical plaintext JSON and never queries
private labels. Public graph IDs and public object IDs are opaque, bounded
values supplied as parameters rather than interpolated into Cypher. Cooperative
public writes and bounded snapshots take the same transient public-graph lock
so a snapshot cannot pair a new relationship with an older entity collection.

The adapter treats an exact row already present after a zero-row write or
`IncompleteCommit` as a successful retry. If it cannot verify the exact row,
the ambiguous error is propagated rather than silently generating another ID.
A future HTTP/API layer still needs an idempotency key for each logical create
request; retrying the whole service call otherwise generates a new ID. The
schema also requires globally unique entity and relationship IDs.

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

The portable schema contains uniqueness constraints. Missing properties are
not covered by uniqueness, and `IF NOT EXISTS` may be blocked by a conflicting
same-named constraint. Deployment must verify the exact result with
`SHOW CONSTRAINTS`, prevent all untrusted direct graph writes, and use
Enterprise existence/key constraints where available.

Neo4j/Aura storage encryption, TLS, RBAC, PBAC, private networking, backups,
and audit controls remain important defense in depth. They are not a
replacement for this application encryption. Current Neo4j documentation also
notes that fine-grained controls are tier-dependent. The adapter rejects a
driver whose `encrypted` property is not explicitly true; production should
still use trusted-certificate verification such as `neo4j+s`.

## Future AI integration contract

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

The trusted tool executor attaches principal and vault scope out of band. It
decrypts only the selected result and returns the minimum necessary fields.

An external LLM necessarily sees those returned plaintext fields. Turning off
"memory" does not cryptographically prove that a model provider kept no logs.
For regulated data, review the exact model provider, region, retention,
training policy, subprocessors, and required contracts such as a DPA or BAA
when applicable. If zero sensitive plaintext may leave the trusted boundary,
use a local/on-premises model or deterministic output.

The prototype also exposes `get_vault_snapshot()` as a deliberate exception
for the requested full-vault chatbot test. It is authenticated out of band and
returns either one complete small vault or an error under fixed count and
aggregate-ciphertext ceilings. It does not stream partial plaintext and
AuthGraph does not cache its return value. Once returned, however, all
decrypted entities and relationships are caller-owned plaintext; passing that
snapshot to an LLM exposes the whole snapshot to the model environment. This
high-exposure operation should not be offered as a model-selectable tool, and
narrow task-specific retrieval remains the production recommendation.
Its all-or-nothing guarantee covers the rows visible to the scoped repository
query and the configured bounds. It cannot detect a hostile storage actor that
deletes a row or removes the label, vault metadata, or ownership edge needed
to make that row query-visible; that requires an authenticated inventory
outside the mutable graph.

The current API has no update or delete operations. It also has no GraphRAG
retriever, embedding provider, vector index, model tool executor, or AI write
path.

## Tests required before real data

The included unit tests cover the first layer:

- cross-owner guessed-ID and forged-principal denial;
- ciphertext-only semantic storage;
- wrong-password behavior;
- synchronous expiry, background expired-key sweeping, and explicit lock;
- ciphertext tampering and object-swapping detection;
- encrypted relationship round trips;
- bounded all-or-nothing vault snapshots and cross-owner snapshot isolation;
- password re-wrapping and session revocation;
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
- fixed, graph-scoped public Neo4j query templates and malformed-row rejection.

Production also needs:

- property/fuzz tests for every URL, body, nested traversal, search, export,
  batch operation, and error path;
- nonce uniqueness under concurrency, retries, and process failure;
- session fixation, replay, cookie theft, CSRF, XSS, logout, and restart tests;
- authorization and key-slot grant/revoke tests;
- log, trace, analytics, crash report, and model-payload redaction assertions;
- prompt-injection tests using malicious text stored in graph records;
- backup/restore and key-loss drills;
- deletion and whole-snapshot rollback detection using an external trusted
  revision source;
- KDF performance calibration and unlock denial-of-service protection;
- live Neo4j two-vault, constraint, transient-retry, and malformed/orphan data
  integration tests; and
- independent security and privacy assessment.

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
