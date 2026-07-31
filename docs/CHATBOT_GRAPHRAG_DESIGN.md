# AuthGraph for chatbots and GraphRAG

This is the target design and the status of its first implementation slice.

The goal is simple:

> A chatbot can use public knowledge plus only the protected knowledge granted
> to the current session. Everything else stays absent and encrypted.

## Status

| Capability | Status |
|---|---|
| Public nodes and connections | Available |
| Legacy whole-vault encryption | Available as v1 |
| Separate random keys for opaque protection scopes | Available as v2 |
| Session holds only policy-granted scope keys | Available in one process |
| Password unlock for selected scopes | Available |
| Fixed OTP disclosure profiles and single-use grants | Available in memory |
| Pluggable scope-key enrollment/release interface | Available |
| Real KMS/HSM provider | Host integration required |
| Email/SMS delivery | Host integration required |
| Bounded lexical GraphRAG and graph traversal | Available |
| Per-kind property allowlists and provenance | Available |
| Temporary in-memory vector index | Available; host-managed lifetime |
| Encrypted embedding storage/loading and embedding model | Planned |
| Passkey and identity-provider adapters | Planned |
| Production web authentication, auditing, and multi-server sessions | Planned |

AuthGraph keeps two formats separate. `AuthGraphService` is the legacy v1
whole-vault format. `ScopedAuthGraphService` is v2: it gives every protection
scope an independent random key and places only granted scope keys in a
session. There is no v1-to-v2 migration yet.

## The trust boundary

```text
Secure login or unlock UI
          |
          | verified identity and evidence
          v
Trusted AuthGraph backend
  - holds temporary keys
  - enforces the disclosure profile
  - reads Neo4j
  - decrypts permitted records
  - retrieves a small visible subgraph
          |
          | selected plaintext only
          v
Chatbot / AI
```

The AI does not receive:

- a password or one-time code;
- an encryption key;
- a session token;
- a Neo4j password or driver;
- an owner, vault, or protection-scope selector;
- arbitrary Cypher; or
- a switch that makes private data public.

The AI never decrypts the graph. It asks a narrow trusted tool for authorized
knowledge. The AuthGraph backend decrypts and returns only the result allowed
for that server-side session.

## Three separate decisions

AuthGraph must not mix these decisions:

1. **Identity:** who is using the application?
2. **Unlock evidence:** what password, passkey, MFA, or other proof is required?
3. **Disclosure:** which protected scopes, record types, fields, and amount of
   data may this session use?

A name or customer number may help find an account, but it is not strong proof
of identity and must not become an encryption key. The application maps an
authenticated account to an opaque AuthGraph vault outside the conversation.

## Public data, owner vaults, and protection scopes

One Neo4j database may hold many owner vaults. Every vault has one owner, and
the library permits one principal to have multiple vaults. If your product
wants exactly one vault per account, its backend must enforce that policy. A
vault may contain several private protection scopes:

```text
Shared public graph
  - product catalog
  - support articles

Owner vault
  - profile
  - orders
  - billing
  - private_notes
```

These names stay in trusted application configuration. AuthGraph stores opaque
scope IDs so a database reader does not learn that a scope is called `medical`
or `private_notes`.

Every v2 private scope gets its own random 256-bit data-encryption key. Every
v2 private node and connection is assigned to exactly one scope and encrypted
before it reaches Neo4j.

This gives a real boundary:

- a session with the `orders` key can decrypt orders;
- it cannot decrypt `billing` or `private_notes`;
- another owner's scope keys are never loaded; and
- public records remain readable without any owner key.

A private connection has its own scope. It is visible only when its scope and
both endpoint nodes are visible. Hidden endpoints are omitted rather than
replaced with revealing placeholders.

If properties inside one node need different access rules, they should be
separate protected nodes. Field filtering after decryption reduces AI
disclosure but is not field-level cryptographic separation.

## Configurable unlock policies

The application owner chooses an unlock policy. Examples:

```yaml
policies:
  basic_support:
    evidence: [existing_login]
    grant_scopes: [profile, orders]
    session_ttl_seconds: 300

  billing_support:
    evidence:
      all_of: [existing_login, passkey]
    grant_scopes: [profile, orders, billing]
    session_ttl_seconds: 180

  low_risk_email_confirmation:
    evidence:
      all_of: [existing_login, email_code]
    grant_scopes: [orders]
    session_ttl_seconds: 180
```

This YAML is illustrative; policy objects are currently configured in Python
with `UnlockProfile`, `ScopeGrantPolicy`, and `DisclosurePolicy`.

The current `UnlockProfile` supports one fixed scope set, TTL, and an
`allow_one_time_code` switch. Rich `all_of`/`any_of` policies remain planned.
This is authentication policy, not threshold cryptography. The trusted backend
evaluates it. The AI cannot weaken or replace it.

`UnlockProfile` currently governs the OTP exchange. Direct password unlock
accepts the exact scope tuple supplied by its trusted backend caller, so the
host must enforce the password disclosure policy before calling it.

Recommended provider types:

- existing application or identity-provider session;
- password or passphrase;
- WebAuthn/passkey;
- TOTP or another proper authenticator;
- company SSO/MFA;
- optional email confirmation for low-risk deployments; and
- KMS/HSM-backed key release.

Provider plugins run inside the trusted boundary and must be reviewed like
security code.

## Password unlock

The v2 password flow is implemented:

1. Derive a key-encryption key from the password with Argon2id.
2. Use it to unwrap one random vault-wrapping key.
3. Use that key to unwrap only the scope keys chosen by trusted policy.
4. Put only those scope keys in the server-side session.
5. Clear temporary key buffers best-effort.

The password must go to a dedicated secure endpoint or form. It must never be
entered into chatbot text, sent to the model, or included in model tool
arguments.

## One-time codes and email

A short code must never be used directly as an encryption key. Six or eight
digits can be guessed and do not contain enough entropy to protect stored
data.

The library implements the challenge, verifier, fixed grant policy, and key
provider boundary in memory. The safe pattern is:

1. The user already has an application session.
2. The host asks AuthGraph to begin a challenge for a fixed disclosure policy.
3. The address comes from a previously verified account record, not chat text.
4. A cryptographically random, short-lived, single-use code is generated.
5. Only a protected verifier is stored, bound to the principal, policy, opaque
   vault context, browser transaction, authorization epoch, expiry, and
   challenge.
6. The host application's mail adapter sends the code; AuthGraph does not.
7. A secure form submits the code directly to the verifier.
8. Rate limits and attempt limits are enforced and consumption is atomic.
9. Successful verification creates broker-authenticated evidence exactly once.
10. Policy exchanges it for a single-use scope grant.
11. AuthGraph consumes that grant, asks the trusted KMS/key service for only
    those scope keys, and returns an opaque, short-lived `AccessContext`.

The code authorizes key release; it does not mathematically derive the key.
The included `InMemoryScopeKeyProvider` demonstrates a second provider wrap
but is not production key custody. A real deployment needs a KMS/HSM adapter.
If a key is protected only by the password envelope, an email code cannot
decrypt it.

Email codes are customizable but must be labeled as a lower-assurance option.
Current NIST digital identity guidance does not accept email as an out-of-band
authenticator because it does not prove possession of a specific device and is
vulnerable to interception and account compromise. Prefer passkeys, an
identity provider with MFA, or another bound authenticator for sensitive data.

References:

- [NIST SP 800-63B: authenticator requirements](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [OWASP multifactor authentication guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)

## Session-visible graph

The decrypted graph is a virtual view in trusted memory. It is never written
back to Neo4j as plaintext.

`ScopedGraphViewAdapter` requests a bounded complete snapshot of only the
scopes present in the current v2 session and decrypts it in trusted memory.
`SessionVisibleGraphGateway` then combines:

```text
allowed public records
        +
records encrypted by scope keys in this session
        -
disallowed kinds and properties
        -
records outside count, byte-estimate, token-estimate, and hop limits
```

`DisclosurePolicy` currently configures:

- allowed node and connection kinds;
- property allowlists;
- maximum search candidates;
- maximum returned nodes and connections;
- maximum traversal depth;
- maximum complete serialized plaintext bytes; and
- a deterministic byte-based token estimate.

Scope grants and session lifetime are configured separately. The token estimate
is not a model tokenizer result; the host must enforce the selected model's
real prompt limit before sending a payload.

The gateway returns targeted lexical/vector seeds plus bounded traversal, but
its current scoped adapter is not a targeted database query: every retrieval
internally calls `ScopedAuthGraphService.get_vault_snapshot()` for all granted
scopes before projection and ranking. That bounded full-snapshot method must
not itself be registered as an AI tool. A future repository-native retriever
should reduce plaintext handled by the trusted process as well as by the model.

The adapter's `graph_id` is a logical label, not a private-record filter. The
session's granted protection scopes are the isolation boundary.

## GraphRAG request flow

```text
Question
   |
   v
Fixed AI tool: search_my_authorized_knowledge
   |
   v
Attach the server-side `AccessContext`
   |
   v
Search public data + only granted private scopes
   |
   v
Choose relevant seed nodes
   |
   v
Bounded traversal through visible connections
   |
   v
Redact fields and enforce count/byte/token limits
   |
   v
Small visible subgraph with provenance
   |
   v
AI answer
```

The model may suggest a search phrase or task argument. It may not select the
owner, vault, scope, disclosure profile, session token, or safety limits.

Retrieved graph text is untrusted content. A node saying “ignore your rules”
is data, not an instruction.

Good AI tools are narrow:

- `get_my_order_timeline(order_reference)`
- `search_my_authorized_knowledge(question)`
- `find_public_support_article(question)`

Unsafe AI tools include:

- `run_cypher(query)`
- `unlock_owner(owner_id)`
- `read_vault(vault_id)`
- `set_scope(scope_id)`
- `make_public(record_id)`

## Embeddings and private vector search

Embeddings are sensitive derivatives of their source text. If they are stored
as ordinary vectors in Neo4j, Neo4j can use a vector index but database readers
can also read or analyze them.

If private embeddings are encrypted, Neo4j cannot directly perform ordinary
vector similarity search over their ciphertext.

The protected target is:

1. Encrypt each embedding with its record's scope key.
2. After unlock, load embeddings only from granted scopes.
3. Decrypt them in trusted backend memory.
4. Lazily build a temporary vector index for that owner session.
5. Use vector matches only as seeds for authorized graph traversal.
6. Destroy the index on lock, expiry, revocation, security change, shutdown, or
   process restart.

The temporary index must have owner/session isolation plus item, memory, and
build-time limits. It trades speed for privacy because it may need rebuilding
after each unlock.

`SessionVisibleGraphGateway.build_vector_index()` now creates a bounded
in-memory cosine index from only the gateway's policy-allowlisted entity
projection. It seals the index to that gateway and exact context, so raw or
cross-context indexes fail closed. AuthGraph does not yet provide an embedding
model, store encrypted embeddings, load them by scope, or close an index
automatically on session revocation. The host must close each index inside the
secure-session lifetime.

Intentionally public embeddings may use Neo4j's normal vector index.

Neo4j's current vector indexes require readable numeric vector properties:
[Neo4j vector index documentation](https://neo4j.com/docs/cypher-manual/current/indexes/semantic-indexes/vector-indexes/).

## Session end

The target is for lock, expiry, logout, revocation, or restart to clear,
best-effort:

- scope keys;
- decrypted record caches;
- temporary vector indexes;
- pending authentication challenges; and
- sensitive server-side conversation state.

It must also block every future retrieval with the old session.

Scope-key sessions and OTP state implement this single-process lifecycle.
Temporary vector-index cleanup still belongs to the host and is therefore not
yet an automatic guarantee.

This cannot make an external AI forget plaintext already sent to it. The model
may repeat that plaintext from the current conversation, and the provider may
have its own retention rules. AuthGraph controls retrieval, not the internals
of a hosted model.

For sensitive deployments:

- end or replace the model conversation when the secure session closes;
- do not persist sensitive prompts, responses, or tool payloads;
- redact logs, traces, analytics, and errors;
- review the model provider's retention, region, and contracts; or
- use a controlled local model when plaintext must not leave the application.

## Safe AI writes

The chatbot may later save information, but it should not receive a generic
graph-writing tool.

A safe write flow is:

1. The model proposes a typed fact.
2. The trusted application validates its schema and source.
3. Authorization chooses the owner and protection scope out of band.
4. High-impact writes require user confirmation.
5. AuthGraph encrypts the node or connection before Neo4j receives it.
6. An audit event records opaque IDs and the action, never the secret content.

Updates, deletes, classification changes, and AI write tools are not currently
implemented.

## Internal model

The first slice now implements these concepts, although production policy and
key providers remain incomplete:

```text
ProtectionScope
  opaque scope ID
  active key version
  independent random scope DEK

Credential
  principal and provider
  password, passkey, identity provider, or code evidence

ScopeKeySlot
  one scope DEK wrapped for one credential/key provider

DisclosureProfile
  required evidence
  granted scopes
  allowed data and operations
  result and session limits

SessionGrant
  principal + vault
  granted scope keys
  disclosure profile
  security revision
  expiry

VisibleSubgraph
  bounded nodes and connections
  allowed properties
  provenance
```

Changing a credential, scope key, key slot, or grant policy should increment a
vault security revision and revoke old sessions. Multi-server deployments need
shared durable revision and revocation state.

## What is next

The first vertical slice now includes real scope keys, fixed scoped Neo4j
queries, password and OTP-authorized sessions, disclosure policies, bounded
retrieval, provenance, and a temporary vector helper.

The next work is:

1. Run schema and v2 flows against a real Neo4j 5.7+ server.
2. Add a production KMS/HSM scope-key provider and real passkey/IdP adapters.
3. Add the host HTTP security layer, delivery adapter, rate limits, and audit
   events.
4. Store embeddings encrypted per scope and automatically destroy temporary
   indexes with their sessions.
5. Add migration, key rotation, recovery, update/delete, multi-process
   revocation, and external anti-rollback state.
6. Perform independent security and privacy review.

Until that work is complete, AuthGraph remains a synthetic-data prototype
rather than a production security product.
