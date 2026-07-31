# AuthGraph for chatbots and GraphRAG

This is the target design. It is not all implemented yet.

The goal is simple:

> A chatbot can use public knowledge plus only the protected knowledge granted
> to the current session. Everything else stays absent and encrypted.

## Status

| Capability | Status |
|---|---|
| Public nodes and connections | Available |
| Encrypted private nodes and connections | Available |
| One owner vault per secure session | Available |
| Session TTL, lock, revocation, and process-restart lock | Available in one process |
| Public-only and public-plus-one-owner views | Available for small graphs |
| Model-safe targeted GraphRAG retriever | Planned |
| Configurable disclosure profiles | Planned |
| Separate keys for named private protection scopes | Planned |
| Password, passkey, identity-provider, and code provider interface | Planned |
| Email code delivery | Planned host integration |
| Encrypted embeddings with a temporary session index | Planned |
| Production web authentication, auditing, and multi-server sessions | Planned |

Current AuthGraph has one encryption key for a complete owner vault. Once that
vault is unlocked, the trusted backend can technically decrypt every private
record in it. It may return fewer records, but that is filtering rather than a
cryptographic boundary.

The target design fixes this with separate **protection scopes**.

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

One Neo4j database may hold many owners. Each owner has one vault. A vault may
contain several private protection scopes:

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

These names are configuration labels. Neo4j should store opaque scope IDs so a
database reader does not learn that a scope is called `medical` or
`private_notes`.

Every private scope gets its own random 256-bit data-encryption key. Every
private node and connection is assigned to exactly one scope and encrypted
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

This format is illustrative; it is not a supported configuration file yet.

The policy may require one factor, every factor in `all_of`, or an approved
choice in `any_of`. This is authentication policy, not threshold cryptography.
The trusted backend evaluates it. The AI cannot weaken or replace it.

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

The current password design can be extended to scopes:

1. Derive a key-encryption key from the password with Argon2id.
2. Use it to unwrap only the scope keys granted by policy.
3. Put those scope keys in the server-side session.
4. Clear temporary password and key buffers best-effort.

The password must go to a dedicated secure endpoint or form. It must never be
entered into chatbot text, sent to the model, or included in model tool
arguments.

## One-time codes and email

A short code must never be used directly as an encryption key. Six or eight
digits can be guessed and do not contain enough entropy to protect stored
data.

The safe pattern is:

1. The user already has an application session.
2. The host asks AuthGraph to begin a challenge for a fixed disclosure policy.
3. The address comes from a previously verified account record, not chat text.
4. A cryptographically random, short-lived, single-use code is generated.
5. Only a protected verifier is stored, bound to the principal, policy,
   browser transaction, expiry, and challenge.
6. The host application's mail adapter sends the code.
7. A secure form submits the code directly to the verifier.
8. Rate limits and attempt limits are enforced and consumption is atomic.
9. Successful verification authorizes a trusted KMS/key service to unwrap only
   the permitted scope keys.
10. AuthGraph creates an opaque, short-lived session grant.

The code authorizes key release; it does not mathematically derive the key.
This requires a server/KMS-controlled key wrap in addition to a password wrap.
If a key is protected only by the current password envelope, an email code
cannot decrypt it.

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

A future `SessionVisibleGraphGateway` should combine:

```text
allowed public records
        +
records encrypted by scope keys in this session
        -
disallowed kinds and properties
        -
records outside count, byte, token, hop, and time limits
```

Every disclosure profile can configure:

- granted protection scopes;
- allowed operations;
- allowed node and connection kinds;
- property allowlists and redaction;
- maximum search candidates;
- maximum returned nodes and connections;
- maximum traversal depth;
- maximum plaintext bytes and estimated model tokens;
- maximum retrieval time;
- session lifetime; and
- whether full authorized-scope access is allowed at all.

Two useful modes are:

- `targeted`: return only a small subgraph relevant to one question;
- `full_authorized_scopes`: expose all records in the granted scopes, within
  hard limits, for deliberate small-graph tests.

`targeted` should be the production default.

## GraphRAG request flow

```text
Question
   |
   v
Fixed AI tool: search_my_authorized_knowledge
   |
   v
Attach the server-side session grant
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

The protected option is:

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

Intentionally public embeddings may use Neo4j's normal vector index.

Neo4j's current vector indexes require readable numeric vector properties:
[Neo4j vector index documentation](https://neo4j.com/docs/cypher-manual/current/indexes/semantic-indexes/vector-indexes/).

## Session end

Lock, expiry, logout, revocation, or restart must clear, best-effort:

- scope keys;
- decrypted record caches;
- temporary vector indexes;
- pending authentication challenges; and
- sensitive server-side conversation state.

It must also block every future retrieval with the old session.

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

## Proposed internal model

The following names describe the intended architecture, not today's Python
API:

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

## Build order

### 1. Model-safe retrieval over the current vault key

- Add disclosure profiles.
- Add the session-visible graph gateway.
- Add fixed, targeted, bounded retrieval.
- Remove full-vault snapshots from model-selectable paths.

This improves disclosure control but is not cryptographic scope isolation.

### 2. Real protection scopes

- Add independent scope keys and key slots.
- Add scope-aware authenticated encryption and fixed Neo4j queries.
- Store only opaque scope IDs.
- Change sessions from one vault key to a map of granted scope keys.
- Add a migration path for existing vaults.

### 3. Pluggable unlock evidence

- Add provider, challenge, evidence, and grant-policy interfaces.
- Keep passwords and codes out of chat.
- Add passphrase unlock for selected scopes.
- Add KMS-backed passkey/identity-provider integrations.
- Add optional lower-assurance email confirmation through a host mail adapter.

### 4. GraphRAG

- Add targeted text/graph retrieval.
- Add bounded traversal, field redaction, provenance, and prompt budgets.
- Add optional encrypted embeddings and temporary private indexes.
- Add prompt-injection and cross-owner isolation tests.

### 5. Production hardening

- Live Neo4j integration and migration tests
- Multi-process sessions, revision fencing, and revocation
- Rate limiting and replay-safe challenge storage
- Structured security audit events
- Key rotation, recovery, backup, and deletion workflows
- Independent security and privacy review

Until these milestones are complete, AuthGraph remains a synthetic-data
prototype rather than a production security product.
