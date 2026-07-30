# AuthGraph

AuthGraph is a proof-of-concept security layer for an owner-scoped Neo4j
knowledge graph. An owner can be any person, customer, user, account, or
tenant. It deliberately does **not** contain a chatbot.

A vault is a logically isolated subgraph inside one Neo4j database—not a
separate Neo4j installation or database for every owner.

The central rule is:

> Passwords and decryption keys belong to a trusted broker, never to an AI.

AuthGraph does not impose a business schema. A vault may contain purchases,
preferences, documents, support history, private notes, financial records,
health records, or any other owner-linked entities and relationships. The
integrating application decides what those records mean.

## What this prototype does

- Gives each owner one or more opaque vaults.
- Generates a random 256-bit data-encryption key (DEK) for each vault.
- Derives a key-encryption key from the vault passphrase with Argon2id.
- Wraps the random DEK with AES-256-GCM, so changing a passphrase does not
  require re-encrypting every graph record.
- Authenticates a monotonically increasing envelope revision and replaces
  passphrase envelopes with compare-and-swap, fencing stale concurrent unlocks
  in the single-process broker.
- Encrypts `PRIVATE` entity types, relationship types, and their properties
  with AES-256-GCM before they reach Neo4j. `PUBLIC` layered records are an
  explicit plaintext exception described below.
- Binds every ciphertext to its vault and object IDs with authenticated
  associated data, so copied or altered ciphertext fails closed.
- Keeps an unlocked DEK only in a short-lived in-memory session. Every
  operation checks expiry before receiving a temporary key lease, and a
  background sweeper removes expired resident keys by default.
- Exposes only fixed, parameterized, principal- and vault-scoped repository
  operations. There is no arbitrary Cypher entry point.
- Provides an explicit, bounded `get_vault_snapshot` operation for controlled
  full-vault workflows. It returns the complete small vault or fails rather
  than silently omitting records.
- Provides an additive layered-graph API in which each new entity and
  relationship inherits a configurable `PUBLIC` or `PRIVATE` default and may,
  when policy permits, override that choice per record.
- Returns only the public base graph while locked. An unlocked view composes
  that base with exactly one owner-scoped encrypted overlay.
- Uses generic Neo4j labels (`AGVault`, `AGEntity`) and a generic relationship
  type (`AG_LINK`) to reduce semantic metadata leakage.

## What is and is not possible

The requested design needs one important correction:

- The AI must **not** ask for a password in ordinary chat. A secure form or
  authentication screen must send it directly to the trusted key broker over
  TLS, outside chat history, model input, logs, analytics, and tracing.
- The whole graph should not routinely become "decrypted for the AI." Narrow,
  task-specific retrieval is safer. This prototype nevertheless includes an
  explicit full-vault snapshot operation for testing the requested workflow;
  it is owner-scoped, bounded, and deliberately treated as high exposure.
- If an LLM must reason over a protected fact, that LLM necessarily receives
  that fact as plaintext. Encryption cannot make a model both use and not see
  the same value. Keeping all sensitive plaintext away from an external model
  requires a trusted local/on-premises model or deterministic application
  responses.

Neo4j sees opaque IDs, ciphertext, counts, access timing, and the generic graph
shape. It does not see the encrypted semantic types or values. Hiding even the
topology while retaining normal server-side graph traversal is not generally
possible.

## Architecture

```text
Authenticated browser
        |
        | password through a dedicated secure form (never chat)
        v
Trusted key/session broker ---- short-lived in-memory vault DEK
        |
        | fixed, identity-bound operation
        v
Encrypted graph repository ---- Neo4j stores ciphertext + opaque IDs
        |
        | authorized bounded result, decrypted transiently
        v
Future retrieval policy -------- optional LLM receives selected plaintext only
```

The bearer session capability must be placed in a `Secure`, `HttpOnly`,
appropriately `SameSite` cookie by a future web backend. It must not appear in
an AI prompt or be accepted as an AI tool argument.

## Dynamic public and private records

`LayeredGraphService` adds the mixed model without weakening the original
encrypted-vault API:

```text
Public base graph                Owner overlay
----------------------------     ----------------------------------
AGPublicEntity                   AGEntity
AG_PUBLIC_LINK                   AG_LINK
plaintext kind + properties      encrypted kind + properties
available while locked           requires the owner's live session
```

`GraphPolicy` controls the defaults independently for entities and
relationships. Both defaults are `ProtectionLevel.PRIVATE`. When
`allow_public_overrides` is enabled, a trusted application can explicitly
choose `ProtectionLevel.PUBLIC` or `ProtectionLevel.PRIVATE` for each new
record. Tightening a public default to private is always permitted. Different
named graphs can receive different policies.

This is the important meaning of `PUBLIC`: the semantic kind and properties
are plaintext at AuthGraph's application-encryption layer. They are still
protected operationally by Neo4j authentication, authorization, TLS, disk
encryption, and backup controls, but a database reader can see them. Never mark
personal or confidential data public merely to avoid asking for an unlock.

While locked, `get_public_view()` does not fetch, decrypt, count, or return any
private record. Policy may optionally return
`LockedDisclosure.GENERIC_BADGE`; that value is identical for an empty and
populated overlay, so it is not a private-record existence oracle. Per-record
placeholders are deliberately not supported because they leak private counts
and graph shape. `get_unlocked_view()` is the separate high-exposure operation
that requires a live owner context and composes the encrypted overlay.
Public snapshots also fail rather than truncate above 100 entities, 200
relationships, or 256 KiB of aggregate semantic JSON by default.

An encrypted relationship may join private entities and/or public entities.
For a public endpoint, AuthGraph creates an opaque encrypted anchor inside the
owner's vault. The public ID and the relationship meaning remain inside
ciphertext and are resolved only in trusted memory after unlock. A public
relationship is allowed only when both endpoints are public. Consequently, a
locked view never contains a dangling edge to a hidden node.

One unlocked view accepts one `AccessContext`, so Benjamin's session composes
only Benjamin's overlay; it cannot retrieve Alexa's overlay. The trusted
identity path is `authenticated person -> authorized opaque vault ID -> unlock
-> AccessContext -> get_unlocked_view()`. That mapping belongs in an identity
or control-plane store, not in public Neo4j properties. A person's name is a
claim or display value, not proof of identity.

The current layered API classifies records when they are created. It does not
yet reclassify an existing record. Publishing previously private data is an
irreversible disclosure to clients, logs, transaction history, and backups;
privatizing previously public data cannot recall those copies. A future
reclassification workflow therefore needs an explicit authenticated,
auditable, atomic migration rather than a mutable `encrypted=false` flag.

Public mutation methods require both an explicit policy opt-in and an
application-supplied publisher context accepted by
`public_write_authorizer`. Public means readable without the owner's vault
password, not writable by anyone. `graph_id` is a scope, not authorization and
not a secret. Do not expose publisher contexts or generic create/connect
operations to a chatbot. The integrating application must authorize
administrators and data owners before invoking them.

Policies are startup configuration in this prototype: they are not yet
persisted, revisioned, or audited, and changing a policy affects only future
writes and the generic badge. The unlocked composer currently decrypts one
bounded whole-vault snapshot before filtering its layered wrappers. Prefer one
layered graph per vault for this test version. Each encrypted connection to a
public endpoint also creates an encrypted helper anchor. AuthGraph creates the
new anchors and their relationship in one atomic repository operation, so a
failed write leaves neither. Successful connections can still create duplicate
anchors, and anchors count toward the private snapshot limit. Production needs
a deduplicated external-reference design.

## Full-vault snapshot mode

`AuthGraphService.get_vault_snapshot()` is the explicit opt-in boundary for a
small-vault chatbot experiment. The repository fetches ciphertext under the
authenticated principal, vault, and envelope revision while serializing
against cooperative Neo4j writes. The service authenticates and decrypts the
result only while holding a guarded session-key lease.

The default hard ceilings are 100 entities, 200 relationships, and 256 KiB of
aggregate ciphertext. The operation probes one row past the requested count
limits and fails if the complete vault does not fit; it never returns a
silently truncated graph. AuthGraph does not cache the returned plaintext.
The caller owns that plaintext object and must not write it to logs,
transcripts, traces, caches, or durable model conversations.

“Complete” means every well-formed row visible to the scoped query. AES-GCM
does not prove that a hostile storage administrator did not delete a row or
remove the metadata/ownership edge that makes it query-visible. Strong
completeness needs an authenticated inventory or external transparency record,
which this prototype does not implement.

This mode does not make an external AI private: sending the snapshot to a
hosted model reveals every included field to that provider. Python also cannot
guarantee erasure of immutable strings after use. Use only synthetic data in
the test harness, and prefer narrow retrieval or a suitably governed local
model for real sensitive information.

## Storage model

```text
(AGVault)-[:AG_OWNS]->(AGEntity)-[:AG_LINK]->(AGEntity)

(AGPublicGraph)-[:AG_PUBLIC_OWNS]->(AGPublicEntity)
     (AGPublicEntity)-[:AG_PUBLIC_LINK]->(AGPublicEntity)
```

The meaningful entity kind, relationship kind, and all semantic properties are
inside authenticated ciphertext for `AGEntity` and `AG_LINK`. Records under
`AGPublicEntity` and `AG_PUBLIC_LINK` are intentionally plaintext. The
plaintext `principal_id`, `vault_id`, and public `graph_id` must be opaque
application identifiers—not a name, email address, government identifier,
customer number, account number, or other PII.

Apply [neo4j/schema.cypher](neo4j/schema.cypher) before using the Neo4j
repository. The Python driver must use encrypted transport (`neo4j+s` for Aura)
and a least-privilege database account. The schema requires Neo4j 5.7 or newer;
verify it after application with `SHOW CONSTRAINTS` rather than trusting
`IF NOT EXISTS` silently. No other writer should be able to create malformed
`AGVault`, `AGEntity`, or `AG_LINK` records.

The included session broker is intentionally single-process. Multiple
application replicas need one hardened shared broker, or distributed
revision/revocation coordination, before they can safely unlock the same
vault. Merely running one in-memory broker per replica leaves a stale-unlock
window during password changes. The broker's default one-second expired-key
sweeper limits post-expiry memory residency; graceful shutdown must call
`close_all()` (or exit its context manager) to stop new work, drain guarded
operations, and clear resident keys. Unexpected sweeper failure closes the
broker and is exposed through its `sweeper_failed` health flag.

Changing only the passphrase is not recovery from a stolen DEK: it re-wraps
the same DEK. If a passphrase, old envelope, or DEK may have been compromised,
production must rotate the DEK and re-encrypt the vault; that workflow is not
implemented here.

## Run the tests

No Neo4j server is needed for the security unit tests:

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The tests use deliberately weak Argon2id parameters for speed and require an
explicit `allow_insecure_kdf_for_testing=True` switch. Normal construction uses
64 MiB, three iterations, and refuses parameters below AuthGraph's production
safety floor.

## Security status

This is an architectural proof of concept using synthetic data. It is **not**
production-ready, audited, certified, or automatically compliant with GDPR,
HIPAA, PCI DSS, or any other legal or industry regime. It is a security
component, not an authoritative system of record.

The Neo4j adapter and Cypher have been reviewed statically but have not been
run against a live Neo4j instance in this workspace. The unit tests use a
ciphertext-only private repository, a separate intentionally plaintext public
repository, and recording drivers; a real two-vault layered integration suite
is still required.

Before real sensitive data is used, at minimum add:

- external identity, MFA/passkeys, rate limiting, and lockout protections;
- a hardened isolated key broker or HSM/KMS-backed key handles;
- a governed recovery and delegated-access/key-sharing design;
- secure-cookie and CSRF protections;
- immutable metadata-only audit events with sensitive-data/password redaction;
- backups and restore drills for ciphertext and key envelopes;
- a trusted anti-rollback revision outside the Neo4j/backup rollback domain;
- key rotation, delegated grant/revoke, and break-glass workflows;
- request-level idempotency and transient-driver-retry tests;
- database RBAC/PBAC as defense in depth;
- independent cryptographic, application-security, privacy, and compliance
  review; and
- adversarial tests covering every query, export, search, log, error, and AI
  integration path.

Read [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the trust boundaries,
leakage profile, session flow, and future AI integration contract.
