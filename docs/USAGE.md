# Using AuthGraph

This guide documents the code that exists today. It covers the original
whole-vault API and the first scoped-encryption, OTP, and GraphRAG slice.

> AuthGraph is an early prototype. Use synthetic data only.

## What you need

- Python 3.11 or newer
- Neo4j 5.7 or newer
- An encrypted Neo4j connection
- A Neo4j account limited to the AuthGraph database

Neo4j may be a managed service such as Aura or a server you operate. AuthGraph
does not install or start Neo4j.

AuthGraph is a Python library. It currently has no `authgraph` command, web
server, login page, chatbot, email sender, or admin panel.

## Install

From the repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
```

For local development, use an editable install:

```bash
python3 -m pip install -e .
```

## Prepare Neo4j

Run [neo4j/schema.cypher](../neo4j/schema.cypher) once against the database.
For example, `cypher-shell` can prompt for the password:

```bash
cypher-shell -a neo4j+s://YOUR_HOST -u YOUR_USER \
  -d YOUR_DATABASE -f neo4j/schema.cypher
```

Then verify that the expected constraints exist:

```cypher
SHOW CONSTRAINTS;
```

Use `neo4j+s://` with a CA-signed certificate. `neo4j+ssc://` also encrypts
traffic but accepts a self-signed certificate and should be used only when that
choice is deliberate.

## Create the services

```python
from neo4j import GraphDatabase

from authgraph import (
    AuthGraphService,
    CryptoEngine,
    GraphPolicy,
    InMemorySessionBroker,
    LayeredGraphService,
    Neo4jGraphRepository,
    Neo4jPublicGraphRepository,
)

driver = GraphDatabase.driver(
    "neo4j+s://YOUR_HOST",
    auth=("YOUR_USER", "YOUR_NEO4J_PASSWORD"),
)
driver.verify_connectivity()

private_repository = Neo4jGraphRepository(driver, database="YOUR_DATABASE")
public_repository = Neo4jPublicGraphRepository(
    driver,
    database="YOUR_DATABASE",
)
sessions = InMemorySessionBroker(
    default_ttl_seconds=300,
    max_ttl_seconds=1800,
)
protected = AuthGraphService(
    private_repository,
    CryptoEngine(),
    sessions,
)
```

`LayeredGraphService` combines a readable public graph with encrypted owner
overlays. Public writes require an authorization decision from your
application. This small example uses a server-only capability:

```python
authorized_publisher = object()

def may_publish(publisher, graph_id):
    return (
        publisher is authorized_publisher
        and graph_id == "support-graph"
    )

graph = LayeredGraphService(
    protected,
    public_repository,
    default_policy=GraphPolicy(allow_public_overrides=True),
    public_write_authorizer=may_publish,
)
```

Do not send `authorized_publisher` to a browser or AI. In a real application,
the authorizer would normally inspect a trusted staff or service identity.

## Choose a private format

AuthGraph currently keeps two private formats separate:

| Format | Service | Encryption boundary |
|---|---|---|
| Legacy v1 | `AuthGraphService` | One key unlocks the whole owner vault |
| Scoped v2 | `ScopedAuthGraphService` | Every protection scope has an independent key |

Use scoped v2 for new scope-isolation experiments. Existing v1 records are not
automatically migrated to v2.

Create the scoped service with the scoped Neo4j adapter:

```python
from authgraph import (
    CryptoEngine,
    Neo4jScopedGraphRepository,
    ScopedAuthGraphService,
    ScopedSessionBroker,
)

scoped_repository = Neo4jScopedGraphRepository(
    driver,
    database="YOUR_DATABASE",
)
scoped_sessions = ScopedSessionBroker(
    default_ttl_seconds=300,
    max_ttl_seconds=1800,
)
scoped = ScopedAuthGraphService(
    scoped_repository,
    CryptoEngine(),
    scoped_sessions,
)
```

Do not use `Neo4jGraphRepository` with `ScopedAuthGraphService`.

## Create an owner vault

Your login system first authenticates a person. It then gives AuthGraph an
opaque identity-provider subject:

```python
principal_id = "idp|opaque-subject-7f921"
passphrase = bytearray(b"a long synthetic test passphrase")

try:
    vault_id = protected.create_vault(principal_id, passphrase)
finally:
    passphrase[:] = b"\x00" * len(passphrase)
```

Keep the returned `vault_id` in your trusted account store. Do not use a name,
email, customer number, or other personal information as `principal_id` or
`vault_id`.

A new passphrase must contain at least 15 UTF-8 bytes. A strong, unique
passphrase is still required because a stolen key envelope can be attacked
offline.

## Unlock and lock

Collect the passphrase in a dedicated secure form, not in chatbot text:

```python
passphrase = bytearray(b"a long synthetic test passphrase")

try:
    context = protected.unlock(
        principal_id,
        vault_id,
        passphrase,
        ttl_seconds=300,
    )
finally:
    passphrase[:] = b"\x00" * len(passphrase)
```

`context` is an opaque bearer capability. Keep it on the server. Never send it
to an AI, put it in a URL, or log it.

Lock explicitly when the protected interaction ends:

```python
protected.lock(context)
```

The context also stops working after its TTL, revocation, passphrase change,
broker shutdown, or process restart.

## Create nodes

Private is the default:

```python
from authgraph import ProtectionLevel

private_order = graph.create_entity(
    "support-graph",
    "Order",
    {
        "order_number": "ORDER-1001",
        "status": "delayed",
    },
    context=context,
)
```

AuthGraph encrypts the node kind and properties before the private repository
writes them to Neo4j.

Create an intentionally public node only when the graph policy permits it and
the trusted publisher is authorized:

```python
public_product = graph.create_entity(
    "support-graph",
    "Product",
    {"name": "Example Headphones"},
    protection=ProtectionLevel.PUBLIC,
    publisher=authorized_publisher,
)
```

Public kinds and properties are plaintext at AuthGraph's application layer.
Neo4j access control, TLS, disk encryption, and backup security are still
required.

## Create connections

`create_entity()` returns a `GraphEntityRef`. Use those references to connect
nodes:

```python
private_connection = graph.connect(
    "support-graph",
    private_order,
    public_product,
    "CONTAINS",
    {"quantity": 1},
    context=context,
    protection=ProtectionLevel.PRIVATE,
)
```

A private connection may join private nodes, or it may use encrypted anchors
to public nodes. A public connection is allowed only between two public nodes:

```python
another_public_product = graph.create_entity(
    "support-graph",
    "Product",
    {"name": "Example Case"},
    protection=ProtectionLevel.PUBLIC,
    publisher=authorized_publisher,
)

public_connection = graph.connect(
    "support-graph",
    public_product,
    another_public_product,
    "RELATED_TO",
    {},
    protection=ProtectionLevel.PUBLIC,
    publisher=authorized_publisher,
)
```

## Read graph views

The locked view reads only the public repository:

```python
locked_view = graph.get_public_view("support-graph")
```

The unlocked view adds private records from exactly the vault represented by
`context`:

```python
unlocked_view = graph.get_unlocked_view(
    "support-graph",
    context,
)
```

The result contains:

- `graph_id`
- `entities`
- `relationships`
- `private_overlay_included`
- `locked_disclosure`

Each returned entity and relationship says whether it was `PUBLIC` or
`PRIVATE`.

Important: the current unlocked layered view first decrypts one bounded vault
snapshot in the trusted Python process and then filters it by `graph_id`.
It is suitable for small tests, not as a production chatbot retriever.

## Use the encrypted vault API directly

`AuthGraphService` can be used without the public layer:

```python
person_id = protected.create_entity(
    context,
    "Person",
    {"display_name": "Synthetic Person"},
)
order_id = protected.create_entity(
    context,
    "Order",
    {"status": "processing"},
)
relationship_id = protected.connect(
    context,
    person_id,
    order_id,
    "PLACED",
    {"source": "test"},
)

person = protected.get_entity(context, person_id)
nearby = protected.get_neighborhood(context, person_id, limit=25)
snapshot = protected.get_vault_snapshot(
    context,
    entity_limit=100,
    relationship_limit=200,
)
```

`get_vault_snapshot()` deliberately returns a complete small vault as
caller-owned plaintext. Do not log, cache, or pass it to a model unless
exposing the complete vault is the intended result.

## Use scoped encryption

Create a v2 vault and its independent protection scopes. Scope IDs are opaque;
keep the meaning of each scope in trusted application configuration.

```python
principal_id = "idp|opaque-subject-7f921"
passphrase = bytearray(b"a long synthetic test passphrase")

try:
    vault_id = scoped.create_vault(principal_id, passphrase)
    profile_scope = scoped.create_protection_scope(
        principal_id,
        vault_id,
        passphrase,
    )
    orders_scope = scoped.create_protection_scope(
        principal_id,
        vault_id,
        passphrase,
    )
finally:
    passphrase[:] = b"\x00" * len(passphrase)
```

Your trusted application policy chooses the scope IDs. The model and browser
must not choose them. `ScopedAuthGraphService.unlock()` validates the tuple but
does not decide which scopes a user should receive; that authorization check
belongs to the backend before this call.

Unlock exactly those scopes:

```python
passphrase = bytearray(b"a long synthetic test passphrase")

try:
    context = scoped.unlock(
        principal_id,
        vault_id,
        passphrase,
        (profile_scope, orders_scope),
        ttl_seconds=300,
    )
finally:
    passphrase[:] = b"\x00" * len(passphrase)
```

Create scoped nodes and a scoped connection:

```python
profile_id = scoped.create_entity(
    context,
    profile_scope,
    "Profile",
    {"display_name": "Synthetic Person"},
)
order_id = scoped.create_entity(
    context,
    orders_scope,
    "Order",
    {"reference": "ORDER-1001", "status": "delayed"},
)
placed_id = scoped.connect(
    context,
    orders_scope,
    profile_id,
    order_id,
    "PLACED",
    {},
)
```

The connection has its own scope. It is returned only if the session has the
connection scope and both endpoint scopes.

Read one node or a bounded complete view of only the granted scopes:

```python
order = scoped.get_entity(context, order_id)
visible = scoped.get_vault_snapshot(
    context,
    entity_limit=100,
    relationship_limit=200,
)
scoped.lock(context)
```

`ScopedVaultSnapshot` contains plaintext owned by your caller. Do not cache or
log it. A session holding only `orders_scope` cannot read `profile_scope`, and
no session can read another owner's scopes.

## Unlock scoped data with a one-time code

The included OTP path is a security flow, not an email service:

```text
issue code -> your app delivers it -> verify once -> fixed scope grant
           -> trusted key provider releases those scope keys -> session
```

The code never derives or decrypts a key. It only authorizes a provider. The
included `InMemoryScopeKeyProvider` is for synthetic, single-process tests; use
a real KMS/HSM-backed provider in production.

First enroll selected scope keys into the test provider. This is an
administrative operation that requires the vault passphrase:

```python
from authgraph import (
    InMemoryOneTimeCodeBroker,
    InMemoryScopeKeyProvider,
    ScopeGrantPolicy,
    UnlockProfile,
)

key_provider = InMemoryScopeKeyProvider()
passphrase = bytearray(b"a long synthetic test passphrase")

try:
    scoped.enroll_key_release_provider(
        principal_id,
        vault_id,
        passphrase,
        (orders_scope,),
        key_provider,
    )
finally:
    passphrase[:] = b"\x00" * len(passphrase)
```

Configure a server-owned profile. The user and AI cannot change its scope set:

```python
profile = UnlockProfile(
    profile_id="order-support",
    scope_ids=(orders_scope,),
    session_ttl_seconds=180,
    allow_one_time_code=True,
)
grant_policy = ScopeGrantPolicy({profile.profile_id: profile})
otp = InMemoryOneTimeCodeBroker(
    ttl_seconds=300,
    max_attempts=5,
)
```

Issue from a trusted HTTP endpoint after the application knows the
authenticated principal, vault, browser transaction, and pre-verified delivery
destination:

```python
client_binding = "opaque-browser-transaction"
epoch = scoped.get_authorization_epoch(principal_id, vault_id)
issued = otp.issue(
    principal_id,
    profile.profile_id,
    client_binding,
    authorization_context=vault_id,
    authorization_epoch=epoch,
)

try:
    deliver_to_preverified_destination(memoryview(issued.code))
finally:
    issued.clear_code()
```

`deliver_to_preverified_destination()` is your code. AuthGraph does not accept
an email address or send mail. Its adapter should accept the mutable view where
possible; any immutable copy it creates cannot be wiped by AuthGraph. Add rate
limits around issuance.

Verify the submitted code in a secure form endpoint, not chatbot text:

```python
evidence = otp.verify(
    issued.challenge_id,
    submitted_code,
    principal_id=principal_id,
    profile_id=profile.profile_id,
    client_binding=client_binding,
)
grant = grant_policy.authorize_one_time_code(
    evidence,
    vault_id=vault_id,
    evidence_consumer=otp,
)
context = scoped.unlock_with_provider(
    grant,
    grant_policy,
    key_provider,
)
```

Challenges, evidence, and grants are short-lived and single-use. They are
bound to the current vault authorization epoch, so a password change rejects
older grants. Restarting the process loses the in-memory OTP and test-provider
state.

Remove test-provider release capability when access is revoked:

```python
key_provider.revoke_scope_keys(
    principal_id,
    vault_id,
    (orders_scope,),
)
# Or remove every enrolled scope for this vault:
key_provider.revoke_vault(principal_id, vault_id)
```

This blocks future provider unlocks. It does not recall plaintext already sent
to a caller or model.

At shutdown:

```python
otp.close()
grant_policy.close()
key_provider.close()
scoped_sessions.close_all()
driver.close()
```

## Change a passphrase

```python
old_passphrase = bytearray(b"a long synthetic test passphrase")
new_passphrase = bytearray(b"a different long synthetic passphrase")

try:
    protected.change_passphrase(
        principal_id,
        vault_id,
        old_passphrase,
        new_passphrase,
    )
finally:
    old_passphrase[:] = b"\x00" * len(old_passphrase)
    new_passphrase[:] = b"\x00" * len(new_passphrase)
```

This re-wraps the same vault key and revokes existing local sessions. It does
not rotate the data-encryption key or re-encrypt records.

`ScopedAuthGraphService.change_passphrase()` has the same arguments. For a v2
vault it re-wraps the vault-wrapping key; independent scope keys and encrypted
records stay unchanged. Existing sessions and grants from the older
authorization epoch stop working. Previously enrolled provider slots can
still support a newly verified grant.

## Use the scoped GraphRAG gateway

The current scoped adapter first asks for a bounded complete snapshot of every
scope granted to the session and decrypts that snapshot in trusted memory.
The gateway then removes disallowed kinds and properties, ranks relevant
nodes, follows a bounded number of visible connections, and returns a smaller
result with provenance. This limits what reaches the model, but it is not yet a
targeted Neo4j read and the trusted process briefly handles the full granted
snapshot.

Create one server-owned disclosure policy:

```python
from authgraph import (
    DisclosurePolicy,
    ScopedGraphViewAdapter,
    SessionBoundRetrievalTool,
    SessionVisibleGraphGateway,
)

view = ScopedGraphViewAdapter(
    scoped,
    graph_id="support-graph",
)
disclosure = DisclosurePolicy(
    allowed_entity_kinds=frozenset({"Profile", "Order"}),
    allowed_relationship_kinds=frozenset({"PLACED"}),
    entity_property_allowlist={
        "Profile": frozenset({"display_name"}),
        "Order": frozenset({"reference", "status"}),
    },
    relationship_property_allowlist={
        "PLACED": frozenset(),
    },
    max_candidates=20,
    max_nodes=20,
    max_edges=30,
    max_hops=1,
    max_plaintext_bytes=32 * 1024,
    max_token_estimate=4 * 1024,
)
gateway = SessionVisibleGraphGateway(
    view,
    graph_id="support-graph",
    policy=disclosure,
)
```

Here `graph_id` is a logical label checked against the gateway. It does not
filter private scoped records. The protection-scope set already bound to
`context` is the private-data isolation boundary, and the adapter maps all
records in those granted scopes to this one logical graph.

Bind the security context outside the AI tool schema:

```python
tool = SessionBoundRetrievalTool(
    gateway,
    context=context,
)
result = tool.search("Where is my delayed order?")
model_payload = result.canonical_json_bytes()
```

Register only `tool.search(question)` with a model. Do not register
`gateway.retrieve()` directly: it also accepts trusted-only context and vector
arguments. The model must not receive `context`, owner/vault/scope IDs, safety
limits, or arbitrary Cypher.

`plaintext_bytes` is the exact size of `canonical_json_bytes()`.
`token_estimate` is only `ceil(bytes / 4)`, not a real model-token count.
Apply the selected model's tokenizer and final prompt budget before sending the
payload.

Optional vector seeds must be built through the gateway:

```python
with gateway.build_vector_index(
    dimension=1536,
    max_items=1000,
    context=context,
    entity_embedder=trusted_entity_embedder,
) as vectors:
    vector_tool = SessionBoundRetrievalTool(
        gateway,
        context=context,
        vector_index=vectors,
        query_embedder=trusted_query_embedder,
    )
    result = vector_tool.search("Find my delivery")
```

The entity embedder receives canonical JSON containing only an allowed kind
and its policy-allowlisted properties. Raw `EphemeralVectorIndex` instances
are rejected by the gateway; the built index is sealed to this gateway and
exact context. AuthGraph does not provide an embedding model or load encrypted
embeddings from Neo4j. Close the index before or when locking the session.
Automatic vector-index cleanup is not implemented.

## Configure public and private defaults

The secure default is private nodes and private connections:

```python
GraphPolicy()
```

An application may configure a graph differently:

```python
from authgraph import GraphPolicy, LockedDisclosure, ProtectionLevel

policy = GraphPolicy(
    default_entity_protection=ProtectionLevel.PRIVATE,
    default_relationship_protection=ProtectionLevel.PRIVATE,
    allow_public_overrides=True,
    locked_disclosure=LockedDisclosure.HIDDEN,
)
```

`LockedDisclosure.GENERIC_BADGE` may show a fixed message that private data is
supported. It does not reveal whether private records actually exist.

Policies are copied into `LayeredGraphService` at startup. They are not stored
in Neo4j, versioned, or audited.

## Shut down safely

Reuse one Neo4j driver and one broker for the application process. At shutdown:

```python
sessions.close_all()
driver.close()
```

Using the broker as a context manager also calls `close_all()`:

```python
with InMemorySessionBroker() as sessions:
    ...
```

The current broker is for one Python process. It does not synchronize sessions
or revocation between application replicas.

## Test without Neo4j

The in-memory repositories are for tests:

```python
from authgraph import (
    CryptoEngine,
    InMemoryGraphRepository,
    InMemoryPublicGraphRepository,
    KdfParameters,
)
```

Run all unit tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The deliberately weak KDF helper is for tests only:

```python
crypto = CryptoEngine(
    KdfParameters.insecure_for_testing(),
    allow_insecure_kdf_for_testing=True,
)
```

Never enable that override for real vaults.

## Current API summary

| Object | Main operations |
|---|---|
| `AuthGraphService` | `create_vault`, `unlock`, `lock`, `change_passphrase`, `create_entity`, `get_entity`, `connect`, `create_relationship_bundle`, `get_neighborhood`, `get_vault_snapshot` |
| `ScopedAuthGraphService` | `create_vault`, `create_protection_scope`, `unlock`, `unlock_with_provider`, `lock`, `change_passphrase`, `create_entity`, `get_entity`, `connect`, `get_vault_snapshot`, provider enrollment and authorization epoch |
| `LayeredGraphService` | `get_policy`, `create_entity`, `connect`, `get_public_view`, `get_unlocked_view` |
| `InMemorySessionBroker` | `open`, `lease`, `close`, `revoke_vault`, `purge_expired`, `close_all`, health/count properties |
| `ScopedSessionBroker` | scoped session lifecycle and health/count properties |
| `InMemoryOneTimeCodeBroker` | `issue`, `verify`, `consume_evidence`, `purge_expired`, `close` |
| `ScopeGrantPolicy` | `authorize_one_time_code`, `consume`, `purge_expired`, `close` |
| Scope-key providers | `ScopeKeyEnrollmentProvider`, `ScopeKeyReleaseProvider`; in-memory test implementation |
| GraphRAG | `DisclosurePolicy`, `SessionVisibleGraphGateway`, `SessionBoundRetrievalTool`, `ScopedGraphViewAdapter`, `EphemeralVectorIndex` |
| Private repositories | `Neo4jGraphRepository`, `Neo4jScopedGraphRepository`, `InMemoryGraphRepository` |
| Public repositories | `Neo4jPublicGraphRepository`, `InMemoryPublicGraphRepository` |

`create_relationship_bundle()` and direct broker methods are low-level APIs
used by AuthGraph internals. Normal applications should prefer
`LayeredGraphService` and `AuthGraphService.unlock()`/`lock()`.

Expected application errors all inherit from `AuthGraphError`:

| Error | Meaning |
|---|---|
| `ValidationError` | Input or a configured limit is invalid |
| `ConflictError` | A generated opaque ID could not be committed |
| `UnlockDenied` | Unlock failed without revealing why |
| `SessionUnavailable` | Session is invalid, expired, revoked, or mismatched |
| `AuthorizationDenied` | The trusted application did not authorize an operation |
| `RecordNotFound` | Record is missing or outside the authorized vault |
| `IntegrityViolation` | Stored authenticated data or its context is inconsistent |
| `OneTimeCodeDenied` | Code verification or evidence consumption failed generically |
| `OneTimeCodeUnavailable` | In-memory challenge broker cannot accept work |
| `ScopeGrantDenied` | Evidence, grant, provider release, or grant lifetime was denied |

## Limits that matter

- Opaque IDs: at most 256 characters
- Entity and relationship kinds: at most 128 characters
- One encrypted payload, including kind and wrapper metadata: at most 64 KiB
  of JSON
- One public properties object: at most 64 KiB of JSON
- Neighborhood: at most 100 neighbors
- Complete vault or layered view: at most 100 entities and 200 relationships
  in each public/private snapshot
- Complete encrypted snapshot: at most 256 KiB of ciphertext
- Complete public snapshot: at most 256 KiB of semantic JSON
- Scoped session: at most 32 independent scope keys
- OTP: 6–10 digits, at most 10 attempts, and at most 15 minutes
- GraphRAG hard ceilings: 100 candidates, 100 nodes, 200 connections, 4 hops,
  256 KiB for the complete canonical result, and a 65,536 byte-based token
  estimate
- Temporary vector index: at most 10,000 items, 4,096 dimensions, and
  4,000,000 total numeric values
- Session TTL: configured by the broker and never more than 24 hours

Full reads fail instead of silently returning a partial graph.

## Features that do not exist yet

- Authentication, user registration, account recovery, passkeys, or a
  production MFA/identity-provider integration
- A web API, CLI, chatbot, or email/SMS delivery adapter
- A production KMS/HSM provider
- An embedding model, encrypted embedding store/loader, or automatic
  vector-index/session lifecycle
- Persistent policy configuration or security audit logs
- Update, delete, record reclassification, key rotation, migration, recovery,
  or shared access
- Multi-process session and revocation coordination
- A tested production deployment

See [CHATBOT_GRAPHRAG_DESIGN.md](CHATBOT_GRAPHRAG_DESIGN.md) for the remaining
path and [SECURITY_MODEL.md](SECURITY_MODEL.md) for the detailed threat model.
