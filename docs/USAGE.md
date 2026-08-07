# Using AuthGraph

This guide covers the API that new applications should use.

> AuthGraph is an early prototype. Use synthetic data only.

For a real deployment boundary and release gates, also read
[PRODUCTION_SETUP.md](PRODUCTION_SETUP.md).

## 1. Install

You need:

- Python 3.11 or newer
- Neo4j 5.7 or newer
- a TLS Neo4j address
- a schema account for setup
- a restricted runtime account for your application

Install from this repository:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
```

For local development:

```bash
python3 -m pip install -e .
```

AuthGraph does not install or start Neo4j.

## 2. Install or verify the Neo4j schema

Apply the packaged fixed schema:

```bash
authgraph schema apply \
  --uri neo4j+s://YOUR_HOST \
  --database YOUR_DATABASE \
  --username YOUR_SCHEMA_USER
```

The command prompts for the password. AuthGraph deliberately has no
`--password` argument because command-line arguments can be exposed by shell
history and process listings.

To read the password from a file:

```bash
authgraph schema apply \
  --uri neo4j+s://YOUR_HOST \
  --database YOUR_DATABASE \
  --username YOUR_SCHEMA_USER \
  --password-file /secure/path/neo4j-password \
  --no-input
```

On POSIX, the password file must be a regular file owned by the process user
with mode `0600`. Do not place it in the repository.

`schema apply` also runs fixed schema-metadata and data migrations. Before using
it on an existing database, take a tested backup, stop conflicting writers, and
test the upgrade against a copy. Verify without applying anything:

```bash
authgraph schema verify \
  --uri neo4j+s://YOUR_HOST \
  --database YOUR_DATABASE \
  --username YOUR_RUNTIME_USER
```

The same values can come from:

- `AUTHGRAPH_NEO4J_URI`
- `AUTHGRAPH_NEO4J_DATABASE`
- `AUTHGRAPH_NEO4J_USERNAME`
- `AUTHGRAPH_NEO4J_PASSWORD_FILE`

Only `neo4j+s://`, `neo4j+ssc://`, `bolt+s://`, and `bolt+ssc://` addresses are
accepted. Prefer `+s` with a CA-signed certificate. Use `+ssc` only when
accepting a self-signed certificate is deliberate.

The schema commands never create or drop a database. `schema verify` is
read-only.

## 3. Create the main service

```python
from neo4j import GraphDatabase

from authgraph import (
    AuthGraph,
    CryptoEngine,
    GraphPolicy,
    Neo4jPublicGraphRepository,
    Neo4jScopedGraphRepository,
    ScopedAuthGraphService,
    ScopedSessionBroker,
)

driver = GraphDatabase.driver(
    "neo4j+s://YOUR_HOST",
    auth=("YOUR_RUNTIME_USER", "YOUR_NEO4J_PASSWORD"),
)
driver.verify_connectivity()

private_repository = Neo4jScopedGraphRepository(
    driver,
    database="YOUR_DATABASE",
)
public_repository = Neo4jPublicGraphRepository(
    driver,
    database="YOUR_DATABASE",
)
sessions = ScopedSessionBroker(
    default_ttl_seconds=300,
    max_ttl_seconds=1800,
)
private = ScopedAuthGraphService(
    private_repository,
    CryptoEngine(),
    sessions,
)
```

Public writes need a decision from your trusted application. This example uses
a server-only capability:

```python
publisher_capability = object()

def may_publish(publisher, graph_id):
    return (
        publisher is publisher_capability
        and graph_id == "support"
    )

graph = AuthGraph(
    private,
    public_repository,
    default_policy=GraphPolicy(allow_public_overrides=True),
    public_write_authorizer=may_publish,
)
```

Do not send the publisher capability, Neo4j credentials, or service objects to
an AI.

## 4. Create a vault and protection scopes

Your login system supplies an opaque identity-provider ID, not a name or email:

```python
principal_id = "idp|opaque-subject-7f921"
passphrase = bytearray(b"a long synthetic test passphrase")

try:
    vault_id = graph.create_vault(principal_id, passphrase)
    profile_scope = graph.create_scope(
        principal_id,
        vault_id,
        passphrase,
    )
    orders_scope = graph.create_scope(
        principal_id,
        vault_id,
        passphrase,
    )
finally:
    passphrase[:] = b"\x00" * len(passphrase)
```

Store the returned `vault_id` and scope mapping in your trusted account store.
Scope IDs are backend authorization data. Do not expose them to the AI.

A new passphrase must contain at least 15 UTF-8 bytes.

## 5. Unlock only the needed scopes

Collect the passphrase in a dedicated secure form, not in chatbot text:

```python
passphrase = bytearray(b"a long synthetic test passphrase")

try:
    context = graph.unlock(
        principal_id,
        vault_id,
        passphrase,
        (orders_scope,),
        ttl_seconds=300,
    )
finally:
    passphrase[:] = b"\x00" * len(passphrase)
```

`context` is a temporary bearer capability. Keep it on the server. Never put
it in a URL, log, prompt, browser storage, or model tool argument.

End access explicitly:

```python
graph.lock(context)
```

Every open and lease requires the vault to be `ACTIVE` at the session's exact
envelope revision. Expiry, lock, password change, or session revocation blocks
a new key lease. The in-memory broker also invalidates sessions on shutdown or
restart. `DurableScopedSessionBroker` intentionally preserves valid wrapped
sessions across a same-host restart, so use explicit close or vault revocation
when restart must end access.

Direct provider-slot revocation does not revoke resident sessions. Use
`SecurityOperations`, which writes an audit intent, blocks admission, revokes
sessions, and performs the provider mutation under one vault fence. This stops
future provider-based release only; it does not disable direct passphrase
unlock unless your host removes that path too.
Interrupted password changes remain `REVISION_PENDING`. A trusted operator may
call `private.reconcile_passphrase_change(principal_id, vault_id)`; it reads the
authoritative Neo4j envelope. Never expose reconciliation as an AI or end-user
tool. Interrupted management operations remain `BLOCKED`; follow
[OPERATIONS.md](OPERATIONS.md).

## 6. Create nodes

Private storage is the default:

```python
order = graph.create_entity(
    "support",
    "Order",
    {
        "order_number": "ORDER-1001",
        "status": "delayed",
    },
    context=context,
    scope_id=orders_scope,
    idempotency_key="create-order-1001",
)
```

The idempotency key makes an exact retry return the same node ID. Reusing the
key with different data fails. The key itself is not stored in Neo4j.

Create an intentionally public node only when policy and authorization allow
it:

```python
from authgraph import ProtectionLevel

product = graph.create_entity(
    "support",
    "Product",
    {"name": "Example Headphones"},
    protection=ProtectionLevel.PUBLIC,
    publisher=publisher_capability,
    idempotency_key="public-product-headphones",
)
```

Public kinds and properties are plaintext to Neo4j and database backups.

## 7. Create connections

Private-to-private:

```python
customer = graph.create_entity(
    "support",
    "Customer",
    {"display_name": "Synthetic Customer"},
    context=context,
    scope_id=orders_scope,
)

placed = graph.connect(
    "support",
    customer,
    order,
    "PLACED",
    {"channel": "web"},
    context=context,
    scope_id=orders_scope,
    idempotency_key="connect-order-1001",
)
```

Private-to-public also works:

```python
contains = graph.connect(
    "support",
    order,
    product,
    "CONTAINS",
    {"quantity": 1},
    context=context,
    scope_id=orders_scope,
    idempotency_key="contains-order-1001",
)
```

AuthGraph creates an encrypted anchor for the public endpoint and commits the
anchor and encrypted connection atomically. An exact retry with the same
idempotency key returns the same connection and helpers; reusing the key with
changed semantics or endpoints conflicts.

A plaintext public connection is allowed only between two public nodes:

```python
another_public_product = graph.create_entity(
    "support",
    "Product",
    {"name": "Example Case"},
    protection=ProtectionLevel.PUBLIC,
    publisher=publisher_capability,
)

related = graph.connect(
    "support",
    product,
    another_public_product,
    "RELATED_TO",
    {},
    protection=ProtectionLevel.PUBLIC,
    publisher=publisher_capability,
    idempotency_key="public-related-products",
)
```

Public and private idempotency keys are scoped by the operation's trusted graph
or protection scope. They are opaque retry keys, not user credentials.

## 8. Read, update, and delete data

Resolve a node:

```python
record = graph.get_entity("support", order, context=context)
print(record.kind, record.properties, record.record_revision)
```

Update with optimistic revision checking:

```python
updated = graph.update_entity(
    "support",
    order,
    "Order",
    {
        "order_number": "ORDER-1001",
        "status": "shipped",
    },
    context=context,
    expected_revision=record.record_revision,
)
```

The update fails if another writer already changed that revision.

Public records use the same methods and optimistic revision checks. Public
writes also require the trusted publisher capability:

```python
public_record = graph.get_entity("support", product)
public_record = graph.update_entity(
    "support",
    product,
    "Product",
    {"name": "Example Headphones v2"},
    expected_revision=public_record.record_revision,
    publisher=publisher_capability,
)
```

Relationships have the same pattern for both protection levels:

```python
edge = graph.get_relationship("support", placed, context=context)

edge = graph.update_relationship(
    "support",
    placed,
    "PLACED",
    {"channel": "phone"},
    context=context,
    expected_revision=edge.record_revision,
)

graph.delete_relationship(
    "support",
    placed,
    context=context,
    expected_revision=edge.record_revision,
)
```

Node deletion is restrictive:

```python
graph.delete_relationship(
    "support",
    contains,
    context=context,
    expected_revision=1,
)

graph.delete_entity(
    "support",
    order,
    context=context,
    expected_revision=updated.record_revision,
)
```

It fails while any encrypted connection still touches the node, including a
connection hidden by a locked scope. AuthGraph never performs an unrestricted
cascade delete.

Public entity deletion similarly refuses incident public relationships and
requires the exact revision plus publisher authorization. It cannot inspect
encrypted mixed-edge semantics in the private repository. Deleting a referenced
public endpoint can therefore leave its encrypted anchor and relationship;
unlocked views omit that unresolved edge. A trusted
`delete_relationship(..., context=..., expected_revision=...)` call can still
remove the private edge and its unshared helper anchor atomically. Apply an
application policy and cleanup workflow before public endpoint deletion.

## 9. Read graph views

The locked view contains only public records:

```python
public_view = graph.get_public_view("support")
```

The unlocked view adds only private wrappers visible to the current scope
session:

```python
visible_view = graph.get_unlocked_view("support", context)
```

Private anchors are resolved to their public endpoints and are not exposed as
semantic nodes.

## 10. Give a chatbot a bounded GraphRAG tool

The model-facing method should accept only the user's question:

```python
from authgraph import (
    DisclosurePolicy,
    SessionBoundRetrievalTool,
    SessionVisibleGraphGateway,
)

policy = DisclosurePolicy(
    allowed_entity_kinds=frozenset({"Order", "Product"}),
    allowed_relationship_kinds=frozenset({"CONTAINS"}),
    entity_property_allowlist={
        "Order": frozenset({"order_number", "status"}),
        "Product": frozenset({"name"}),
    },
    relationship_property_allowlist={
        "CONTAINS": frozenset({"quantity"}),
    },
    max_nodes=12,
    max_edges=16,
    max_hops=1,
    max_plaintext_bytes=16_384,
    max_token_estimate=2_048,
)

gateway = SessionVisibleGraphGateway(
    graph,
    graph_id="support",
    policy=policy,
)
tool = SessionBoundRetrievalTool(gateway, context=context)

result = tool.search("Where is my order?")
```

Without a candidate index, each private search reads and decrypts one bounded
complete session-visible snapshot. For repeated searches, build a candidate
index once and keep it only for that secure session:

```python
with gateway.build_candidate_index(context=context) as candidates:
    tool = SessionBoundRetrievalTool(
        gateway,
        context=context,
        candidate_index=candidates,
    )
    first = tool.search("Where is my order?")
    second = tool.search("Which products are in it?")
```

The build still decrypts one complete bounded projection in trusted memory.
The index retains allowlisted lexical token counts plus opaque IDs/topology;
the hard index ceilings are 1,000 entities and 2,000 relationships, while
stricter snapshot limits may apply. Treat it as sensitive. Later searches rank
that index, then ask Neo4j for only the exact selected ciphertext rows and
decrypt their granted endpoints. It is
strictly bound to the same gateway and context; a closed, wrong-context, or
expired session fails instead of falling back to public data.

Candidate selection reflects the build-time tokens/topology, although selected
rows are read again in their current encrypted form. Rebuild after graph
changes when discovery freshness matters, and always close the index when the
session ends. This is exact targeted retrieval, not semantic search over
encrypted properties inside Neo4j.

The AI gets `result`, not `context`. Without a context, the same tool searches
only public data:

```python
public_tool = SessionBoundRetrievalTool(gateway)
```

If you send retrieved plaintext to an external AI, that AI can read it.
AuthGraph controls retrieval; it cannot force an external service to forget
data it received.

## 11. One-time-code unlock

The OTP broker and scope-key-provider interfaces support this flow:

1. your backend creates and sends a short one-time code;
2. the code proves authorization to a trusted provider;
3. under one vault guard, the provider releases a fixed configured set of
   scope keys; and
4. AuthGraph opens a short session only while the vault remains `ACTIVE` at the
   grant's exact revision.

The code is never an encryption key. The default broker, grant policy, session
broker, and key provider are in-memory test components. Optional
`DurableOneTimeCodeBroker`, `DurableScopeGrantPolicy`,
`DurableScopedSessionBroker`, and `SqliteKeySlotStore` survive restarts and
coordinate processes on one host. They are not multi-host authorization
backends.

`DurableOneTimeCodeBroker(..., ttl_seconds=600)` sets a ten-minute maximum.
Expiry does not automatically send a new code. A server-controlled resend
calls `issue()` again with the same binding, replacing the old challenge and
counting against the issue limit. Load the OTP, grant, session, and audit HMAC
keys as separate stable secrets; do not generate new values at each restart.

AuthGraph does not know an email address or send messages. The host resolves a
previously verified destination, sends the caller-owned code buffer, clears it,
and accepts verification through a dedicated form outside chat. See
[OTP_EMAIL_ADAPTER.md](OTP_EMAIL_ADAPTER.md) for the exact flow.

For provider-shaped custody, combine `EnvelopeScopeKeyProvider`, a managed
`KeyWrappingBackend` such as the injected-client
`AwsKmsKeyWrappingBackend`, and an atomic `KeySlotStore`. The included SQLite
slot store is still a single-host reference. Production also needs provider
credentials/policies, shared strongly consistent state for multiple hosts,
account and network rate limits, monitoring, and reviewed recovery.

Routine `MirroredKeyWrappingBackend.unwrap_key()` uses its primary backend only
and never silently falls back to recovery. Recovery is an explicit operation
that consumes a fixed single-use recovery grant, rewraps into a different
provider generation, and records pseudonymous source provenance.

See [CHATBOT_GRAPHRAG_DESIGN.md](CHATBOT_GRAPHRAG_DESIGN.md) for the trust
boundary and provider flow.

## 12. Change a passphrase and shut down

```python
graph.change_passphrase(
    principal_id,
    vault_id,
    current_passphrase,
    new_passphrase,
)
```

This prepares a fail-closed revision transition, revokes existing sessions,
changes only the wrapped vault key, and activates the new revision after the
graph compare-and-swap. It does not rewrite graph records. An interruption
requires the trusted reconciliation path described above.

On application shutdown:

```python
otp.close()       # if an OTP broker is active
grants.close()    # if a grant policy is active
sessions.close_all()
driver.close()
```

The durable brokers are context managers. Close admission before the driver
and provider clients. `SqliteKeySlotStore` opens a transaction per operation
and has no persistent client to close; the injected KMS client remains owned by
the host application. For `DurableScopedSessionBroker`, `close_all()` closes
only the local broker handle; it deliberately does not revoke unexpired
persisted sessions. Call `close(context)` or `revoke_vault()` when revocation is
intended.

The durable broker tracks each active key lease with its own expiry-bound row.
After a worker crash, purge can reclaim stale rows and delete revoked wrapped
session ciphertext. This cannot recall plaintext already copied into a process
and does not prove complete memory zeroization.

## 13. Tests

Run all unit tests without Neo4j:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Run the opt-in live suite only against a disposable or explicitly approved
database:

```bash
AUTHGRAPH_RUN_NEO4J_TESTS=1 \
AUTHGRAPH_TEST_NEO4J_URI=neo4j+ssc://YOUR_TEST_HOST \
AUTHGRAPH_TEST_NEO4J_USERNAME=YOUR_TEST_USER \
AUTHGRAPH_TEST_NEO4J_PASSWORD_FILE=/secure/path/test-password \
AUTHGRAPH_TEST_NEO4J_DATABASE=neo4j \
python3 -m unittest discover -s tests/integration -v
```

By default the suite only verifies the schema. Allow it to install the schema
by also setting:

```bash
AUTHGRAPH_TEST_APPLY_SCHEMA=1
```

The live tests use random principals and exact vault IDs for cleanup. They
never clear the whole database.

## Advanced and legacy APIs

- `ScopedAuthGraphService` is the lower-level scoped-v2 private API.
- `LegacyAuthGraphService` is the old one-key whole-vault API.
- `LayeredGraphService` is the old v1 public/private façade.

There is no automatic migration from legacy v1 encrypted records to scoped-v2
data. This is separate from packaged Neo4j schema-version migrations. New
applications should use `AuthGraph`.
