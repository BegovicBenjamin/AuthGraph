# Using AuthGraph

This guide covers the API that new applications should use.

> AuthGraph is an early prototype. Use synthetic data only.

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

Verify without applying anything:

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

The schema command never creates or drops a database.

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

Expiry, lock, password change, provider revocation, shutdown, or process
restart also removes future access.

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
)
```

AuthGraph creates an encrypted anchor for the public endpoint and commits the
anchor and encrypted connection atomically. Retry-safe idempotency for this
mixed case is not implemented yet.

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
)
```

## 8. Read, update, and delete private data

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

Relationships have the same pattern:

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

Public update, delete, lookup by relationship reference, and public
idempotency are not implemented.

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

The AI gets `result`, not `context`. Without a context, the same tool searches
only public data:

```python
public_tool = SessionBoundRetrievalTool(gateway)
```

AuthGraph currently obtains the private view by decrypting a bounded complete
snapshot of the session's granted scopes in trusted memory, then filtering and
ranking it. It does not yet run targeted search over encrypted Neo4j rows.

If you send retrieved plaintext to an external AI, that AI can read it.
AuthGraph controls retrieval; it cannot force an external service to forget
data it received.

## 11. One-time-code unlock

The included OTP broker and scope-key provider can test this flow:

1. your backend creates and sends a short one-time code;
2. the code proves authorization to a trusted provider;
3. the provider releases a fixed configured set of scope keys;
4. AuthGraph opens a short session.

The code is never an encryption key. The included implementation is in-memory
only. Production needs real email/SMS delivery, rate limiting, abuse
protection, and a KMS or HSM-backed key provider.

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

This rewraps the vault key and revokes older sessions. It does not decrypt and
rewrite every graph record.

On application shutdown:

```python
sessions.close_all()
driver.close()
```

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

There is no automatic migration from v1 to v2. New applications should use
`AuthGraph`.
