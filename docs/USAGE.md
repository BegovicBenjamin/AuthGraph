# Using AuthGraph

This guide documents the code that exists today. Planned chatbot and GraphRAG
features are documented separately in
[CHATBOT_GRAPHRAG_DESIGN.md](CHATBOT_GRAPHRAG_DESIGN.md).

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
| `LayeredGraphService` | `get_policy`, `create_entity`, `connect`, `get_public_view`, `get_unlocked_view` |
| `InMemorySessionBroker` | `open`, `lease`, `close`, `revoke_vault`, `purge_expired`, `close_all`, health/count properties |
| Private repositories | `Neo4jGraphRepository`, `InMemoryGraphRepository` |
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
- Session TTL: configured by the broker and never more than 24 hours

Full reads fail instead of silently returning a partial graph.

## Features that do not exist yet

- Authentication, user registration, account recovery, MFA, email codes, or
  passkeys
- A web API, CLI, chatbot, GraphRAG retriever, embeddings, or vector search
- Named private protection scopes with separate keys
- Persistent policy configuration or security audit logs
- Update, delete, record reclassification, key rotation, or shared access
- Multi-process session and revocation coordination
- A tested production deployment

See [CHATBOT_GRAPHRAG_DESIGN.md](CHATBOT_GRAPHRAG_DESIGN.md) for the proposed
path to these features and [SECURITY_MODEL.md](SECURITY_MODEL.md) for the
detailed current threat model.
