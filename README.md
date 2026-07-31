# AuthGraph

AuthGraph is a Python security layer for Neo4j knowledge graphs.

It lets one database hold:

- public nodes and connections that Neo4j can read normally; and
- private nodes and connections encrypted before they reach Neo4j.

Private data can be split into independent protection scopes such as profile,
orders, or billing. A session receives only the keys for its allowed scopes.
Unlocking orders does not unlock billing or another owner's data.

> AuthGraph is an early prototype. Use synthetic data only.

## How it works

```text
Login or secure unlock form
           |
           v
Trusted application + AuthGraph
  - checks the unlock policy
  - keeps temporary scope keys
  - reads and decrypts allowed records
  - retrieves a small visible subgraph
           |
           v
         Chatbot
```

Neo4j stores opaque IDs, key metadata, and ciphertext for protected records.
The semantic node type, connection type, and properties are inside
AES-256-GCM ciphertext.

A password unlocks a random vault-wrapping key. That key unwraps only the
independent scope keys selected by the trusted application. Plaintext
passwords and unwrapped keys are not persisted.

For password unlocks, the application—not the AI—must enforce which scope IDs
may be requested. The scoped password API trusts its backend caller.

The optional one-time-code component works differently: a code authorizes a
trusted key provider to release a fixed scope set. The short code is never
used as an encryption key. The included provider is only an in-memory test
provider; production needs a real KMS or HSM integration.

Session keys stay in one server process for a short time. Lock, expiry,
password change, revocation, shutdown, or restart removes their future access.
Neo4j data remains encrypted while a session is open.

## Chatbot and GraphRAG rule

The AI must never receive a password, one-time code, encryption key, Neo4j
credential, vault ID, scope ID, or AuthGraph session token.

Your backend binds those values outside the model and gives the AI one narrow
read-only search tool. AuthGraph's GraphRAG gateway searches only the
session-visible graph, filters fields, traverses a bounded number of hops, and
returns a bounded subgraph with provenance.

The current scoped adapter first decrypts a bounded complete snapshot of every
scope granted to that session in trusted memory, then filters and ranks it. It
does not yet issue a targeted encrypted Neo4j retrieval.

If that plaintext is sent to a hosted AI, the AI can read it. AuthGraph
controls retrieval; it cannot make an external model forget data already sent.

## Start here

You need Python 3.11+, Neo4j 5.7+, TLS, and a restricted Neo4j account.

```bash
python3 -m pip install .
```

Then run [neo4j/schema.cypher](neo4j/schema.cypher) once and follow
[docs/USAGE.md](docs/USAGE.md).

The code includes two APIs:

- `AuthGraphService`: the original whole-vault format;
- `ScopedAuthGraphService`: the new independent-scope format.

New scoped tests should use `ScopedAuthGraphService`. There is no migration
between the two formats yet.

## Current limits

- Neo4j adapters are unit-tested but have not been run here against a live
  Neo4j server.
- Login, HTTP routes, cookies, email delivery, and chatbot hosting belong to
  your application.
- OTP challenges, scope sessions, policies, and the demo key provider are
  in-memory and single-process.
- The temporary vector index must currently be created and closed by the
  trusted host for each session; encrypted embedding storage is not wired in.
- Update, delete, key rotation, recovery, migration, multi-server revocation,
  and audit logging are not implemented.
- AuthGraph has not had an independent security audit.

Do not use real personal, medical, financial, or other sensitive data yet.

## Tests

The unit tests do not need Neo4j:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

See:

- [Usage and API guide](docs/USAGE.md)
- [Chatbot and GraphRAG design](docs/CHATBOT_GRAPHRAG_DESIGN.md)
- [Security model](docs/SECURITY_MODEL.md)

License: [MIT](LICENSE)
