# AuthGraph

AuthGraph is a Python security layer for Neo4j knowledge graphs.

One graph can contain:

- public nodes and connections that Neo4j stores normally; and
- private nodes and connections encrypted before Neo4j receives them.

Private data is split into independent protection scopes. A short-lived
session receives only the keys for its allowed scopes, so unlocking orders
does not also unlock billing or another person's data.

> AuthGraph is still an early prototype. Use synthetic data only.

## How it works

```text
Your login or unlock form
          |
          v
Your trusted backend + AuthGraph
  - chooses the allowed scopes
  - keeps temporary keys
  - decrypts only visible records
          |
          v
Your chatbot's small read-only GraphRAG tool
```

Neo4j stores generic labels, opaque IDs, key metadata, and AES-256-GCM
ciphertext for private records. Node kinds, connection kinds, properties, and
logical graph IDs stay inside the ciphertext.

Passwords, one-time codes, keys, scope IDs, vault IDs, and session tokens must
never be given to the AI. Your backend binds access before it calls the
chatbot's read tool.

## Install and prepare Neo4j

You need Python 3.11+, Neo4j 5.7+, TLS, and a restricted Neo4j account.

```bash
python3 -m pip install .
authgraph schema apply \
  --uri neo4j+s://YOUR_HOST \
  --database YOUR_DATABASE \
  --username YOUR_SCHEMA_USER
```

The command securely prompts for the password. It installs AuthGraph's fixed
schema and verifies all expected constraints and indexes. It does not accept a
password as a command-line argument.

Use `authgraph schema verify` with the same connection options to check an
existing database. A password file is also supported:

```bash
authgraph schema verify \
  --uri neo4j+s://YOUR_HOST \
  --database YOUR_DATABASE \
  --username YOUR_USER \
  --password-file /secure/path/neo4j-password
```

## Main API

`AuthGraph` is the main API for new applications. It combines:

- scoped-v2 private encryption;
- an intentionally plaintext public graph;
- private create, read, update, and delete;
- retry-safe private creates using an idempotency key;
- public, private, and mixed encrypted connections; and
- public and unlocked graph views for GraphRAG.

`ScopedAuthGraphService` remains available as the lower-level private API.
`LegacyAuthGraphService` and `LayeredGraphService` keep the old whole-vault
format readable; new applications should not start with them.

See [docs/USAGE.md](docs/USAGE.md) for a complete setup and API example.

## Important limits

- The live Neo4j integration suite is opt-in. It has not completed in this
  workspace because the Docker host ran out of disk space.
- Private GraphRAG currently decrypts a bounded complete session-visible
  snapshot in trusted memory before ranking it. Targeted encrypted Neo4j
  search is not implemented yet.
- Public update, delete, and idempotent public creation are not implemented.
- Mixed encrypted relationships work, but retry-safe mixed-edge creation is
  not implemented yet.
- OTP challenges, scope sessions, policies, and the included key provider are
  in-memory and single-process.
- Production KMS/HSM integration, durable revocation, recovery, migration,
  audit logging, and multi-server coordination are still missing.
- AuthGraph has not had an independent security audit.

Do not use real personal, medical, financial, or other sensitive data yet.

## Tests

Unit tests do not need Neo4j:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The opt-in live suite is documented in [docs/USAGE.md](docs/USAGE.md).

More detail:

- [Usage and commands](docs/USAGE.md)
- [Chatbot and GraphRAG design](docs/CHATBOT_GRAPHRAG_DESIGN.md)
- [Security model](docs/SECURITY_MODEL.md)

License: [MIT](LICENSE)
