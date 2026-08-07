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

The command securely prompts for the password. It applies AuthGraph's fixed
schema, schema metadata, and packaged data migrations, then verifies every
expected constraint and index. Back up and test an existing database, and stop
conflicting writers during an upgrade. The command does not accept a password
as a command-line argument.

Use the read-only `authgraph schema verify` command with the same connection
options to check an existing database. A password file is also supported:

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
- public and private create, read, update, and delete;
- retry-safe public, private, and mixed creates using an idempotency key;
- public, private, and mixed encrypted connections; and
- public and unlocked graph views for GraphRAG.

`ScopedAuthGraphService` remains available as the lower-level private API.
`LegacyAuthGraphService` and `LayeredGraphService` keep the old whole-vault
format readable; new applications should not start with them.

See [docs/USAGE.md](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/USAGE.md)
for the main setup and API example.

## Important limits

- The live Neo4j suite is opt-in locally and a CI matrix is configured. Check
  the result for the exact commit and server version you deploy.
- Private GraphRAG still needs one bounded complete session-visible projection
  to build its optional candidate index. Repeated searches can then fetch and
  decrypt only exact selected ciphertext rows. This does not make encrypted
  properties semantically searchable inside Neo4j, and the sensitive
  in-process index remains caller-managed.
- Public and private records live in separate repositories. Deleting a public
  endpoint can leave an encrypted mixed-edge anchor that is hidden until a
  trusted cleanup deletes that private relationship.
- Defaults remain in-memory and single-process. Optional SQLite authorization
  stores coordinate processes sharing one local file only, not multiple hosts.
- Durable session state includes a fenced vault lifecycle, renewable guards,
  and expiry-bound lease records. Work is admitted only while the vault is
  `ACTIVE` at the exact envelope revision. Interrupted password changes remain
  `REVISION_PENDING`; interrupted key operations remain `BLOCKED` until trusted
  reconciliation.
- Routine mirrored-key unwrap uses only the primary backend. Recovery requires
  a separate single-use recovery authorization.
- Management operations write a required pending audit intent before mutation.
  Operators must investigate any unmatched pending intent reported by audit
  verification.
- An injected-client AWS KMS adapter and provider-neutral custody SPI exist. A
  production deployment still needs configured provider policy, shared
  strongly consistent multi-host state, monitoring, tested runbooks, and
  application integrations.
- AuthGraph does not send email or provide login, HTTP, cookies, abuse
  protection, or a hosted multi-server authorization service.
- Any ignored local demo that displays an OTP is synthetic test UI, not a
  secure email delivery adapter.
- AuthGraph has not had an independent security audit.

Do not use real personal, medical, financial, or other sensitive data yet.

## Tests

Unit tests do not need Neo4j:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The opt-in live suite is documented in
[docs/USAGE.md](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/USAGE.md).

More detail:

- [Documentation index](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/README.md)
- [Usage and commands](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/USAGE.md)
- [Chatbot and GraphRAG design](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/CHATBOT_GRAPHRAG_DESIGN.md)
- [Security model](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/SECURITY_MODEL.md)
- [Production setup](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/PRODUCTION_SETUP.md)
- [OTP email adapter contract](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/OTP_EMAIL_ADAPTER.md)
- [Operations and recovery](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/OPERATIONS.md)
- [Public errors](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/ERRORS.md)
- [External security review package](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/SECURITY_REVIEW.md)
- [Supported versions](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/SUPPORTED_VERSIONS.md)
- [Release process](https://github.com/BegovicBenjamin/AuthGraph/blob/main/docs/RELEASE.md)
- [Security reporting](https://github.com/BegovicBenjamin/AuthGraph/blob/main/SECURITY.md)
- [Changelog](https://github.com/BegovicBenjamin/AuthGraph/blob/main/CHANGELOG.md)

License: [MIT](https://github.com/BegovicBenjamin/AuthGraph/blob/main/LICENSE)
