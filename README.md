# AuthGraph

AuthGraph is a Python library for storing public and encrypted private
knowledge-graph data in Neo4j.

Private nodes and connections are encrypted before they reach the database.
Public records are stored as normal readable Neo4j data.

AuthGraph is not a chatbot, login system, or web API. Your application supplies
those parts.

> **AuthGraph is an early prototype. Use synthetic data only.**

## How it works

One Neo4j database can contain many separate vaults. A vault can belong to a
person, customer, account, or other owner. You do not need a separate database
for every owner.

```text
Your application
(login and permissions)
        |
        v
     AuthGraph
      /     \
 public     private
 plaintext  encrypted
      \     /
       Neo4j

Unlock one vault
        |
        v
Public graph + only that owner's private graph
```

When AuthGraph creates a vault, it generates a random encryption key. That key
encrypts private node types, connection types, and properties with AES-256-GCM.
A key made from the owner's password protects the vault key. The password is
not stored.

After a successful unlock, the vault key stays in server memory for a short
time. Locking the vault, letting the session expire, or stopping the process
removes it. Data in Neo4j stays encrypted while the vault is unlocked.

| Record | What Neo4j stores | Available while locked |
|---|---|---|
| Private node or connection | Ciphertext and opaque IDs | No |
| Public node or connection | Readable type and properties | Yes |

Private is the default. A graph policy can let your trusted application mark
individual nodes and connections as public.

Neo4j can still see opaque IDs, record counts, connection directions,
ciphertext sizes, and access timing. It cannot read encrypted types or
properties without the vault key.

A locked graph view contains only public records. An unlocked view adds one
authorized owner's private records. Unlocking one owner never unlocks another.

Passwords, keys, database credentials, and session tokens must never be sent
to an AI. If your application sends decrypted facts to an AI, the AI can read
those facts.

## Using AuthGraph

You need Python 3.11 or newer, Neo4j 5.7 or newer, an encrypted Neo4j
connection, and a limited database account.

Install the package:

```text
python3 -m pip install .
```

Then:

1. Run [neo4j/schema.cypher](neo4j/schema.cypher) in Neo4j.
2. Connect the private and public repositories.
3. Create an `AuthGraphService` and `LayeredGraphService`.
4. Create a vault for an authenticated owner.
5. Unlock the vault before using private records and lock it when finished.

Your application must handle login, user-to-vault mapping, password input,
permissions, APIs, and user interfaces.

## Current limits

- The Neo4j adapters have unit tests but have not yet been tested here with a
  live Neo4j server.
- There is no built-in login, web API, MFA, recovery, or admin system.
- The included key-session broker supports one application process.
- Existing records cannot yet switch safely between public and private.
- Key rotation, shared access, and recovery are not implemented.
- AuthGraph has not had an independent security audit.

Do not use real personal, medical, or financial data yet. Production use still
needs live Neo4j tests, strong authentication, hardened key storage, audit
logs, backups, key rotation, multi-server sessions, and a security review.

## Tests

The unit tests do not need Neo4j:

```text
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Technical security details are in
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).

License: [MIT](LICENSE)
