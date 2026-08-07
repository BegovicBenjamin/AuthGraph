# Security policy

AuthGraph is an early security prototype. Do not use it with real personal,
medical, financial, credential, or other sensitive data. It has not received an
independent security assessment.

## Supported versions

Security fixes are made on a best-effort basis for the current `0.3.x` line.
Older prototype lines are not supported.

| Version | Status |
|---|---|
| `0.3.x` | Current prototype line |
| `< 0.3` | Unsupported |

This table is not a production-support promise or an SLA. See
[docs/SUPPORTED_VERSIONS.md](docs/SUPPORTED_VERSIONS.md) for tested runtime
versions.

## Report a vulnerability

Do not open a public issue for a suspected vulnerability or include real data,
passwords, keys, tokens, one-time codes, database dumps, or exploit details in
public discussions.

Use GitHub's private vulnerability report form:

https://github.com/BegovicBenjamin/AuthGraph/security/advisories/new

Include only what is needed to reproduce the problem with synthetic data:

- affected AuthGraph version and commit;
- Python, Neo4j server, and Neo4j driver versions;
- the security boundary that was crossed;
- minimal reproduction steps; and
- whether a credential may already have been exposed.

No response-time guarantee is currently offered. If an active credential or key
may be exposed, revoke or rotate it immediately rather than waiting for a code
change.

## Scope

Reports about ciphertext isolation, cross-principal or cross-scope access,
session expiry or revocation, OTP replay, schema mediation, unsafe query
construction, secret exposure, and package integrity are in scope.

The following are known prototype limitations rather than undisclosed security
properties:

- the default OTP/grant brokers, session brokers, and included in-memory key
  provider remain single-process;
- the optional SQLite authorization references coordinate OTP, grant, session,
  vault-lifecycle, guard, and expiry-bound lease state across processes on one
  host only;
- an injected-client AWS KMS wrapping adapter and durable slot-store SPI exist,
  while the included SQLite slot store remains a single-host reference;
- ordinary mirrored-key unwrap uses only the primary backend; the recovery copy
  is reachable only through an explicitly authorized recovery operation;
- interrupted lifecycle operations fail closed in `REVISION_PENDING` or
  `BLOCKED` and require trusted reconciliation;
- pre-mutation audit intents make interrupted management operations detectable,
  but the JSONL sink remains a local reference rather than WORM or multi-host
  audit storage;
- production KMS use still requires correctly configured credentials, key
  policies, a shared strongly consistent multi-host slot store, lifecycle
  integration and runbooks, monitoring, and external review;
- no durable multi-server session/key revocation or anti-rollback authority;
- no production HTTP authentication layer or email delivery adapter;
- no automatic legacy v1 encrypted-record to scoped-v2 data migration or
  complete key-recovery workflow; and
- no guarantee that an external model provider forgets plaintext sent to it.

The complete trust assumptions and known gaps are in
[docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).
