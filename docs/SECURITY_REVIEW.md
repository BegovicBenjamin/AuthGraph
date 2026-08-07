# External security review package

> **No independent security review or production signoff has occurred.**

This checklist prepares a review package. Completing it internally is not an
independent audit, certification, compliance opinion, or approval to use real
sensitive data.

## Freeze the review target

Record these before review:

```text
Release/tag:
Git commit:
Source archive SHA-256:
Wheel/sdist SHA-256:
Schema version:
Python and Neo4j versions:
Deployment diagram/configuration revision:
Review start/end dates:
Independent reviewer and organization:
In-scope environments and exclusions:
```

A later code, dependency, schema, KMS-policy, identity, network, model, or
deployment change needs impact review and may invalidate the result.

## Package contents

- [ ] Exact source and built artifacts, checksums, license, changelog, and
      supported-version policy.
- [ ] Reproducible build instructions, dependency lock/evidence, SBOM, and CI
      results for the frozen commit.
- [ ] Unit, live Neo4j, concurrency, failure-injection, and restore test output.
- [ ] Data-flow and deployment diagrams showing browser, backend, AI, Neo4j,
      authorization stores, KMS/HSM, email/IdP, audit, backup, and operators.
- [ ] [Security model](SECURITY_MODEL.md), trust assumptions, data classes,
      leakage, abuse cases, and accepted residual risks.
- [ ] Public API/error inventory, fixed Cypher/schema manifest, GraphRAG tool
      schemas, and every non-AuthGraph write path to Neo4j.
- [ ] Redacted runtime configuration, RBAC, network policy, KMS key policy,
      provider identity, secret ownership, rotation schedule, and logging rules.
- [ ] OTP/email, session, key-slot, audit, rate-limit, and multi-host backend
      designs, including their atomicity and failure semantics.
- [ ] [Operations and recovery](OPERATIONS.md), backup inventory, completed
      restore/revocation/recovery drills, and incident contacts.
- [ ] Model-provider retention/training/region/subprocessor settings and any
      required privacy, DPA, BAA, or regulatory assessment.
- [ ] Prior findings, fixes, risk acceptances, and retest evidence.

Do not put live credentials, unredacted KMS responses, real customer data,
private database dumps, OTPs, session tokens, or exploitable production details
in the reviewer package. Use an agreed secure exchange.

## Minimum review work

The independent reviewer should determine the exact scope and methods, but the
assessment should at least cover:

- cryptographic construction, key hierarchy, random/nonces, AAD binding,
  ciphertext swapping/tampering, buffer lifetime, and provider wrapping;
- cross-principal, cross-vault, cross-scope, relationship-endpoint, guessed-ID,
  direct-Neo4j, stale-revision, and schema-bypass attempts;
- OTP enumeration, resend, brute force, replay, forged evidence, race, email
  takeover, and account-recovery abuse;
- grant/session fixation, theft, restart, expiry, logout, concurrent lease,
  revocation, capacity exhaustion, and process/host failure;
- key-slot compare-and-swap, tombstone rollback, provider outage, provider-key
  rewrap, scope-key compromise, backup/restore, and recovery controls;
- required-audit failure, log/trace/crash-report leakage, hash-chain tampering,
  access control, export, and retention;
- fixed query mediation, Neo4j RBAC/TLS/backups, malformed/orphan graph data,
  transaction retry, and database-administrator threat assumptions;
- GraphRAG over-disclosure, prompt injection from stored data, field/size/token
  limits, session binding, tool-schema abuse, and model-provider exposure;
- web authentication, cookies, CSRF, XSS, SSRF, request limits, error oracles,
  dependencies, packaging, release provenance, and deployment hardening; and
- multi-host linearizability and split-brain tests for every custom shared
  authorization backend, if the deployment uses more than one host.

## Required output

The review deliverable should state:

- exact frozen target, deployment, scope, exclusions, methods, and limitations;
- each finding's severity, evidence, affected component, and remediation;
- retest result for every fixed finding;
- unresolved findings and named risk owner with an expiry date;
- privacy/compliance questions that require separate specialist advice; and
- an explicit outcome: rejected, conditional, or approved for a named data
  class and deployment only.

Release is blocked until critical/high findings are fixed and retested, or a
qualified organizational authority explicitly accepts the documented risk.
Project authors should not describe internal testing, this checklist, or a
conditional report as "security audited" or "production secure."
