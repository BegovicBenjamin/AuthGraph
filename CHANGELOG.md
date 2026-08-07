# Changelog

AuthGraph follows semantic versioning while it is below 1.0. Minor releases may
change APIs; every such change should be called out here.

## Unreleased

### Fixed

- Made simultaneous first-time initialization of the durable SQLite key-slot,
  OTP, and scope-grant stores safe across local worker processes.

## 0.3.0 - 2026-08-06

### Added

- Cross-platform Python unit-test automation.
- Opt-in live TLS Neo4j compatibility checks.
- Verified wheel and source-distribution build automation.
- Manual, approval-gated TestPyPI and PyPI publication jobs.
- Supported-version, release, and vulnerability-reporting documentation.
- Complete optimistic public CRUD and retry-safe public and mixed creates.
- Session-bound targeted private retrieval for repeated GraphRAG searches.
- Restart-safe single-host SQLite adapters for OTP challenges, fixed-scope
  grants, wrapped sessions, and provider key slots.
- A provider-neutral wrapping SPI, injected-client AWS KMS adapter, mirrored
  recovery wrapping, audited revocation/rewrap/recovery operations, and a
  pseudonymous hash-chained audit sink.
- Fixed, versioned Neo4j schema metadata and migrations.
- Public session-broker typing protocols and a packaged `py.typed` marker.

### Security

- SQLite adapters require owner-controlled state directories and mode-0600
  database files on POSIX systems.
- Added fail-closed per-vault `ACTIVE`, `REVISION_PENDING`, and `BLOCKED`
  lifecycle states with exact-revision admission, fenced renewable guards, and
  explicit crash reconciliation.
- Replaced durable scalar lease accounting with expiry-bound per-lease records
  so crashed workers do not retain wrapped session ciphertext indefinitely.
  Upgrading that SQLite session file requires stopping all old workers before
  the first new worker opens and migrates it; mixed-version rolling use is not
  supported.
- Made routine mirrored unwrap primary-only. Recovery now uses a separate,
  explicitly authorized path with audited source provenance.
- Added required pre-mutation audit intents, linked terminal outcomes, and
  verification reports for unmatched pending operations.
- This release still has no independent security assessment. Multi-host state,
  delegated principals, and scope-DEK rotation/re-encryption remain host or
  future-version responsibilities.

## 0.2.0 - 2026-07-31

### Added

- Scoped-v2 vaults with independent protection-scope keys.
- The `AuthGraph` public/private facade.
- Private CRUD and mixed public/private graph support.
- In-memory OTP authorization and provider interfaces.
- Bounded GraphRAG retrieval and temporary in-memory vector search.
- Packaged Neo4j schema application and verification commands.

### Security

- This release remains a synthetic-data prototype and has not received an
  independent security assessment.
