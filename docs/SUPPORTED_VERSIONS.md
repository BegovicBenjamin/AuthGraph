# Supported versions

AuthGraph is a synthetic-data prototype. This page records compatibility targets
and does not claim production readiness.

## Python

The package requires Python 3.11 or newer. The configured CI matrix covers:

| Python | CI target |
|---|---|
| 3.11 | Minimum dependency versions |
| 3.12 | Current dependency versions |
| 3.13 | Current dependency versions |
| 3.14 | Linux, Windows, and macOS |

A future Python release is not supported merely because `requires-python`
accepts it. Add it to CI before documenting support.

## Neo4j Python driver

AuthGraph declares `neo4j>=6.2,<7`. The configured matrix tests both `6.2.0` and
the newest version allowed by that range. A new driver major version requires an
AuthGraph release and live compatibility testing.

## Neo4j server

The portable schema requires Neo4j 5.7 or newer because it uses relationship
property uniqueness. The live workflow is configured for these explicit
compatibility points:

| Neo4j image | Purpose |
|---|---|
| `neo4j:5.7.0` | Minimum schema compatibility |
| `neo4j:5.26.29` | Maintained 5.x line |
| `neo4j:2026.06.0` | Current line when this matrix was written |

Testing an old compatibility floor does not make that database version safe to
deploy. Use a Neo4j version that still receives upstream fixes and review the
matrix whenever Neo4j publishes a security or maintenance update.

Community Edition is used for portable CI. Enterprise-only existence/key
constraints, fine-grained authorization, and an actual Aura deployment require
separate environment-specific validation.

## Transport and platform

Neo4j access must use encrypted Bolt transport. CI uses a short-lived
self-signed certificate with `bolt+ssc://`; deployed systems should use
certificate verification with `neo4j+s://` or `bolt+s://`.

Unit tests run on Linux, Windows, and macOS. Live Neo4j container tests run on
Linux. AuthGraph does not currently publish platform-specific wheels.

## API stability

AuthGraph is below version 1.0. Public API changes may occur in minor releases.
Pin a compatible AuthGraph version, read [CHANGELOG.md](../CHANGELOG.md), and
test upgrades with synthetic data. There is no automatic v1-to-v2 data
migration.
