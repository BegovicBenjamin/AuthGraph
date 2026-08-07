"""Install and verify AuthGraph's fixed Neo4j schema.

The schema is a packaged, version-controlled resource. Callers cannot provide
arbitrary Cypher or a filesystem path through this API.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from typing import Any


@dataclass(frozen=True)
class SchemaObject:
    """The exact shape expected for one named Neo4j schema object."""

    name: str
    object_type: str
    entity_type: str
    labels_or_types: tuple[str, ...]
    properties: tuple[str, ...]


@dataclass(frozen=True)
class SchemaProblem:
    """One missing, conflicting, malformed, or unavailable schema object."""

    name: str
    reason: str


@dataclass(frozen=True)
class SchemaVerificationReport:
    """Result of comparing a database with AuthGraph's schema manifest."""

    verified_constraints: int
    verified_indexes: int
    schema_version: int
    problems: tuple[SchemaProblem, ...] = ()

    @property
    def is_valid(self) -> bool:
        return not self.problems


class Neo4jSchemaError(RuntimeError):
    """Base class for safe schema deployment failures."""


class SchemaApplyError(Neo4jSchemaError):
    """A fixed schema statement could not be applied."""

    def __init__(self, statement_name: str, ordinal: int) -> None:
        self.statement_name = statement_name
        self.ordinal = ordinal
        super().__init__(
            f"Could not apply AuthGraph schema object {statement_name!r} "
            f"(statement {ordinal})."
        )


class SchemaVerificationError(Neo4jSchemaError):
    """The connected database does not have the exact AuthGraph schema."""

    def __init__(
        self,
        report: SchemaVerificationReport | None = None,
        *,
        message: str = "Could not verify the AuthGraph Neo4j schema.",
    ) -> None:
        self.report = report
        if report is not None and report.problems:
            details = "; ".join(
                f"{problem.name}: {problem.reason}"
                for problem in report.problems
            )
            message = f"AuthGraph Neo4j schema verification failed: {details}"
        super().__init__(message)


class SchemaMigrationError(Neo4jSchemaError):
    """The fixed, versioned data migration could not complete safely."""

    def __init__(self, from_version: int, to_version: int) -> None:
        self.from_version = from_version
        self.to_version = to_version
        super().__init__(
            f"Could not migrate the AuthGraph schema from version "
            f"{from_version} to {to_version}."
        )


CURRENT_SCHEMA_VERSION = 2


EXPECTED_CONSTRAINTS = (
    SchemaObject(
        "authgraph_schema_metadata_name",
        "NODE_PROPERTY_UNIQUENESS",
        "NODE",
        ("AGSchemaMetadata",),
        ("name",),
    ),
    SchemaObject(
        "authgraph_vault_id",
        "NODE_PROPERTY_UNIQUENESS",
        "NODE",
        ("AGVault",),
        ("vault_id",),
    ),
    SchemaObject(
        "authgraph_entity_id",
        "NODE_PROPERTY_UNIQUENESS",
        "NODE",
        ("AGEntity",),
        ("entity_id",),
    ),
    SchemaObject(
        "authgraph_relationship_id",
        "RELATIONSHIP_PROPERTY_UNIQUENESS",
        "RELATIONSHIP",
        ("AG_LINK",),
        ("relationship_id",),
    ),
    SchemaObject(
        "authgraph_protection_scope_id",
        "NODE_PROPERTY_UNIQUENESS",
        "NODE",
        ("AGProtectionScope",),
        ("scope_id",),
    ),
    SchemaObject(
        "authgraph_scoped_entity_id",
        "NODE_PROPERTY_UNIQUENESS",
        "NODE",
        ("AGScopedEntity",),
        ("entity_id",),
    ),
    SchemaObject(
        "authgraph_scoped_relationship_id",
        "RELATIONSHIP_PROPERTY_UNIQUENESS",
        "RELATIONSHIP",
        ("AG_SCOPED_LINK",),
        ("relationship_id",),
    ),
    SchemaObject(
        "authgraph_public_graph_id",
        "NODE_PROPERTY_UNIQUENESS",
        "NODE",
        ("AGPublicGraph",),
        ("graph_id",),
    ),
    SchemaObject(
        "authgraph_public_entity_id",
        "NODE_PROPERTY_UNIQUENESS",
        "NODE",
        ("AGPublicEntity",),
        ("entity_id",),
    ),
    SchemaObject(
        "authgraph_public_relationship_id",
        "RELATIONSHIP_PROPERTY_UNIQUENESS",
        "RELATIONSHIP",
        ("AG_PUBLIC_LINK",),
        ("relationship_id",),
    ),
)

EXPECTED_INDEXES = (
    SchemaObject(
        "authgraph_entity_vault",
        "RANGE",
        "NODE",
        ("AGEntity",),
        ("vault_id",),
    ),
    SchemaObject(
        "authgraph_vault_owner",
        "RANGE",
        "NODE",
        ("AGVault",),
        ("principal_id",),
    ),
    SchemaObject(
        "authgraph_protection_scope_vault",
        "RANGE",
        "NODE",
        ("AGProtectionScope",),
        ("vault_id",),
    ),
    SchemaObject(
        "authgraph_scoped_entity_vault_scope",
        "RANGE",
        "NODE",
        ("AGScopedEntity",),
        ("vault_id", "scope_id"),
    ),
    SchemaObject(
        "authgraph_scoped_relationship_vault_scope",
        "RANGE",
        "RELATIONSHIP",
        ("AG_SCOPED_LINK",),
        ("vault_id", "scope_id"),
    ),
    SchemaObject(
        "authgraph_public_entity_graph",
        "RANGE",
        "NODE",
        ("AGPublicEntity",),
        ("graph_id",),
    ),
)

_SHOW_CONSTRAINTS = """
SHOW CONSTRAINTS
YIELD name, type, entityType, labelsOrTypes, properties
RETURN name, type, entityType, labelsOrTypes, properties
"""

_SHOW_INDEXES = """
SHOW INDEXES
YIELD name, type, entityType, labelsOrTypes, properties, state
RETURN name, type, entityType, labelsOrTypes, properties, state
"""

_INITIALIZE_SCHEMA_VERSION = """
MERGE (metadata:AGSchemaMetadata {name: 'authgraph'})
ON CREATE SET metadata.version = 1
RETURN metadata.version AS version
"""

_GET_SCHEMA_VERSION = """
MATCH (metadata:AGSchemaMetadata {name: 'authgraph'})
RETURN metadata.version AS version
LIMIT 1
"""

_MIGRATE_V1_PUBLIC_ENTITY_REVISIONS = """
MATCH (entity:AGPublicEntity)
WHERE entity.record_revision IS NULL
SET entity.record_revision = 1
RETURN count(entity) AS updated
"""

_MIGRATE_V1_PUBLIC_RELATIONSHIP_REVISIONS = """
MATCH ()-[link:AG_PUBLIC_LINK]->()
WHERE link.record_revision IS NULL
SET link.record_revision = 1
RETURN count(link) AS updated
"""

_ADVANCE_SCHEMA_VERSION = """
MATCH (metadata:AGSchemaMetadata {name: 'authgraph'})
WHERE metadata.version = $from_version
SET metadata.version = $to_version
RETURN metadata.version AS version
"""

_STATEMENT_NAME = re.compile(
    r"\ACREATE\s+(?:CONSTRAINT|INDEX)\s+([A-Za-z][A-Za-z0-9_]*)\b",
    re.IGNORECASE,
)


def _validate_connection(driver: Any, database: str) -> None:
    if (
        not isinstance(database, str)
        or not database
        or database != database.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in database)
    ):
        raise ValueError("An explicit valid Neo4j database name is required.")
    if getattr(driver, "encrypted", None) is not True:
        raise ValueError(
            "AuthGraph schema operations require an encrypted Neo4j driver."
        )
    if not callable(getattr(driver, "execute_query", None)):
        raise TypeError("driver must provide execute_query().")


def _split_cypher(source: str) -> tuple[str, ...]:
    """Split fixed Cypher while ignoring comments and quoted semicolons."""

    if not isinstance(source, str):
        raise TypeError("Cypher source must be text.")
    statements: list[str] = []
    buffer: list[str] = []
    state = "normal"
    quote = ""
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "line-comment":
            if char in "\r\n":
                buffer.append(char)
                state = "normal"
            index += 1
            continue

        if state == "block-comment":
            if char == "*" and following == "/":
                buffer.append(" ")
                index += 2
                state = "normal"
                continue
            if char in "\r\n":
                buffer.append(char)
            index += 1
            continue

        if state == "quoted":
            buffer.append(char)
            if char == quote:
                if following == quote:
                    buffer.append(following)
                    index += 2
                    continue
                state = "normal"
            elif char == "\\" and quote != "`" and following:
                buffer.append(following)
                index += 2
                continue
            index += 1
            continue

        if char == "/" and following == "/":
            state = "line-comment"
            index += 2
            continue
        if char == "/" and following == "*":
            state = "block-comment"
            index += 2
            continue
        if char in ("'", '"', "`"):
            quote = char
            state = "quoted"
            buffer.append(char)
            index += 1
            continue
        if char == ";":
            statement = "".join(buffer).strip()
            if statement:
                statements.append(statement)
            buffer.clear()
            index += 1
            continue
        buffer.append(char)
        index += 1

    if state in ("block-comment", "quoted"):
        raise Neo4jSchemaError("The packaged Neo4j schema is malformed.")
    final_statement = "".join(buffer).strip()
    if final_statement:
        statements.append(final_statement)
    return tuple(statements)


def schema_statements() -> tuple[str, ...]:
    """Return the immutable statements from AuthGraph's packaged schema."""

    try:
        source = (
            resources.files("authgraph.neo4j")
            .joinpath("schema.cypher")
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        raise Neo4jSchemaError(
            "The packaged AuthGraph Neo4j schema is unavailable."
        ) from exc
    statements = _split_cypher(source)
    expected_names = {
        item.name for item in (*EXPECTED_CONSTRAINTS, *EXPECTED_INDEXES)
    }
    found_names: list[str] = []
    for statement in statements:
        match = _STATEMENT_NAME.match(statement)
        if match is None:
            raise Neo4jSchemaError(
                "The packaged AuthGraph Neo4j schema is malformed."
            )
        found_names.append(match.group(1))
    if (
        len(found_names) != len(expected_names)
        or len(set(found_names)) != len(found_names)
        or set(found_names) != expected_names
    ):
        raise Neo4jSchemaError(
            "The packaged schema and verification manifest disagree."
        )
    return statements


def _records(result: Any) -> list[Any]:
    records = getattr(result, "records", None)
    if records is not None:
        return list(records)
    try:
        return list(result[0])
    except (IndexError, KeyError, TypeError):
        raise SchemaVerificationError(
            message="Neo4j returned an invalid schema result."
        ) from None


def _version_from_result(result: Any) -> int | None:
    records = _records(result)
    if not records:
        return None
    if len(records) != 1:
        raise SchemaVerificationError(
            message="Neo4j returned invalid AuthGraph schema metadata."
        )
    value = _field(records[0], "version")
    if type(value) is not int or value <= 0:
        raise SchemaVerificationError(
            message="Neo4j returned invalid AuthGraph schema metadata."
        )
    return value


def _read_schema_version(driver: Any, database: str) -> int | None:
    try:
        return _version_from_result(
            driver.execute_query(_GET_SCHEMA_VERSION, database_=database)
        )
    except SchemaVerificationError:
        raise
    except Exception as exc:
        raise SchemaVerificationError(
            message="Could not inspect the AuthGraph schema version."
        ) from exc


def apply_migrations(driver: Any, *, database: str) -> int:
    """Apply every fixed, crash-resumable migration to the current version."""

    _validate_connection(driver, database)
    try:
        version = _version_from_result(
            driver.execute_query(
                _INITIALIZE_SCHEMA_VERSION,
                database_=database,
            )
        )
    except SchemaVerificationError as exc:
        raise SchemaMigrationError(0, CURRENT_SCHEMA_VERSION) from exc
    except Exception as exc:
        raise SchemaMigrationError(0, CURRENT_SCHEMA_VERSION) from exc
    if version is None or version > CURRENT_SCHEMA_VERSION:
        raise SchemaMigrationError(
            0 if version is None else version,
            CURRENT_SCHEMA_VERSION,
        )

    while version < CURRENT_SCHEMA_VERSION:
        if version != 1:
            raise SchemaMigrationError(version, CURRENT_SCHEMA_VERSION)
        try:
            driver.execute_query(
                _MIGRATE_V1_PUBLIC_ENTITY_REVISIONS,
                database_=database,
            )
            driver.execute_query(
                _MIGRATE_V1_PUBLIC_RELATIONSHIP_REVISIONS,
                database_=database,
            )
            advanced = _version_from_result(
                driver.execute_query(
                    _ADVANCE_SCHEMA_VERSION,
                    from_version=1,
                    to_version=2,
                    database_=database,
                )
            )
        except SchemaVerificationError as exc:
            raise SchemaMigrationError(1, 2) from exc
        except Exception as exc:
            raise SchemaMigrationError(1, 2) from exc
        if advanced == 2:
            version = 2
            continue
        # Another migrator may have won the compare-and-set after both
        # idempotent backfills completed. Re-read before treating it as a
        # conflict.
        version = _read_schema_version(driver, database) or 0
        if version != 2:
            raise SchemaMigrationError(1, 2)
    return version


def _field(record: Any, name: str) -> Any:
    try:
        return record[name]
    except (IndexError, KeyError, TypeError):
        raise SchemaVerificationError(
            message="Neo4j returned an invalid schema record."
        ) from None


def _text_field(record: Any, name: str) -> str:
    value = _field(record, name)
    if not isinstance(value, str) or not value:
        raise SchemaVerificationError(
            message="Neo4j returned an invalid schema record."
        )
    return value


def _text_tuple_field(record: Any, name: str) -> tuple[str, ...]:
    value = _field(record, name)
    if (
        not isinstance(value, (list, tuple))
        or not value
        or any(not isinstance(item, str) or not item for item in value)
    ):
        raise SchemaVerificationError(
            message="Neo4j returned an invalid schema record."
        )
    return tuple(value)


def _normalized_constraint_type(
    object_type: str,
    entity_type: str,
) -> str:
    if object_type in (
        "NODE_UNIQUENESS",
        "NODE_PROPERTY_UNIQUENESS",
    ):
        return "NODE_PROPERTY_UNIQUENESS"
    if object_type in (
        "RELATIONSHIP_UNIQUENESS",
        "RELATIONSHIP_PROPERTY_UNIQUENESS",
    ):
        return "RELATIONSHIP_PROPERTY_UNIQUENESS"
    if object_type == "UNIQUENESS":
        if entity_type == "NODE":
            return "NODE_PROPERTY_UNIQUENESS"
        if entity_type == "RELATIONSHIP":
            return "RELATIONSHIP_PROPERTY_UNIQUENESS"
    return object_type


def _describe(item: SchemaObject) -> str:
    return (
        f"{item.object_type} {item.entity_type} "
        f"{item.labels_or_types!r} {item.properties!r}"
    )


def _inspect_named_objects(
    records: Iterable[Any],
    expected: tuple[SchemaObject, ...],
    *,
    indexes: bool,
) -> tuple[int, tuple[SchemaProblem, ...]]:
    expected_by_name = {item.name: item for item in expected}
    observed: dict[str, list[tuple[SchemaObject, str | None]]] = {}

    for record in records:
        name = _text_field(record, "name")
        if name not in expected_by_name:
            continue
        entity_type = _text_field(record, "entityType")
        object_type = _text_field(record, "type")
        if not indexes:
            object_type = _normalized_constraint_type(
                object_type,
                entity_type,
            )
        item = SchemaObject(
            name=name,
            object_type=object_type,
            entity_type=entity_type,
            labels_or_types=_text_tuple_field(record, "labelsOrTypes"),
            properties=_text_tuple_field(record, "properties"),
        )
        state = _text_field(record, "state") if indexes else None
        observed.setdefault(name, []).append((item, state))

    problems: list[SchemaProblem] = []
    verified = 0
    for name, wanted in expected_by_name.items():
        matches = observed.get(name, [])
        if not matches:
            problems.append(SchemaProblem(name, "missing"))
            continue
        if len(matches) != 1:
            problems.append(SchemaProblem(name, "returned more than once"))
            continue
        actual, state = matches[0]
        if actual != wanted:
            problems.append(
                SchemaProblem(
                    name,
                    f"expected {_describe(wanted)}, got {_describe(actual)}",
                )
            )
            continue
        if indexes and state != "ONLINE":
            problems.append(
                SchemaProblem(name, f"index state is {state!r}, not 'ONLINE'")
            )
            continue
        verified += 1
    return verified, tuple(problems)


def verify_schema(driver: Any, *, database: str) -> SchemaVerificationReport:
    """Require the exact named constraints and online indexes AuthGraph uses."""

    _validate_connection(driver, database)
    try:
        constraint_result = driver.execute_query(
            _SHOW_CONSTRAINTS,
            database_=database,
        )
        index_result = driver.execute_query(
            _SHOW_INDEXES,
            database_=database,
        )
        constraint_records = _records(constraint_result)
        index_records = _records(index_result)
        schema_version = _read_schema_version(driver, database)
    except SchemaVerificationError:
        raise
    except Exception as exc:
        raise SchemaVerificationError() from exc

    verified_constraints, constraint_problems = _inspect_named_objects(
        constraint_records,
        EXPECTED_CONSTRAINTS,
        indexes=False,
    )
    verified_indexes, index_problems = _inspect_named_objects(
        index_records,
        EXPECTED_INDEXES,
        indexes=True,
    )
    version_problems: tuple[SchemaProblem, ...] = ()
    if schema_version != CURRENT_SCHEMA_VERSION:
        version_problems = (
            SchemaProblem(
                "authgraph_schema_version",
                (
                    "missing"
                    if schema_version is None
                    else f"expected {CURRENT_SCHEMA_VERSION}, got {schema_version}"
                ),
            ),
        )
    report = SchemaVerificationReport(
        verified_constraints=verified_constraints,
        verified_indexes=verified_indexes,
        schema_version=(0 if schema_version is None else schema_version),
        problems=constraint_problems + index_problems + version_problems,
    )
    if not report.is_valid:
        raise SchemaVerificationError(report)
    return report


def apply_schema(driver: Any, *, database: str) -> SchemaVerificationReport:
    """Apply the packaged idempotent schema and verify its exact result."""

    _validate_connection(driver, database)
    for ordinal, statement in enumerate(schema_statements(), start=1):
        match = _STATEMENT_NAME.match(statement)
        if match is None:  # Fenced by schema_statements(); fail closed anyway.
            raise Neo4jSchemaError(
                "The packaged AuthGraph Neo4j schema is malformed."
            )
        try:
            driver.execute_query(statement, database_=database)
        except Exception as exc:
            raise SchemaApplyError(match.group(1), ordinal) from exc
    apply_migrations(driver, database=database)
    return verify_schema(driver, database=database)
