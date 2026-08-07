from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from authgraph import cli
from authgraph.neo4j_schema import (
    CURRENT_SCHEMA_VERSION,
    EXPECTED_CONSTRAINTS,
    EXPECTED_INDEXES,
    SchemaApplyError,
    SchemaMigrationError,
    SchemaVerificationError,
    apply_migrations,
    apply_schema,
    schema_statements,
    verify_schema,
)


class FakeResult:
    def __init__(self, records: list[dict[str, object]]) -> None:
        self.records = records


def constraint_records(
    *,
    legacy_type_names: bool = False,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for item in EXPECTED_CONSTRAINTS:
        object_type = item.object_type
        if legacy_type_names:
            if item.entity_type == "NODE":
                object_type = "NODE_UNIQUENESS"
            else:
                object_type = "RELATIONSHIP_UNIQUENESS"
        records.append(
            {
                "name": item.name,
                "type": object_type,
                "entityType": item.entity_type,
                "labelsOrTypes": list(item.labels_or_types),
                "properties": list(item.properties),
            }
        )
    return records


def index_records() -> list[dict[str, object]]:
    return [
        {
            "name": item.name,
            "type": item.object_type,
            "entityType": item.entity_type,
            "labelsOrTypes": list(item.labels_or_types),
            "properties": list(item.properties),
            "state": "ONLINE",
        }
        for item in EXPECTED_INDEXES
    ]


class RecordingDriver:
    encrypted = True

    def __init__(
        self,
        *,
        constraints: list[dict[str, object]] | None = None,
        indexes: list[dict[str, object]] | None = None,
        fail_on: str | None = None,
        schema_version: int | None = CURRENT_SCHEMA_VERSION,
    ) -> None:
        self.constraints = (
            constraint_records() if constraints is None else constraints
        )
        self.indexes = index_records() if indexes is None else indexes
        self.fail_on = fail_on
        self.schema_version = schema_version
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute_query(self, query: str, **kwargs: object) -> FakeResult:
        self.calls.append((query, kwargs))
        if self.fail_on is not None and self.fail_on in query:
            raise RuntimeError("database failure containing secret-value")
        stripped = query.lstrip()
        if stripped.startswith("SHOW CONSTRAINTS"):
            return FakeResult(self.constraints)
        if stripped.startswith("SHOW INDEXES"):
            return FakeResult(self.indexes)
        if stripped.startswith("MERGE (metadata:AGSchemaMetadata"):
            if self.schema_version is None:
                self.schema_version = 1
            return FakeResult([{"version": self.schema_version}])
        if (
            stripped.startswith("MATCH (metadata:AGSchemaMetadata")
            and "$from_version" in query
        ):
            if self.schema_version == kwargs.get("from_version"):
                self.schema_version = int(kwargs["to_version"])
                return FakeResult([{"version": self.schema_version}])
            return FakeResult([])
        if stripped.startswith("MATCH (metadata:AGSchemaMetadata"):
            return FakeResult(
                []
                if self.schema_version is None
                else [{"version": self.schema_version}]
            )
        if "record_revision IS NULL" in query:
            return FakeResult([{"updated": 0}])
        return FakeResult([])


class Neo4jSchemaTests(unittest.TestCase):
    def test_repository_and_packaged_schema_copies_match(self) -> None:
        repository_schema = (
            Path(__file__).resolve().parents[1]
            / "neo4j"
            / "schema.cypher"
        ).read_text(encoding="utf-8")
        packaged_schema = (
            resources.files("authgraph.neo4j")
            .joinpath("schema.cypher")
            .read_text(encoding="utf-8")
        )

        self.assertEqual(packaged_schema, repository_schema)

    def test_packaged_schema_matches_complete_manifest(self) -> None:
        statements = schema_statements()
        expected_names = {
            item.name for item in (*EXPECTED_CONSTRAINTS, *EXPECTED_INDEXES)
        }

        self.assertEqual(len(statements), 16)
        self.assertTrue(
            all(statement.startswith("CREATE ") for statement in statements)
        )
        self.assertEqual(
            {
                statement.split()[2]
                for statement in statements
            },
            expected_names,
        )
        self.assertNotIn("IF NOT EXISTS can otherwise", "\n".join(statements))

    def test_apply_uses_fixed_statements_explicit_database_and_verifies(
        self,
    ) -> None:
        driver = RecordingDriver()

        report = apply_schema(driver, database="authgraph")

        self.assertTrue(report.is_valid)
        self.assertEqual(report.verified_constraints, 10)
        self.assertEqual(report.verified_indexes, 6)
        self.assertEqual(report.schema_version, CURRENT_SCHEMA_VERSION)
        self.assertEqual(len(driver.calls), 20)
        self.assertTrue(
            all(
                kwargs == {"database_": "authgraph"}
                for _, kwargs in driver.calls
            )
        )
        self.assertTrue(
            all(
                query.lstrip().startswith("CREATE ")
                for query, _ in driver.calls[:16]
            )
        )

    def test_apply_is_idempotent_at_the_library_boundary(self) -> None:
        driver = RecordingDriver()

        apply_schema(driver, database="authgraph")
        apply_schema(driver, database="authgraph")

        self.assertEqual(len(driver.calls), 40)

    def test_apply_migrations_backfills_v1_and_advances_version(self) -> None:
        driver = RecordingDriver(schema_version=1)

        version = apply_migrations(driver, database="authgraph")

        self.assertEqual(version, CURRENT_SCHEMA_VERSION)
        self.assertEqual(driver.schema_version, CURRENT_SCHEMA_VERSION)
        self.assertTrue(
            any("AGPublicEntity" in query for query, _ in driver.calls)
        )
        self.assertTrue(
            any("AG_PUBLIC_LINK" in query for query, _ in driver.calls)
        )

    def test_apply_migrations_rejects_unknown_future_version(self) -> None:
        driver = RecordingDriver(schema_version=CURRENT_SCHEMA_VERSION + 1)

        with self.assertRaises(SchemaMigrationError):
            apply_migrations(driver, database="authgraph")

    def test_verify_accepts_neo4j_5_constraint_type_names(self) -> None:
        driver = RecordingDriver(
            constraints=constraint_records(legacy_type_names=True)
        )

        report = verify_schema(driver, database="authgraph")

        self.assertTrue(report.is_valid)

    def test_verify_fails_on_missing_named_object(self) -> None:
        driver = RecordingDriver(constraints=constraint_records()[:-1])

        with self.assertRaises(SchemaVerificationError) as caught:
            verify_schema(driver, database="authgraph")

        report = caught.exception.report
        self.assertIsNotNone(report)
        assert report is not None
        self.assertFalse(report.is_valid)
        self.assertIn(
            "authgraph_public_relationship_id",
            {problem.name for problem in report.problems},
        )

    def test_verify_fails_on_wrong_shape_and_non_online_index(self) -> None:
        constraints = constraint_records()
        vault_index = next(
            index
            for index, record in enumerate(constraints)
            if record["name"] == "authgraph_vault_id"
        )
        constraints[vault_index] = {
            **constraints[vault_index],
            "labelsOrTypes": ["WrongLabel"],
        }
        indexes = index_records()
        indexes[0] = {**indexes[0], "state": "POPULATING"}
        driver = RecordingDriver(
            constraints=constraints,
            indexes=indexes,
        )

        with self.assertRaises(SchemaVerificationError) as caught:
            verify_schema(driver, database="authgraph")

        report = caught.exception.report
        self.assertIsNotNone(report)
        assert report is not None
        problems = {problem.name: problem.reason for problem in report.problems}
        self.assertIn("WrongLabel", problems["authgraph_vault_id"])
        self.assertIn("POPULATING", problems["authgraph_entity_vault"])

    def test_unrelated_schema_objects_do_not_break_verification(self) -> None:
        unrelated = {
            "name": "some_unrelated_label_constraint",
            "type": "NODE_LABEL_EXISTENCE",
            "entityType": "NODE",
            "labelsOrTypes": ["Other"],
            "properties": None,
        }
        driver = RecordingDriver(
            constraints=[unrelated, *constraint_records()]
        )

        self.assertTrue(
            verify_schema(driver, database="authgraph").is_valid
        )

    def test_malformed_expected_record_fails_closed(self) -> None:
        constraints = constraint_records()
        constraints[0] = {**constraints[0], "properties": None}
        driver = RecordingDriver(constraints=constraints)

        with self.assertRaises(SchemaVerificationError):
            verify_schema(driver, database="authgraph")

    def test_unencrypted_or_invalid_database_is_rejected_without_query(
        self,
    ) -> None:
        driver = RecordingDriver()
        driver.encrypted = False

        with self.assertRaises(ValueError):
            verify_schema(driver, database="authgraph")
        self.assertEqual(driver.calls, [])

        driver.encrypted = True
        with self.assertRaises(ValueError):
            verify_schema(driver, database=" authgraph")
        self.assertEqual(driver.calls, [])

    def test_apply_error_names_only_fixed_object_not_database_message(
        self,
    ) -> None:
        driver = RecordingDriver(fail_on="authgraph_entity_id")

        with self.assertRaises(SchemaApplyError) as caught:
            apply_schema(driver, database="authgraph")

        self.assertEqual(
            caught.exception.statement_name,
            "authgraph_entity_id",
        )
        self.assertNotIn("secret-value", str(caught.exception))


class FakeCliDriver(RecordingDriver):
    def __init__(self) -> None:
        super().__init__()
        self.connectivity_verified = False
        self.closed = False

    def __enter__(self) -> FakeCliDriver:
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True

    def verify_connectivity(self) -> None:
        self.connectivity_verified = True


class Neo4jSchemaCliTests(unittest.TestCase):
    @staticmethod
    def write_password(path: Path, value: str) -> None:
        path.write_text(value, encoding="utf-8")
        if os.name == "posix":
            path.chmod(0o600)

    def command(
        self,
        password_path: Path,
        *,
        uri: str = "neo4j+ssc://localhost:7687",
        action: str = "verify",
    ) -> list[str]:
        return [
            "schema",
            action,
            "--uri",
            uri,
            "--database",
            "authgraph",
            "--username",
            "schema-admin",
            "--password-file",
            str(password_path),
            "--no-input",
        ]

    def test_cli_reads_password_file_without_printing_secret(self) -> None:
        driver = FakeCliDriver()
        captured: dict[str, str] = {}
        stdout = io.StringIO()
        stderr = io.StringIO()

        with tempfile.TemporaryDirectory() as directory:
            password_path = Path(directory, "neo4j-password")
            self.write_password(
                password_path,
                "integration-secret\n",
            )

            def open_driver(
                uri: str,
                username: str,
                password: str,
            ) -> FakeCliDriver:
                captured.update(
                    uri=uri,
                    username=username,
                    password=password,
                )
                return driver

            with (
                patch("authgraph.cli._open_driver", side_effect=open_driver),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = cli.main(self.command(password_path))

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured["password"], "integration-secret")
        self.assertTrue(driver.connectivity_verified)
        self.assertTrue(driver.closed)
        combined_output = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("integration-secret", combined_output)
        self.assertIn("10 constraints and 6 indexes", stdout.getvalue())
        self.assertIn("schema v2", stdout.getvalue())

    def test_cli_rejects_unencrypted_or_credential_bearing_uri(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "password")
            self.write_password(path, "secret")

            for uri in (
                "neo4j://localhost:7687",
                "neo4j+s://user:secret@localhost:7687",
                "neo4j+s://localhost:7687?secret=value",
                "neo4j+s://localhost:7687/#fragment",
            ):
                with self.subTest(uri=uri), redirect_stderr(stderr):
                    self.assertEqual(cli.main(self.command(path, uri=uri)), 2)

        self.assertNotIn("user:secret", stderr.getvalue())

    def test_cli_requires_password_file_in_noninteractive_mode(self) -> None:
        stderr = io.StringIO()
        arguments = [
            "schema",
            "verify",
            "--uri",
            "neo4j+s://example.invalid",
            "--database",
            "authgraph",
            "--username",
            "schema-admin",
            "--no-input",
        ]

        with redirect_stderr(stderr):
            exit_code = cli.main(arguments)

        self.assertEqual(exit_code, 2)
        self.assertIn("password file", stderr.getvalue().lower())

    def test_cli_does_not_echo_an_unsupported_password_argument(self) -> None:
        stderr = io.StringIO()
        arguments = [
            "schema",
            "verify",
            "--uri",
            "neo4j+s://example.invalid",
            "--database",
            "authgraph",
            "--username",
            "schema-admin",
            "--password",
            "must-not-be-printed",
        ]

        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            cli.main(arguments)

        self.assertEqual(caught.exception.code, 2)
        self.assertNotIn("must-not-be-printed", stderr.getvalue())

    def test_cli_connection_error_does_not_print_exception_message(
        self,
    ) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "password")
            self.write_password(path, "do-not-print-me")
            with (
                patch(
                    "authgraph.cli._open_driver",
                    side_effect=RuntimeError(
                        "failed with do-not-print-me in message"
                    ),
                ),
                redirect_stdout(stdout),
                redirect_stderr(stderr),
            ):
                exit_code = cli.main(self.command(path))

        self.assertEqual(exit_code, 1)
        self.assertNotIn(
            "do-not-print-me",
            stdout.getvalue() + stderr.getvalue(),
        )

    @unittest.skipUnless(os.name == "posix", "POSIX file modes are required")
    def test_cli_rejects_permissive_or_symlinked_password_files(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory, "target")
            target.write_text("secret", encoding="utf-8")
            target.chmod(0o644)
            with redirect_stderr(stderr):
                self.assertEqual(cli.main(self.command(target)), 2)

            target.chmod(0o600)
            link = Path(directory, "link")
            link.symlink_to(target)
            with redirect_stderr(stderr):
                self.assertEqual(cli.main(self.command(link)), 2)

        self.assertNotIn("secret", stderr.getvalue())

    def test_cli_rejects_multiline_password_file(self) -> None:
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "password")
            self.write_password(path, "first\nsecond\n")
            with redirect_stderr(stderr):
                self.assertEqual(cli.main(self.command(path)), 2)

        self.assertNotIn("first", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
