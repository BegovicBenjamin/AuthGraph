"""Small deployment CLI for AuthGraph's packaged Neo4j schema."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

from .neo4j_schema import (
    EXPECTED_CONSTRAINTS,
    EXPECTED_INDEXES,
    SchemaApplyError,
    SchemaVerificationError,
    apply_schema,
    verify_schema,
)


_SECURE_NEO4J_SCHEMES = {
    "bolt+s",
    "bolt+ssc",
    "neo4j+s",
    "neo4j+ssc",
}
_MAX_SECRET_FILE_BYTES = 64 * 1024


class _CliInputError(ValueError):
    pass


class _CliRuntimeError(RuntimeError):
    pass


class _SafeArgumentParser(argparse.ArgumentParser):
    """Do not echo unrecognized argument values that might be secrets."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="authgraph",
        description="AuthGraph deployment utilities.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    schema = commands.add_parser(
        "schema",
        help="Install or verify the fixed AuthGraph Neo4j schema.",
    )
    schema_commands = schema.add_subparsers(
        dest="schema_command",
        required=True,
    )
    for name in ("apply", "verify"):
        command = schema_commands.add_parser(
            name,
            help=f"{name.capitalize()} the AuthGraph Neo4j schema.",
        )
        command.add_argument(
            "--uri",
            default=os.environ.get("AUTHGRAPH_NEO4J_URI"),
            help="Encrypted Neo4j URI (or AUTHGRAPH_NEO4J_URI).",
        )
        command.add_argument(
            "--database",
            default=os.environ.get("AUTHGRAPH_NEO4J_DATABASE"),
            help="Explicit database name (or AUTHGRAPH_NEO4J_DATABASE).",
        )
        command.add_argument(
            "--username",
            default=os.environ.get("AUTHGRAPH_NEO4J_USERNAME"),
            help="Neo4j username (or AUTHGRAPH_NEO4J_USERNAME).",
        )
        command.add_argument(
            "--password-file",
            default=os.environ.get("AUTHGRAPH_NEO4J_PASSWORD_FILE"),
            help=(
                "Read the password from a file "
                "(or AUTHGRAPH_NEO4J_PASSWORD_FILE)."
            ),
        )
        command.add_argument(
            "--no-input",
            action="store_true",
            help="Fail instead of prompting when no password file is given.",
        )
    return parser


def _required_text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise _CliInputError(f"{label} is required and must be valid text.")
    return value


def _validated_uri(value: Any) -> str:
    uri = _required_text(value, "Neo4j URI")
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError as exc:
        raise _CliInputError("Neo4j URI is invalid.") from exc
    if (
        parsed.scheme not in _SECURE_NEO4J_SCHEMES
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise _CliInputError(
            "Use a +s or +ssc Neo4j URI without embedded credentials."
        )
    return uri


def _read_password(path_value: Any, *, no_input: bool) -> str:
    if path_value is None:
        if no_input:
            raise _CliInputError(
                "A password file is required when --no-input is used."
            )
        try:
            password = getpass.getpass("Neo4j password: ")
        except (EOFError, KeyboardInterrupt):
            raise _CliInputError("Could not read the Neo4j password.") from None
    else:
        path_text = _required_text(path_value, "Password file")
        path = Path(path_text)
        try:
            if not path.is_file() or path.stat().st_size > _MAX_SECRET_FILE_BYTES:
                raise _CliInputError(
                    "Password file must be a small regular file."
                )
            password = path.read_text(encoding="utf-8")
        except _CliInputError:
            raise
        except (OSError, UnicodeError) as exc:
            raise _CliInputError("Could not read the password file.") from exc
        if password.endswith("\r\n"):
            password = password[:-2]
        elif password.endswith("\n"):
            password = password[:-1]

    if not password or "\x00" in password:
        raise _CliInputError("Neo4j password must not be empty.")
    return password


def _open_driver(uri: str, username: str, password: str) -> Any:
    try:
        from neo4j import GraphDatabase
    except (ImportError, AttributeError) as exc:
        raise _CliRuntimeError(
            "The Neo4j Python driver is not installed."
        ) from exc
    return GraphDatabase.driver(uri, auth=(username, password))


def _print_verification_failure(exc: SchemaVerificationError) -> None:
    if exc.report is None:
        print("AuthGraph could not inspect the Neo4j schema.", file=sys.stderr)
        return
    print(
        "The Neo4j database does not have the exact AuthGraph schema:",
        file=sys.stderr,
    )
    for problem in exc.report.problems:
        print(f"- {problem.name}: {problem.reason}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the schema command without ever accepting a plaintext password arg."""

    args = _parser().parse_args(argv)
    try:
        uri = _validated_uri(args.uri)
        database = _required_text(args.database, "Database name")
        username = _required_text(args.username, "Neo4j username")
        password = _read_password(
            args.password_file,
            no_input=args.no_input,
        )
    except _CliInputError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    try:
        with _open_driver(uri, username, password) as driver:
            driver.verify_connectivity()
            if args.schema_command == "apply":
                apply_schema(driver, database=database)
                action = "applied and verified"
            else:
                verify_schema(driver, database=database)
                action = "verified"
    except SchemaVerificationError as exc:
        _print_verification_failure(exc)
        return 2
    except SchemaApplyError as exc:
        print(
            f"AuthGraph could not apply schema object "
            f"{exc.statement_name!r}.",
            file=sys.stderr,
        )
        return 1
    except (KeyboardInterrupt, _CliRuntimeError):
        print(
            "AuthGraph schema operation was interrupted or unavailable.",
            file=sys.stderr,
        )
        return 1
    except Exception as exc:
        print(
            f"AuthGraph schema operation failed ({type(exc).__name__}).",
            file=sys.stderr,
        )
        return 1
    finally:
        password = ""

    print(
        f"AuthGraph schema {action}: "
        f"{len(EXPECTED_CONSTRAINTS)} constraints and "
        f"{len(EXPECTED_INDEXES)} indexes."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
