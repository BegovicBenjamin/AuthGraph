#!/usr/bin/env python3
"""Smoke-test an installed AuthGraph wheel outside the source checkout."""

from __future__ import annotations

import argparse
import importlib.metadata
import importlib.resources
import json
import os
import subprocess
import sys
from pathlib import Path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--expected-version",
        help="Fail unless the installed distribution has this exact version.",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="Fail if authgraph imports from this source checkout.",
    )
    return parser


def main() -> int:
    arguments = _parser().parse_args()

    import authgraph

    installed_version = importlib.metadata.version("authgraph")
    module_version = getattr(authgraph, "__version__", None)
    if module_version != installed_version:
        raise RuntimeError(
            "AuthGraph module and distribution versions do not match."
        )
    if (
        arguments.expected_version is not None
        and installed_version != arguments.expected_version
    ):
        raise RuntimeError(
            "Installed AuthGraph version does not match the release version."
        )

    module_path = Path(authgraph.__file__).resolve()
    source_root = arguments.source_root.resolve()
    try:
        module_path.relative_to(source_root)
    except ValueError:
        pass
    else:
        raise RuntimeError("AuthGraph imported from the source checkout.")

    schema = importlib.resources.files("authgraph.neo4j").joinpath(
        "schema.cypher"
    )
    schema_text = schema.read_text(encoding="utf-8")
    if "CREATE CONSTRAINT" not in schema_text or "CREATE INDEX" not in schema_text:
        raise RuntimeError("The wheel is missing the complete packaged schema.")

    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    cli = subprocess.run(
        [sys.executable, "-m", "authgraph.cli", "--help"],
        check=False,
        cwd=Path.cwd(),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
    )
    if cli.returncode != 0 or "AuthGraph deployment utilities" not in cli.stdout:
        raise RuntimeError("The installed AuthGraph CLI smoke test failed.")

    print(
        json.dumps(
            {
                "distribution": "authgraph",
                "version": installed_version,
                "module_version": module_version,
                "schema_bytes": len(schema_text.encode("utf-8")),
                "source_checkout_imported": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
