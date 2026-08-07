# Releasing AuthGraph

Releases are built from a clean, reviewed commit. A release does not change the
project's prototype status or authorize real sensitive data.

## 1. Prepare

1. Choose a semantic version. AuthGraph is below 1.0, so incompatible API
   changes require at least a minor-version increase.
2. Update `project.version` in `pyproject.toml`.
3. Move relevant entries from `Unreleased` in `CHANGELOG.md` into a dated
   version section.
4. Update `docs/SUPPORTED_VERSIONS.md` only after the matching CI jobs pass.
5. Confirm that README and security-model limitations are still accurate.
6. Review the diff for credentials, customer data, generated databases, and
   local demo files.

## 2. Run local checks

```bash
python3 -m pip install -e '.[dev]'
python3 -m ruff check src tests scripts
python3 -m mypy src/authgraph
python3 -X dev -m unittest discover -s tests -v
python3 -m pip_audit --strict --progress-spinner off .
python3 -m build
python3 -m twine check dist/*
```

Build into an empty output directory or remove previously reviewed artifacts
from `dist/` first. Never publish a wildcard that may include an older build.

Test the built wheel outside the checkout:

```bash
release_smoke_dir=$(mktemp -d)
python3 -m venv "$release_smoke_dir/venv"
"$release_smoke_dir/venv/bin/python" -m pip install dist/*.whl
cd "$release_smoke_dir"
"$release_smoke_dir/venv/bin/python" \
  /absolute/path/to/AuthGraph/scripts/ci/installed-wheel-smoke.py \
  --expected-version VERSION \
  --source-root /absolute/path/to/AuthGraph
```

Delete the temporary directory after inspecting the result. Windows users can
run the same helper with the virtual environment's `Scripts/python.exe`.

## 3. Require CI evidence

Before tagging, require all jobs in `.github/workflows/ci.yml` and
`.github/workflows/live-neo4j.yml` to pass for the exact commit. The live job
must apply and verify the schema over TLS and run the opt-in integration suite.

Review:

- Python 3.11 through 3.14 unit results;
- minimum and current dependency results;
- Linux, Windows, and macOS results;
- every documented Neo4j compatibility point;
- wheel and source-distribution metadata;
- strict package typing;
- installed-wheel smoke output; and
- dependency-audit output.

Do not waive a failed security, packaging, schema, isolation, or cleanup check
for a public release.

## 4. Tag and build

Create a tag that exactly matches `pyproject.toml`:

```bash
git tag -s vVERSION -m "AuthGraph vVERSION"
git push origin vVERSION
```

Pushing the tag runs `.github/workflows/release.yml`. It builds and uploads
checked artifacts and hashes, but it does not publish a package automatically.
Download the workflow artifact and confirm it contains only:

- one wheel and one source distribution;
- `SHA256SUMS`; and
- dependency-audit evidence.

## 5. TestPyPI and PyPI

Configure `testpypi` and `pypi` GitHub environments with required reviewers and
PyPI trusted publishing. Do not store long-lived PyPI tokens in the repository.
Also enable and test GitHub private vulnerability reporting so the contact in
`SECURITY.md` is available before publishing.

First dispatch the release workflow against the exact tag with
`publish_target=testpypi`. Install that version in a clean environment:

```bash
python3 -m venv /tmp/authgraph-testpypi
/tmp/authgraph-testpypi/bin/python -m pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  authgraph==VERSION
```

Run the installed-wheel smoke helper again. Only after review, dispatch the same
tag with `publish_target=pypi` and approve the protected `pypi` environment.
Package index versions are immutable; fix a bad release with a new version. Yank
an unsafe version through the package index and add a clear changelog warning.

## 6. Publish release notes

Release notes should link the changelog, list tested Python/Neo4j versions,
identify incompatible changes, repeat the synthetic-data-only warning, and list
known security and operational gaps. Never attach raw CI databases, credentials,
OTP values, model prompts, or ignored local-demo files.
