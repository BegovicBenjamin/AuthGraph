#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  echo "usage: start-neo4j-tls.sh IMAGE PASSWORD_FILE [PORT]" >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
  usage
  exit 2
fi

image=$1
password_file=$2
port=${3:-7687}
python_command=${AUTHGRAPH_CI_PYTHON:-python}

if [[ ! -f "$password_file" ]]; then
  echo "Neo4j password file is not a regular file." >&2
  exit 2
fi
if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
  echo "Neo4j port must be between 1 and 65535." >&2
  exit 2
fi
if ! command -v "$python_command" >/dev/null 2>&1; then
  echo "The configured Python command is unavailable." >&2
  exit 2
fi
if ! "$python_command" -c 'from neo4j import GraphDatabase' >/dev/null 2>&1; then
  echo "The configured Python environment does not contain the Neo4j driver." >&2
  exit 2
fi

password=$(<"$password_file")
if [[ -z "$password" || "$password" == *$'\n'* || "$password" == *$'\r'* ]]; then
  password=""
  echo "Neo4j password file must contain exactly one non-empty line." >&2
  exit 2
fi

run_identity=${GITHUB_RUN_ID:-local}
run_attempt=${GITHUB_RUN_ATTEMPT:-1}
matrix_identity=${AUTHGRAPH_NEO4J_JOB_ID:-job}
run_nonce=$(openssl rand -hex 4)
safe_identity=$(printf '%s-%s-%s-%s' "$run_identity" "$run_attempt" "$matrix_identity" "$run_nonce" | tr -cd 'A-Za-z0-9_.-')
container_name="authgraph-neo4j-${safe_identity}"
certificate_volume="authgraph-neo4j-certs-${safe_identity}"
certificate_source=$(mktemp -d "${RUNNER_TEMP:-/tmp}/authgraph-neo4j-certs.XXXXXX")

cleanup_on_exit() {
  password=""
  docker rm --force "$container_name" >/dev/null 2>&1 || true
  docker volume rm --force "$certificate_volume" >/dev/null 2>&1 || true
  rm -rf -- "$certificate_source"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$certificate_source/bolt/trusted" "$certificate_source/bolt/revoked"
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -sha256 \
  -nodes \
  -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$certificate_source/bolt/private.key" \
  -out "$certificate_source/bolt/public.crt" \
  >/dev/null 2>&1
chmod 600 "$certificate_source/bolt/private.key"
cp "$certificate_source/bolt/public.crt" "$certificate_source/bolt/trusted/public.crt"

docker pull "$image"
docker volume create "$certificate_volume" >/dev/null
docker run --rm \
  --user root \
  --entrypoint /bin/sh \
  --volume "$certificate_volume:/target" \
  --volume "$certificate_source:/source:ro" \
  "$image" \
  -c 'cp -R /source/. /target/ && chown -R neo4j:neo4j /target && chmod 400 /target/bolt/private.key'

docker run --detach \
  --name "$container_name" \
  --publish "127.0.0.1:${port}:7687" \
  --env "NEO4J_AUTH=neo4j/${password}" \
  --env NEO4J_server_bolt_tls__level=REQUIRED \
  --env NEO4J_dbms_ssl_policy_bolt_enabled=true \
  --env NEO4J_dbms_ssl_policy_bolt_base__directory=certificates/bolt \
  --env NEO4J_dbms_ssl_policy_bolt_private__key=private.key \
  --env NEO4J_dbms_ssl_policy_bolt_public__certificate=public.crt \
  --env NEO4J_dbms_ssl_policy_bolt_client__auth=NONE \
  --volume "$certificate_volume:/var/lib/neo4j/certificates" \
  "$image" \
  >/dev/null
password=""

ready=0
for _ in $(seq 1 90); do
  if "$python_command" - "$password_file" "$port" >/dev/null 2>&1 <<'PY'
from pathlib import Path
import sys

from neo4j import GraphDatabase

password = Path(sys.argv[1]).read_text(encoding="utf-8").rstrip("\r\n")
driver = GraphDatabase.driver(
    f"bolt+ssc://127.0.0.1:{sys.argv[2]}",
    auth=("neo4j", password),
)
try:
    driver.verify_connectivity()
finally:
    driver.close()
PY
  then
    ready=1
    break
  fi
  if ! docker inspect --format '{{.State.Running}}' "$container_name" 2>/dev/null | grep -qx true; then
    break
  fi
  sleep 2
done

if (( ready != 1 )); then
  echo "Neo4j did not become ready with required TLS." >&2
  docker logs "$container_name" >&2 || true
  exit 1
fi

rm -rf -- "$certificate_source"
trap - EXIT INT TERM

if [[ -n "${GITHUB_ENV:-}" ]]; then
  {
    echo "AUTHGRAPH_TEST_NEO4J_URI=bolt+ssc://127.0.0.1:${port}"
    echo "AUTHGRAPH_TEST_NEO4J_USERNAME=neo4j"
    echo "AUTHGRAPH_TEST_NEO4J_PASSWORD_FILE=${password_file}"
    echo "AUTHGRAPH_TEST_NEO4J_DATABASE=neo4j"
    echo "AUTHGRAPH_NEO4J_CONTAINER=${container_name}"
    echo "AUTHGRAPH_NEO4J_CERTIFICATE_VOLUME=${certificate_volume}"
  } >>"$GITHUB_ENV"
else
  echo "Neo4j is ready at bolt+ssc://127.0.0.1:${port}."
  echo "Container: ${container_name}"
  echo "Certificate volume: ${certificate_volume}"
fi
