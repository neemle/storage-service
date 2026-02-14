#!/bin/sh
set -e

COMPOSE_FILE="deploy/docker-compose.test.yml"
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-deploy-cluster}
NETWORK_NAME="${PROJECT_NAME}_default"
CURL_IMAGE=${CURL_IMAGE:-curlimages/curl:8.5.0}
PYTHON_IMAGE=${PYTHON_IMAGE:-python:3.12-alpine}
AWS_IMAGE=${AWS_IMAGE:-amazon/aws-cli}
ENV_FILE=${NSS_ENV_FILE:-.env}

dotenv_value() {
  key="$1"
  file="$2"
  [ -f "$file" ] || return 1
  value=$(sed -n "s/^${key}=//p" "$file" | head -n 1)
  [ -n "$value" ] || return 1
  printf '%s' "$value"
}

DOTENV_ADMIN_USER=$(dotenv_value NSS_ADMIN_BOOTSTRAP_USER "$ENV_FILE" || true)
DOTENV_ADMIN_PASS=$(dotenv_value NSS_ADMIN_BOOTSTRAP_PASSWORD "$ENV_FILE" || true)

ADMIN_USER=${NSS_ADMIN_BOOTSTRAP_USER:-${DOTENV_ADMIN_USER:-admin}}
ADMIN_PASS=${NSS_ADMIN_BOOTSTRAP_PASSWORD:-${DOTENV_ADMIN_PASS:-change-me}}

curl_net() {
  docker run --rm --network "$NETWORK_NAME" "$CURL_IMAGE" "$@"
}

json_get() {
  field="$1"
  docker run --rm -i "$PYTHON_IMAGE" python -c "import sys, json; data=json.load(sys.stdin); print(data${field})"
}

json_len() {
  docker run --rm -i "$PYTHON_IMAGE" python -c "import sys, json; data=json.load(sys.stdin); print(len(data))"
}

cleanup() {
  rm -rf scripts/tmp
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up -d --build postgres master

echo "Waiting for master to be ready..."
for i in $(seq 1 30); do
  if curl_net -sf http://master:9100/readyz >/dev/null; then
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "master not ready" >&2
    exit 1
  fi
done

ADMIN_JSON=$(curl_net -s -X POST http://master:9001/admin/v1/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")
ADMIN_TOKEN=$(printf '%s' "$ADMIN_JSON" | json_get "['token']")

JOIN_JSON=$(curl_net -s -X POST http://master:9001/admin/v1/cluster/join-tokens \
  -H "Authorization: Bearer ${ADMIN_TOKEN}")
JOIN_TOKEN=$(printf '%s' "$JOIN_JSON" | json_get "['token']")

NSS_JOIN_TOKEN="$JOIN_TOKEN" \
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" --profile replica up -d --build replica

echo "Waiting for replica to be healthy..."
for i in $(seq 1 30); do
  if curl_net -sf http://replica:9100/healthz >/dev/null; then
    break
  fi
  sleep 2
  if [ "$i" -eq 30 ]; then
    echo "replica not healthy" >&2
    docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" logs --no-color --tail=200 replica || true
    docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" logs --no-color --tail=200 master || true
    exit 1
  fi
done

NODES_JSON=$(curl_net -s -H "Authorization: Bearer ${ADMIN_TOKEN}" http://master:9001/admin/v1/cluster/nodes)
NODE_COUNT=$(printf '%s' "$NODES_JSON" | json_len)
if [ "$NODE_COUNT" -lt 2 ]; then
  echo "expected at least 2 nodes, got ${NODE_COUNT}" >&2
  exit 1
fi

CONSOLE_JSON=$(curl_net -s -X POST http://master:9001/console/v1/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")
CONSOLE_TOKEN=$(printf '%s' "$CONSOLE_JSON" | json_get "['token']")

KEY_JSON=$(curl_net -s -X POST http://master:9001/console/v1/access-keys \
  -H "Authorization: Bearer ${CONSOLE_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"label\":\"cluster-test\"}")
ACCESS_KEY=$(printf '%s' "$KEY_JSON" | json_get "['accessKeyId']")
SECRET_KEY=$(printf '%s' "$KEY_JSON" | json_get "['secretAccessKey']")

mkdir -p scripts/tmp
printf 'cluster payload' > scripts/tmp/cluster.txt

BUCKET="cluster-bucket-$(date +%s)"

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  -v "$(pwd)/scripts/tmp:/data" \
  "$AWS_IMAGE" \
  s3 mb "s3://${BUCKET}" --endpoint-url http://master:9000 --region us-east-1

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  -v "$(pwd)/scripts/tmp:/data" \
  "$AWS_IMAGE" \
  s3 cp /data/cluster.txt "s3://${BUCKET}/cluster.txt" --endpoint-url http://master:9000 --region us-east-1

REPLICA_COUNT=$(docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" exec -T postgres \
  psql -U nss -d nss -t -c "SELECT count(*) FROM chunk_replicas;")
REPLICA_COUNT=$(printf '%s' "$REPLICA_COUNT" | tr -d '[:space:]')
if [ "$REPLICA_COUNT" -lt 1 ]; then
  echo "expected chunk replicas, got ${REPLICA_COUNT}" >&2
  exit 1
fi

REPLICA_NODES=$(docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" exec -T postgres \
  psql -U nss -d nss -t -c "SELECT count(*) FROM nodes WHERE role='replica' AND status='online';")
REPLICA_NODES=$(printf '%s' "$REPLICA_NODES" | tr -d '[:space:]')
if [ "$REPLICA_NODES" -lt 1 ]; then
  echo "expected online replica node, got ${REPLICA_NODES}" >&2
  exit 1
fi

echo "Cluster tests completed"
