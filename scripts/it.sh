#!/bin/sh
set -e

COMPOSE_FILE="deploy/docker-compose.test.yml"
PROJECT_NAME=${COMPOSE_PROJECT_NAME:-$(basename "$(dirname "$COMPOSE_FILE")")}
NETWORK_NAME="${PROJECT_NAME}_default"
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
AWS_IMAGE=${AWS_IMAGE:-amazon/aws-cli}
PYTHON_IMAGE=${PYTHON_IMAGE:-python:3.12-alpine}
CURL_IMAGE=${CURL_IMAGE:-curlimages/curl:8.5.0}

json_get() {
  field="$1"
  docker run --rm -i "$PYTHON_IMAGE" python -c "import sys, json; data=json.load(sys.stdin); print(data${field})"
}

curl_net() {
  docker run --rm --network "$NETWORK_NAME" "$CURL_IMAGE" "$@"
}

mkdir -p scripts/tmp

cleanup() {
  rm -rf scripts/tmp
}
trap cleanup EXIT

docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" up -d --build

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

TEST_USER="user$(date +%s)"
TEST_PASS="test-pass-123"

curl_net -s -X POST http://master:9001/admin/v1/users \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\",\"displayName\":\"Test User\"}" >/dev/null

CONSOLE_JSON=$(curl_net -s -X POST http://master:9001/console/v1/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}")
CONSOLE_TOKEN=$(printf '%s' "$CONSOLE_JSON" | json_get "['token']")

KEY_JSON=$(curl_net -s -X POST http://master:9001/console/v1/access-keys \
  -H "Authorization: Bearer ${CONSOLE_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"label\":\"integration\"}")
ACCESS_KEY=$(printf '%s' "$KEY_JSON" | json_get "['accessKeyId']")
SECRET_KEY=$(printf '%s' "$KEY_JSON" | json_get "['secretAccessKey']")

BUCKET="it-bucket-${TEST_USER}"
OBJECT="hello.txt"

printf 'hello from integration test' > scripts/tmp/${OBJECT}

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  -v "$(pwd)/scripts/tmp:/data" \
  amazon/aws-cli \
  s3 mb "s3://${BUCKET}" --endpoint-url http://master:9000 --region us-east-1

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  -v "$(pwd)/scripts/tmp:/data" \
  amazon/aws-cli \
  s3 cp "/data/${OBJECT}" "s3://${BUCKET}/${OBJECT}" --endpoint-url http://master:9000 --region us-east-1

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  amazon/aws-cli \
  s3 ls "s3://${BUCKET}" --endpoint-url http://master:9000 --region us-east-1

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  -v "$(pwd)/scripts/tmp:/data" \
  amazon/aws-cli \
  s3 cp "s3://${BUCKET}/${OBJECT}" /data/out.txt --endpoint-url http://master:9000 --region us-east-1

dd if=/dev/zero of=scripts/tmp/large.bin bs=1M count=10 >/dev/null 2>&1

UPLOAD_JSON=$(docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  amazon/aws-cli \
  s3api create-multipart-upload \
    --bucket "$BUCKET" --key large.bin --endpoint-url http://master:9000 \
    --region us-east-1 --query UploadId --output text)
UPLOAD_ID=$(printf '%s' "$UPLOAD_JSON" | tr -d '"')

split -b 5m scripts/tmp/large.bin scripts/tmp/part-
PART1_ETAG=$(docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  -v "$(pwd)/scripts/tmp:/data" \
  amazon/aws-cli \
  s3api upload-part \
    --bucket "$BUCKET" --key large.bin --part-number 1 --upload-id "$UPLOAD_ID" \
    --body /data/part-aa --endpoint-url http://master:9000 --region us-east-1 \
    --query ETag --output text | tr -d '"'
)
PART2_ETAG=$(docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  -v "$(pwd)/scripts/tmp:/data" \
  amazon/aws-cli \
  s3api upload-part \
    --bucket "$BUCKET" --key large.bin --part-number 2 --upload-id "$UPLOAD_ID" \
    --body /data/part-ab --endpoint-url http://master:9000 --region us-east-1 \
    --query ETag --output text | tr -d '"'
)

cat <<EOF_PARTS > scripts/tmp/parts.json
{
  "Parts": [
    {"ETag": "${PART1_ETAG}", "PartNumber": 1},
    {"ETag": "${PART2_ETAG}", "PartNumber": 2}
  ]
}
EOF_PARTS

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  -v "$(pwd)/scripts/tmp:/data" \
  amazon/aws-cli \
  s3api complete-multipart-upload \
    --bucket "$BUCKET" --key large.bin --upload-id "$UPLOAD_ID" \
    --multipart-upload file:///data/parts.json --endpoint-url http://master:9000 \
    --region us-east-1

PRIVATE_BUCKET="presign-private-${TEST_USER}"
PUBLIC_BUCKET="presign-public-${TEST_USER}"
BACKUP_BUCKET="backup-${TEST_USER}"
RESTORE_BUCKET="restore-${TEST_USER}"
PRESIGN_KEY="presign-object.txt"

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  "$AWS_IMAGE" \
  s3 mb "s3://${PRIVATE_BUCKET}" --endpoint-url http://master:9000 --region us-east-1

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  "$AWS_IMAGE" \
  s3 mb "s3://${PUBLIC_BUCKET}" --endpoint-url http://master:9000 --region us-east-1

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  "$AWS_IMAGE" \
  s3 mb "s3://${BACKUP_BUCKET}" --endpoint-url http://master:9000 --region us-east-1

curl_net -s -X PATCH "http://master:9001/admin/v1/storage/buckets/${BACKUP_BUCKET}/worm" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"isWorm":true}' >/dev/null

curl_net -s -X PATCH "http://master:9001/console/v1/buckets/${PUBLIC_BUCKET}" \
  -H "Authorization: Bearer ${CONSOLE_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"publicRead":true}' >/dev/null

PRIVATE_PRESIGN_JSON=$(curl_net -s -X POST http://master:9001/console/v1/presign \
  -H "Authorization: Bearer ${CONSOLE_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"method\":\"PUT\",\"bucket\":\"${PRIVATE_BUCKET}\",\"key\":\"${PRESIGN_KEY}\"}")
PRIVATE_PRESIGN_URL=$(printf '%s' "$PRIVATE_PRESIGN_JSON" | json_get "['url']")

PUBLIC_PRESIGN_JSON=$(curl_net -s -X POST http://master:9001/console/v1/presign \
  -H "Authorization: Bearer ${CONSOLE_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"method\":\"PUT\",\"bucket\":\"${PUBLIC_BUCKET}\",\"key\":\"${PRESIGN_KEY}\"}")
PUBLIC_PRESIGN_URL=$(printf '%s' "$PUBLIC_PRESIGN_JSON" | json_get "['url']")

curl_net -s -X PUT "$PRIVATE_PRESIGN_URL" --data 'private-presigned-upload' >/dev/null
curl_net -s -X PUT "$PUBLIC_PRESIGN_URL" --data 'public-presigned-upload' >/dev/null

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  "$AWS_IMAGE" \
  s3 ls "s3://${PRIVATE_BUCKET}/${PRESIGN_KEY}" --endpoint-url http://master:9000 --region us-east-1 >/dev/null

docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  "$AWS_IMAGE" \
  s3 ls "s3://${PUBLIC_BUCKET}/${PRESIGN_KEY}" --endpoint-url http://master:9000 --region us-east-1 >/dev/null

PUBLIC_URL_JSON=$(curl_net -s \
  -H "Authorization: Bearer ${CONSOLE_TOKEN}" \
  "http://master:9001/console/v1/buckets/${PUBLIC_BUCKET}/object-url/${PRESIGN_KEY}")
PUBLIC_URL=$(printf '%s' "$PUBLIC_URL_JSON" | json_get "['url']")
PUBLIC_URL_FLAG=$(printf '%s' "$PUBLIC_URL_JSON" | json_get "['public']")
if [ "$PUBLIC_URL_FLAG" != "True" ]; then
  echo "expected public URL flag to be true" >&2
  exit 1
fi

PUBLIC_FETCH_BODY=$(curl_net -s "$PUBLIC_URL")
if [ "$PUBLIC_FETCH_BODY" != "public-presigned-upload" ]; then
  echo "expected public unsigned read to return uploaded content" >&2
  exit 1
fi

for BACKUP_TYPE in full incremental differential; do
  POLICY_NAME="policy-${TEST_USER}-${BACKUP_TYPE}"
  RESTORE_NAME="${RESTORE_BUCKET}-${BACKUP_TYPE}"
  BACKUP_POLICY_JSON=$(curl_net -s -X POST http://master:9001/admin/v1/storage/backup-policies \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H 'Content-Type: application/json' \
    -d "{
      \"name\":\"${POLICY_NAME}\",
      \"scope\":\"master\",
      \"sourceBucketName\":\"${BUCKET}\",
      \"backupBucketName\":\"${BACKUP_BUCKET}\",
      \"backupType\":\"${BACKUP_TYPE}\",
      \"scheduleKind\":\"on_demand\",
      \"strategy\":\"3-2-1\",
      \"retentionCount\":2,
      \"enabled\":true,
      \"externalTargets\":[]
    }")
  BACKUP_POLICY_ID=$(printf '%s' "$BACKUP_POLICY_JSON" | json_get "['id']")
  BACKUP_RUN_JSON=$(curl_net -s -X POST "http://master:9001/admin/v1/storage/backups/${BACKUP_POLICY_ID}/run" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}")
  SNAPSHOT_ID=$(printf '%s' "$BACKUP_RUN_JSON" | json_get "['snapshot_id']")
  if [ "$SNAPSHOT_ID" = "None" ] || [ -z "$SNAPSHOT_ID" ]; then
    echo "backup run (${BACKUP_TYPE}) did not return snapshot id" >&2
    exit 1
  fi
  curl_net -s -X POST "http://master:9001/admin/v1/storage/snapshots/${SNAPSHOT_ID}/restore" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H 'Content-Type: application/json' \
    -d "{\"bucketName\":\"${RESTORE_NAME}\"}" >/dev/null
  docker run --rm --network "$NETWORK_NAME" \
    -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
    -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
    -e AWS_EC2_METADATA_DISABLED=true \
    "$AWS_IMAGE" \
    s3 ls "s3://${RESTORE_NAME}/${OBJECT}" --endpoint-url http://master:9000 --region us-east-1 >/dev/null
done

curl_net -s -X PATCH http://master:9001/console/v1/access-keys/${ACCESS_KEY} \
  -H "Authorization: Bearer ${CONSOLE_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"status":"disabled"}' >/dev/null

set +e
FAIL_OUTPUT=$(docker run --rm --network "$NETWORK_NAME" \
  -e AWS_ACCESS_KEY_ID="$ACCESS_KEY" \
  -e AWS_SECRET_ACCESS_KEY="$SECRET_KEY" \
  -e AWS_EC2_METADATA_DISABLED=true \
  amazon/aws-cli \
  s3 ls "s3://${BUCKET}" --endpoint-url http://master:9000 --region us-east-1 2>&1)
EXIT_CODE=$?
set -e
if [ "$EXIT_CODE" -eq 0 ]; then
  echo "expected auth failure after disabling key" >&2
  echo "$FAIL_OUTPUT" >&2
  exit 1
fi

echo "Integration test completed"
