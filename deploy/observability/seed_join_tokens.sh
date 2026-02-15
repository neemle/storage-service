#!/bin/sh
set -eu

DB_HOST=${DB_HOST:-postgres}
DB_PORT=${DB_PORT:-5432}
DB_USER=${DB_USER:-nss}
DB_PASS=${DB_PASS:-nss}
DB_BASE=${DB_BASE:-nss}
TOKEN_ONE=${NSS_REPLICA1_JOIN_TOKEN:?NSS_REPLICA1_JOIN_TOKEN is required}
TOKEN_TWO=${NSS_REPLICA2_JOIN_TOKEN:?NSS_REPLICA2_JOIN_TOKEN is required}
TOKEN_THREE=${NSS_REPLICA3_JOIN_TOKEN:?NSS_REPLICA3_JOIN_TOKEN is required}

export PGPASSWORD="$DB_PASS"

wait_for_db() {
  for _ in $(seq 1 60); do
    if pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_BASE" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "postgres is not ready" >&2
  return 1
}

wait_for_join_table() {
  for _ in $(seq 1 60); do
    found=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_BASE" -tAc \
      "SELECT to_regclass('public.join_tokens') IS NOT NULL;")
    found=$(printf '%s' "$found" | tr -d '[:space:]')
    if [ "$found" = "t" ]; then
      return 0
    fi
    sleep 1
  done
  echo "join_tokens table is not ready" >&2
  return 1
}

wait_for_db
wait_for_join_table

HASH_ONE=$(printf '%s' "$TOKEN_ONE" | sha256sum | awk '{print $1}')
HASH_TWO=$(printf '%s' "$TOKEN_TWO" | sha256sum | awk '{print $1}')
HASH_THREE=$(printf '%s' "$TOKEN_THREE" | sha256sum | awk '{print $1}')

psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_BASE" <<SQL
DELETE FROM join_tokens
WHERE token_hash IN ('$HASH_ONE', '$HASH_TWO', '$HASH_THREE');
INSERT INTO join_tokens (token_id, token_hash, expires_at, used_at)
VALUES (uuid_generate_v4(), '$HASH_ONE', now() + interval '30 days', NULL);
INSERT INTO join_tokens (token_id, token_hash, expires_at, used_at)
VALUES (uuid_generate_v4(), '$HASH_TWO', now() + interval '30 days', NULL);
INSERT INTO join_tokens (token_id, token_hash, expires_at, used_at)
VALUES (uuid_generate_v4(), '$HASH_THREE', now() + interval '30 days', NULL);
SQL

echo "seeded replica join tokens"
