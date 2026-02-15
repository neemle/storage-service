# Installation Guide

This guide describes how to install and run Neemle Storage Service using Docker.

## Prerequisites

- Docker Engine
- Docker Compose v2
- Optional: AWS CLI for S3 testing

## Demo install (1 master + 2 replicas + observability)

1) Create local env file and set strong credentials:

```bash
cp .env.dist .env
```

- `NSS_ADMIN_BOOTSTRAP_PASSWORD`
- `NSS_SECRET_ENCRYPTION_KEY_BASE64` (32 bytes base64)
- `NSS_JWT_SIGNING_KEY_BASE64` (32 bytes base64, optional but recommended)
- `NSS_CHUNK_ENCRYPTION_ENABLED=true`
- `NSS_CHUNK_ENCRYPTION_ACTIVE_KEY_ID=default`
- `NSS_CHUNK_ENCRYPTION_ALLOW_PLAINTEXT_READ=false`
- `NSS_CHUNK_ENCRYPTION_KEY_BASE64` or `NSS_CHUNK_ENCRYPTION_KEYS` (optional rotation keyring)
- `NSS_INTERNAL_SHARED_TOKEN`

Generate a new encryption key if needed:

```bash
openssl rand -base64 32
```

2) Start the stack:

```bash
docker compose up --build
```

3) Access services:
- Unified Console + Admin UI: `http://localhost:9001`
- Master S3: `http://localhost:9000`
- Replica S3 (read): `http://localhost:9004` and `http://localhost:9005`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000`
- Loki: `http://localhost:3100`

Grafana login defaults:
- Username: `admin`
- Password: `admin`

4) Sign in as the bootstrap admin to create a user, then sign in as that user and create an access key.

5) Test S3:

```bash
aws s3 mb s3://my-bucket --endpoint-url http://localhost:9000 --region us-east-1
aws s3 cp ./file.txt s3://my-bucket/file.txt --endpoint-url http://localhost:9000 --region us-east-1
aws s3 ls s3://my-bucket --endpoint-url http://localhost:9000 --region us-east-1
```

## Replica behavior in demo

- Root compose automatically seeds join tokens and starts both replicas.
- Writes should target master S3 (`:9000`).
- Reads can be served by replicas (`:9004`, `:9005`) using master-issued access keys and presigned URLs.
- Slave mode can be changed remotely from master admin APIs:
  `slave-delivery|slave-backup|slave-volume` (aliases: `delivery|backup|volume`).
- New chunk writes are encrypted at rest by default; keep plaintext-read compatibility disabled unless
  you are migrating legacy plaintext chunk data.

## Snapshot and backup setup

1) Create or select a backup bucket, then mark it WORM (`is_worm=true`) through admin storage API.
2) Create snapshot policies (`hourly|daily|weekly|monthly|on_create_change`) for source buckets.
3) Create backup policies (`full|incremental|differential`) with schedule and retention settings.
4) Trigger an on-demand backup run and verify archive export (`tar` or `tar.gz`).

## Optional services

Enable Redis and RabbitMQ via Docker Compose profiles:

```bash
docker compose --profile redis --profile rabbitmq up --build
```

Then set:
- `NSS_REDIS_URL=redis://redis:6379`
- `NSS_RABBIT_URL=amqp://guest:guest@rabbitmq:5672/`

## Stop and clean up

```bash
docker compose down -v
```

## Production deployment

For a Traefik-backed deployment example, see:
- `docs/traefik/stack.yml`
- `docs/traefik/stack.env`
