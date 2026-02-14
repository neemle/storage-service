#!/usr/bin/env python3
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

LOKI_CONFIG_TEMPLATE = """auth_enabled: false
server:
  http_listen_port: 3100
common:
  path_prefix: /loki
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
ingester:
  chunk_idle_period: 30s
  max_chunk_age: 1m
  chunk_target_size: 262144
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: s3
      schema: v13
      index:
        prefix: loki_index_
        period: 24h
storage_config:
  aws:
    bucketnames: {bucket}
    endpoint: master:9000
    region: us-east-1
    access_key_id: {access_key_id}
    secret_access_key: {secret_access_key}
    s3forcepathstyle: true
    insecure: true
  tsdb_shipper:
    active_index_directory: /loki/index
    cache_location: /loki/index-cache
compactor:
  working_directory: /loki/compactor
limits_config:
  reject_old_samples: true
  reject_old_samples_max_age: 168h
"""

THANOS_CONFIG_TEMPLATE = """type: S3
config:
  bucket: {bucket}
  endpoint: master:9000
  region: us-east-1
  access_key: {access_key_id}
  secret_key: {secret_access_key}
  insecure: true
"""

def env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value is not None and value != "" else default


def post_json(url: str, payload: dict, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        text = response.read().decode("utf-8")
    return json.loads(text)


def wait_for_endpoint(url: str) -> None:
    for _ in range(120):
        try:
            with urllib.request.urlopen(url, timeout=5):
                return
        except Exception:
            time.sleep(1)
    raise RuntimeError(f"endpoint is not ready: {url}")


def login_with_retries(base_url: str, username: str, password: str) -> dict:
    payload = {"username": username, "password": password}
    login_url = f"{base_url}/console/v1/login"
    for _ in range(10):
        try:
            return post_json(login_url, payload)
        except urllib.error.HTTPError as err:
            if err.code == 429:
                time.sleep(2)
                continue
            raise
    raise RuntimeError("admin login is rate-limited")


def credentials_work(endpoint: str, creds: dict) -> bool:
    try:
        client = build_s3_client(endpoint, creds["access_key_id"], creds["secret_access_key"])
        client.list_buckets()
        return True
    except Exception:
        return False


def build_s3_client(endpoint: str, access_key: str, secret_key: str):
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
    )


def ensure_bucket(client, bucket: str) -> None:
    try:
        client.head_bucket(Bucket=bucket)
        return
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        if code not in {"404", "NoSuchBucket", "NotFound"}:
            raise
    except Exception:
        pass
    try:
        client.create_bucket(Bucket=bucket)
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            raise


def load_cached_credentials(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if "access_key_id" in payload and "secret_access_key" in payload:
        return payload
    return None


def create_access_credentials(base_url: str, username: str, password: str, label: str) -> dict:
    login = login_with_retries(base_url, username, password)
    token = login["token"]
    created = post_json(
        f"{base_url}/console/v1/access-keys",
        {"label": label},
        token=token,
    )
    return {
        "access_key_id": created["accessKeyId"],
        "secret_access_key": created["secretAccessKey"],
    }


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_loki_config(path: Path, bucket: str, creds: dict) -> None:
    content = LOKI_CONFIG_TEMPLATE.format(
        bucket=bucket,
        access_key_id=creds["access_key_id"],
        secret_access_key=creds["secret_access_key"],
    )
    write_file(path, content)


def write_thanos_config(path: Path, bucket: str, creds: dict) -> None:
    content = THANOS_CONFIG_TEMPLATE.format(
        bucket=bucket,
        access_key_id=creds["access_key_id"],
        secret_access_key=creds["secret_access_key"],
    )
    write_file(path, content)


def main() -> None:
    output_dir = Path(env("NSS_OBS_OUTPUT_DIR", "/obs"))
    master_api = env("NSS_OBS_MASTER_URL", "http://master:9001")
    master_s3 = env("NSS_OBS_S3_URL", "http://master:9000")
    metrics_url = env("NSS_OBS_METRICS_URL", "http://master:9100/healthz")
    admin_user = env("NSS_ADMIN_BOOTSTRAP_USER", "admin")
    admin_pass = env("NSS_ADMIN_BOOTSTRAP_PASSWORD", "change-me")
    key_label = env("NSS_OBS_ACCESS_KEY_LABEL", "observability-bootstrap")
    loki_bucket = env("NSS_OBS_LOKI_BUCKET", "nss-observability-loki")
    prom_bucket = env("NSS_OBS_PROM_BUCKET", "nss-observability-prometheus")
    creds_path = output_dir / "credentials.json"

    wait_for_endpoint(metrics_url)
    creds = load_cached_credentials(creds_path)
    if creds is None or not credentials_work(master_s3, creds):
        creds = create_access_credentials(master_api, admin_user, admin_pass, key_label)
        write_file(creds_path, json.dumps(creds, indent=2))

    s3_client = build_s3_client(master_s3, creds["access_key_id"], creds["secret_access_key"])
    ensure_bucket(s3_client, loki_bucket)
    ensure_bucket(s3_client, prom_bucket)
    write_loki_config(output_dir / "loki-config.yml", loki_bucket, creds)
    write_thanos_config(output_dir / "thanos-objstore.yml", prom_bucket, creds)
    print("observability bootstrap complete")


if __name__ == "__main__":
    main()
