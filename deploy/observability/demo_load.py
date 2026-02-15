#!/usr/bin/env python3
import json
import os
import time
import urllib.request
from pathlib import Path

import boto3
from botocore.config import Config


def env(name: str, default: str) -> str:
    value = os.getenv(name)
    return value if value is not None and value != "" else default


def load_credentials(path: Path) -> dict:
    for _ in range(180):
        if path.exists():
            payload = json.loads(path.read_text(encoding="utf-8"))
            if "access_key_id" in payload and "secret_access_key" in payload:
                return payload
        time.sleep(1)
    raise RuntimeError("credentials file was not created")


def build_s3_client(endpoint: str, creds: dict):
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        config=Config(signature_version="s3v4"),
    )


def ensure_bucket(client, bucket: str) -> None:
    try:
        client.head_bucket(Bucket=bucket)
    except Exception:
        client.create_bucket(Bucket=bucket)


def probe_http(url: str) -> None:
    try:
        with urllib.request.urlopen(url, timeout=3):
            return
    except Exception:
        return


def is_transient_read_error(err: Exception) -> bool:
    message = str(err)
    transient_markers = (
        "IncompleteRead",
        "Connection broken",
        "no valid replicas",
        "NoSuchKey",
    )
    return any(marker in message for marker in transient_markers)


def read_replica_object(client, bucket: str, key: str) -> bool:
    for attempt in range(3):
        try:
            response = client.get_object(Bucket=bucket, Key=key)
            body = response["Body"]
            try:
                body.read()
            finally:
                body.close()
            return True
        except Exception as err:
            if not is_transient_read_error(err):
                raise
            time.sleep(0.2 * (attempt + 1))
    return False


def add_key(recent_keys: list[str], key: str) -> None:
    recent_keys.append(key)
    if len(recent_keys) > 16:
        del recent_keys[0]


def select_replica_read_key(recent_keys: list[str]) -> str | None:
    return recent_keys[0] if len(recent_keys) >= 4 else None


def observe_replica_reads(
    bucket: str,
    key: str | None,
    replica_one,
    transient_failures: int,
    replica_two=None,
) -> int:
    if key is None:
        return transient_failures
    read_one = read_replica_object(replica_one, bucket, key)
    read_two = True if replica_two is None else read_replica_object(replica_two, bucket, key)
    if read_one and read_two:
        return 0
    next_failures = transient_failures + 1
    if next_failures % 30 == 0:
        print(
            "demo-load: transient replica read retries are still failing "
            f"(count={next_failures}, key={key})"
        )
    return next_failures


def run_loop(bucket: str, master, replica_one, replica_two=None) -> None:
    counter = 0
    recent_keys: list[str] = []
    transient_failures = 0
    while True:
        key = f"demo/obj-{counter % 512}.txt"
        body = f"demo payload #{counter} at {time.time()}".encode("utf-8")
        try:
            master.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain")
            master.list_objects_v2(Bucket=bucket, Prefix="demo/", MaxKeys=50)
            add_key(recent_keys, key)
            read_key = select_replica_read_key(recent_keys)
            transient_failures = observe_replica_reads(
                bucket,
                read_key,
                replica_one,
                transient_failures,
                replica_two,
            )
        except Exception as err:
            print(f"demo-load iteration failed: {err}")
        probe_http("http://master:9100/metrics")
        probe_http("http://replica1:9100/metrics")
        probe_http("http://replica2:9100/metrics")
        probe_http("http://replica3:9100/metrics")
        counter += 1
        time.sleep(2)


def main() -> None:
    obs_dir = Path(env("NSS_OBS_OUTPUT_DIR", "/obs"))
    demo_bucket = env("NSS_OBS_DEMO_BUCKET", "nss-observability-demo")
    creds = load_credentials(obs_dir / "credentials.json")

    master = build_s3_client("http://master:9000", creds)
    replica_one = build_s3_client(env("NSS_OBS_DELIVERY_PRIMARY_URL", "http://replica1:9000"), creds)
    secondary_url = env("NSS_OBS_DELIVERY_SECONDARY_URL", "")
    replica_two = build_s3_client(secondary_url, creds) if secondary_url else None
    ensure_bucket(master, demo_bucket)

    print("demo load generator running")
    run_loop(demo_bucket, master, replica_one, replica_two)


if __name__ == "__main__":
    main()
