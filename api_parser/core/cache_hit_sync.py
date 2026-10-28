# core/cache_hit_sync.py
"""
Periodic edge → backend report of L7 cache-hit breakdowns.

Pulls closed Athens buckets:
  - content_types (hit ratio by content-type family)
  - top_miss_urls (MISS + EXPIRED origin fetches)

POST command: report_cache_hit
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional

import config
from core.api_client import APIClient
from core.athens_cache_stats import fetch_cache_hit_bucket, latest_closed_timestamp
from utils.auth import get_token

SYNC_INTERVAL_SEC = int(getattr(config, "CACHE_HIT_SYNC_INTERVAL", 60))
_last_reported_ts: Optional[int] = None
_lock = threading.Lock()


def build_cache_hit_payload(token: str, bucket: dict) -> dict:
    return {
        "token": token,
        "command": "report_cache_hit",
        "reported_at": int(time.time()),
        "timestamp": int(bucket["timestamp"]),
        "interval_seconds": int(getattr(config, "CACHE_HIT_BUCKET_SECONDS", 60)),
        "content_types": bucket.get("content_types") or [],
        "top_miss_urls": bucket.get("top_miss_urls") or [],
        # Aliases matching Athens metrics API field names.
        "content_type_request_stats": bucket.get("content_type_request_stats")
        or bucket.get("content_types")
        or [],
        "cache_miss_url_stats": bucket.get("cache_miss_url_stats")
        or bucket.get("top_miss_urls")
        or [],
        "content_types_count": len(bucket.get("content_types") or []),
        "top_miss_urls_count": len(bucket.get("top_miss_urls") or []),
    }


def report_cache_hit_once(force: bool = False) -> bool:
    """Fetch latest closed Athens bucket and POST to panel. Returns True on success."""
    global _last_reported_ts

    token = get_token()
    if not token:
        print("[CACHE_HIT_SYNC] No API token; skipping report", flush=True)
        return False

    ok_ts, ts_or_err = latest_closed_timestamp("content_type_request_stats")
    if not ok_ts:
        print(f"[CACHE_HIT_SYNC] No Athens timestamp yet: {ts_or_err}", flush=True)
        return False
    timestamp = int(ts_or_err)

    with _lock:
        if not force and _last_reported_ts is not None and timestamp <= _last_reported_ts:
            return True

    ok, bucket_or_err = fetch_cache_hit_bucket(timestamp)
    if not ok:
        print(f"[CACHE_HIT_SYNC] Failed to fetch Athens stats: {bucket_or_err}", flush=True)
        return False

    payload = build_cache_hit_payload(token, bucket_or_err)
    ok = APIClient.report_cache_hit(payload)
    if ok:
        with _lock:
            _last_reported_ts = timestamp
        print(
            f"[CACHE_HIT_SYNC] Reported cache hit "
            f"ts={timestamp} content_types={payload['content_types_count']} "
            f"top_miss_urls={payload['top_miss_urls_count']}",
            flush=True,
        )
    else:
        print("[CACHE_HIT_SYNC] Backend report failed", flush=True)
    return ok


def _run_sync_loop() -> None:
    pid = os.getpid()
    thread_name = threading.current_thread().name
    print(
        f"[CACHE_HIT_SYNC] pid={pid} thread={thread_name} "
        f"starting (interval={SYNC_INTERVAL_SEC}s)",
        flush=True,
    )
    # First pass shortly after boot so UI is not empty for a full interval.
    time.sleep(min(15, max(5, SYNC_INTERVAL_SEC // 4)))
    while True:
        try:
            report_cache_hit_once()
        except Exception as exc:
            print(f"[CACHE_HIT_SYNC] Unexpected error: {exc}", flush=True)
        time.sleep(SYNC_INTERVAL_SEC)


def start_cache_hit_sync() -> threading.Thread:
    thread = threading.Thread(
        target=_run_sync_loop, daemon=True, name="cache_hit_sync"
    )
    thread.start()
    return thread
