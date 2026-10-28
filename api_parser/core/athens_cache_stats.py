# core/athens_cache_stats.py
"""Fetch L7 cache stats from Athens internal API (:9000)."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import requests

import config

ATHENS_STATS_BASE = getattr(config, "L7_CACHE_PURGE_BASE", "http://127.0.0.1:9000").rstrip("/")
REQUEST_TIMEOUT = float(getattr(config, "ATHENS_STATS_TIMEOUT", 5))
TOP_MISS_URLS_LIMIT = int(getattr(config, "CACHE_HIT_TOP_MISS_URLS", 50))


def _get_json(path: str, params: Optional[Dict[str, Any]] = None) -> Tuple[bool, Any]:
    url = f"{ATHENS_STATS_BASE}{path}"
    try:
        resp = requests.get(url, params=params or {}, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return True, resp.json()
    except (requests.exceptions.RequestException, ValueError) as exc:
        return False, str(exc)


def list_closed_timestamps(endpoint: str) -> Tuple[bool, Any]:
    """Return closed bucket timestamps (oldest first) for an Athens stats endpoint."""
    return _get_json(f"/{endpoint}/timestamps")


def latest_closed_timestamp(endpoint: str) -> Tuple[bool, Any]:
    ok, data = list_closed_timestamps(endpoint)
    if not ok:
        return False, data
    if not isinstance(data, list) or not data:
        return False, "no closed timestamps"
    try:
        return True, int(data[-1])
    except (TypeError, ValueError):
        return False, f"invalid timestamp list: {data[-1]!r}"


def _hit_ratio(cached: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(min(float(cached) / float(total), 1.0), 6)


def normalize_content_types(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for raw in items or []:
        if not isinstance(raw, dict):
            continue
        try:
            site_id = int(raw.get("site_id") or 0)
        except (TypeError, ValueError):
            continue
        content_type = str(raw.get("content_type") or "").strip() or "other"
        try:
            request_count = int(raw.get("request_count") or 0)
            cached_request_count = int(raw.get("cached_request_count") or 0)
            traffic_l7_tx = int(raw.get("traffic_l7_tx") or 0)
            traffic_cached_tx = int(raw.get("traffic_cached_tx") or 0)
        except (TypeError, ValueError):
            continue
        if request_count <= 0 and cached_request_count <= 0:
            continue
        out.append(
            {
                "site_id": site_id,
                "content_type": content_type,
                "request_count": request_count,
                "cached_request_count": cached_request_count,
                "cache_hit_ratio": _hit_ratio(cached_request_count, request_count),
                "traffic_l7_tx": traffic_l7_tx,
                "traffic_cached_tx": traffic_cached_tx,
            }
        )
    out.sort(key=lambda r: (r["site_id"], -r["request_count"], r["content_type"]))
    return out


def normalize_top_miss_urls(
    items: List[Dict[str, Any]], limit_per_site: int = TOP_MISS_URLS_LIMIT
) -> List[Dict[str, Any]]:
    per_site: Dict[int, List[Dict[str, Any]]] = {}
    for raw in items or []:
        if not isinstance(raw, dict):
            continue
        try:
            site_id = int(raw.get("site_id") or 0)
            miss_count = int(raw.get("miss_count") or 0)
            request_count = int(raw.get("request_count") or 0)
        except (TypeError, ValueError):
            continue
        if miss_count <= 0:
            continue
        domain = str(raw.get("domain") or "").strip()
        url = str(raw.get("url") or "").strip()
        if not url:
            continue
        per_site.setdefault(site_id, []).append(
            {
                "site_id": site_id,
                "domain": domain,
                "url": url,
                "miss_count": miss_count,
                "request_count": request_count,
            }
        )

    out: List[Dict[str, Any]] = []
    for site_id in sorted(per_site.keys()):
        rows = per_site[site_id]
        rows.sort(key=lambda r: (-r["miss_count"], r["url"]))
        out.extend(rows[: max(1, int(limit_per_site))])
    return out


def fetch_cache_hit_bucket(timestamp: Optional[int] = None) -> Tuple[bool, Any]:
    """
    Fetch one closed Athens bucket for cache-hit UI fields.

    Returns (True, payload_dict) or (False, error_string).
    """
    if timestamp is None:
        ok_ts, ts_or_err = latest_closed_timestamp("content_type_request_stats")
        if not ok_ts:
            return False, ts_or_err
        timestamp = int(ts_or_err)

    params = {"timestamp": int(timestamp)}
    ok_ct, ct_body = _get_json("/content_type_request_stats", params)
    if not ok_ct:
        return False, f"content_type_request_stats: {ct_body}"
    ok_miss, miss_body = _get_json("/cache_miss_url_stats", params)
    if not ok_miss:
        return False, f"cache_miss_url_stats: {miss_body}"

    ct_items = []
    miss_items = []
    if isinstance(ct_body, dict):
        ct_items = ct_body.get("content_type_request_stats") or []
        try:
            timestamp = int(ct_body.get("timestamp") or timestamp)
        except (TypeError, ValueError):
            pass
    if isinstance(miss_body, dict):
        miss_items = miss_body.get("cache_miss_url_stats") or []

    content_types = normalize_content_types(ct_items if isinstance(ct_items, list) else [])
    top_miss_urls = normalize_top_miss_urls(miss_items if isinstance(miss_items, list) else [])

    return True, {
        "timestamp": int(timestamp),
        "content_types": content_types,
        "top_miss_urls": top_miss_urls,
        # Athens raw names (same arrays) for backends that mirror metrics API.
        "content_type_request_stats": content_types,
        "cache_miss_url_stats": top_miss_urls,
    }
