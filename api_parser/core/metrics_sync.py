# core/metrics_sync.py
"""Pull closed Sparta/Athens metric buckets and push them to the panel.

Panel never scrapes the edge; collection stays in athens/sparta, delivery is
outbound from angelos via POST /api/report_edge_metrics (batched items).

Sparta TRAFFIC_STATS is one sample per second (rate for that second). We
aggregate closed wall-clock minutes into a single l4_attack_stats item so the
panel gets ~1 L4 point/minute and the feed can keep up with realtime.
"""
from __future__ import annotations

import re
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import config
from core import license_check as license_check_mod
from core.api_client import APIClient
from core.athens_cache_stats import _get_json, list_closed_timestamps
from core.firewall import execute_cli_command
from core.license_check import get_license_info
from utils.auth import get_token

SYNC_INTERVAL_SEC = int(getattr(config, "METRICS_SYNC_INTERVAL", 60))
BUCKET_SECONDS = int(getattr(config, "METRICS_BUCKET_SECONDS", 60))
MAX_BUCKETS_PER_TICK = int(getattr(config, "METRICS_SYNC_MAX_BUCKETS", 5))
MAX_ITEMS_PER_POST = int(getattr(config, "METRICS_SYNC_MAX_ITEMS_PER_POST", 40))
BACKFILL_SEC = int(getattr(config, "METRICS_SYNC_BACKFILL_SEC", 6 * 3600))
CATCHUP_BUCKETS_PER_TICK = int(
    getattr(config, "METRICS_SYNC_CATCHUP_BUCKETS", max(MAX_BUCKETS_PER_TICK, 30))
)
# Closed L4 minutes to aggregate per tick while catching up.
L4_MINUTES_PER_TICK = int(getattr(config, "METRICS_SYNC_L4_MINUTES_PER_TICK", 30))

ATHENS_ENDPOINTS = (
    "server_traffic_stats",
    "site_traffic_stats",
    "ip_request_stats",
    "url_request_stats",
    "useragent_request_stats",
    "country_request_stats",
    "isp_request_stats",
    "referer_request_stats",
    "domain_request_stats",
    "content_type_request_stats",
    "cache_miss_url_stats",
    "block_reason_stats",
)

ATHENS_ARRAY_ENDPOINTS = frozenset(
    ep for ep in ATHENS_ENDPOINTS if ep != "server_traffic_stats"
)

# Panel series name (legacy Athens :9000 path). Keep l4_traffic_stats as alias.
L4_ENDPOINT = "l4_attack_stats"
L4_ENDPOINT_ALIASES = ["l4_traffic_stats", "l4_attack_stats"]

SPARTA_STAT_KEYS = (
    "total",
    "allow",
    "block",
    "syn",
    "ack",
    "rst",
    "tcp",
    "udp",
    "icmp",
    "gre",
    "other",
)

_lock = threading.Lock()
_cursors: Dict[str, int] = {}
_started = False


def _license():
    info = license_check_mod.license_info
    if info is None:
        try:
            info = get_license_info()
            license_check_mod.license_info = info
        except Exception:
            return None
    return info


def _cursor_key(source: str, endpoint: str) -> str:
    return f"{source}:{endpoint}"


def _last_ts(source: str, endpoint: str) -> int:
    with _lock:
        return int(_cursors.get(_cursor_key(source, endpoint), 0))


def _set_ts(source: str, endpoint: str, ts: int) -> None:
    with _lock:
        _cursors[_cursor_key(source, endpoint)] = int(ts)


def _rewind_cursors(seconds: int) -> None:
    floor = max(0, int(time.time()) - max(0, int(seconds)))
    # Align L4 cursor to minute boundary so aggregation starts cleanly.
    l4_floor = floor - (floor % 60)
    with _lock:
        _cursors[_cursor_key("sparta", L4_ENDPOINT)] = l4_floor
        # Compat if an older build used l4_traffic_stats as cursor key.
        _cursors[_cursor_key("sparta", "l4_traffic_stats")] = l4_floor
        for ep in ATHENS_ENDPOINTS:
            _cursors[_cursor_key("athens", ep)] = floor
    print(
        f"[METRICS_SYNC] rewound cursors to >= {floor} "
        f"(l4_minute_floor={l4_floor}, backfill_sec={seconds})",
        flush=True,
    )


def _parse_sparta_cli(result: Dict[str, str]) -> Tuple[bool, str]:
    if result.get("status") != "success":
        return False, result.get("message") or "sparta_cli failed"
    return True, result.get("message") or ""


def _sparta_timestamps() -> Tuple[bool, Any]:
    parsed = execute_cli_command(["sparta_cli", "TRAFFIC_TIMESTAMPS"])
    ok, msg = _parse_sparta_cli(parsed)
    if not ok:
        return False, msg
    stamps: List[int] = []
    for tok in msg.replace("\n", ",").split(","):
        tok = tok.strip()
        if tok.isdigit():
            stamps.append(int(tok))
    stamps = sorted(set(stamps))
    return True, stamps


def _sparta_stats_raw(timestamp: int) -> Tuple[bool, Any]:
    parsed = execute_cli_command(["sparta_cli", "TRAFFIC_STATS", str(timestamp)])
    ok, msg = _parse_sparta_cli(parsed)
    if not ok:
        return False, msg
    stats: Dict[str, int] = {}
    for key, value in re.findall(r"(\w+):(\d+)", msg):
        stats[key] = int(value)
    if not stats:
        return False, f"empty TRAFFIC_STATS for {timestamp}"
    full = {k: int(stats.get(k) or 0) for k in SPARTA_STAT_KEYS}
    for k, v in stats.items():
        if k not in full:
            full[k] = int(v)
    return True, full


def _sample_seconds_for_minute(second_ts: List[int], max_samples: int = 6) -> List[int]:
    """Pick evenly spaced seconds in the minute to limit sparta_cli calls."""
    ordered = sorted(set(second_ts))
    if len(ordered) <= max_samples:
        return ordered
    if max_samples <= 1:
        return [ordered[-1]]
    out: List[int] = []
    last_idx = len(ordered) - 1
    for i in range(max_samples):
        idx = int(round(i * last_idx / (max_samples - 1)))
        out.append(ordered[idx])
    # Preserve order, drop dupes from rounding.
    dedup: List[int] = []
    seen = set()
    for ts in out:
        if ts not in seen:
            seen.add(ts)
            dedup.append(ts)
    return dedup


def _aggregate_minute(minute: int, second_ts: List[int]) -> Tuple[bool, Any]:
    """Build one closed-minute L4 bucket from per-second Sparta rates.

    Sparta samples are bytes/packets **per second**. We subsample the minute
    (default 6 points), average those rates, then scale to a 60s total so catch-up
    does not require 60 sparta_cli calls per minute.
    """
    picked = _sample_seconds_for_minute(second_ts, max_samples=6)
    totals = {k: 0 for k in SPARTA_STAT_KEYS}
    samples = 0
    for ts in picked:
        ok, stats = _sparta_stats_raw(ts)
        if not ok:
            continue
        samples += 1
        for k in SPARTA_STAT_KEYS:
            totals[k] += int(stats.get(k) or 0)
        for k, v in stats.items():
            if k not in totals:
                totals[k] = totals.get(k, 0) + int(v)
    if samples == 0:
        return False, f"no TRAFFIC_STATS samples for minute {minute}"

    # Average per-second rate across samples, then * 60 => estimated minute total.
    scale = 60.0 / float(samples)
    scaled = {k: int(round(totals.get(k, 0) * scale)) for k in SPARTA_STAT_KEYS}
    for k, v in list(totals.items()):
        if k not in scaled:
            scaled[k] = int(round(v * scale))

    payload: Dict[str, Any] = {
        "timestamp": int(minute),
        "interval_seconds": 60,
        "samples": samples,
        "samples_available": len(set(second_ts)),
        "stats": {k: int(scaled.get(k) or 0) for k in SPARTA_STAT_KEYS},
        **{k: int(scaled.get(k) or 0) for k in SPARTA_STAT_KEYS},
        "source_cli": "TRAFFIC_STATS",
        "aggregation": "avg_per_second_rate_x60",
        "endpoint_aliases": list(L4_ENDPOINT_ALIASES),
        "row_count": 1,
    }
    return True, payload


def _new_timestamps(all_ts: List[int], last: int, limit: int) -> List[int]:
    newer = [ts for ts in all_ts if ts > last]
    if len(newer) > limit:
        newer = newer[:limit]
    return newer


def _normalize_athens_payload(endpoint: str, timestamp: int, body: Any) -> Dict[str, Any]:
    if isinstance(body, dict):
        payload = dict(body)
    else:
        payload = {"data": body}
    payload["timestamp"] = int(payload.get("timestamp") or timestamp)

    if endpoint in ATHENS_ARRAY_ENDPOINTS:
        rows = payload.get(endpoint)
        if not isinstance(rows, list):
            rows = []
        payload[endpoint] = rows
        payload["row_count"] = len(rows)
        if endpoint == "cache_miss_url_stats":
            payload.setdefault("top_miss_urls", rows)
            payload["top_miss_urls_count"] = len(rows)
        if endpoint == "content_type_request_stats":
            payload.setdefault("content_types", rows)
            payload["content_types_count"] = len(rows)
        if endpoint == "block_reason_stats":
            payload["block_reason_count"] = len(rows)
    else:
        payload.setdefault("row_count", 1)
    return payload


def _make_item(
    source: str,
    endpoint: str,
    timestamp: int,
    payload: Any,
    *,
    endpoint_aliases: Optional[List[str]] = None,
    interval_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "source": source,
        "endpoint": endpoint,
        "timestamp": int(timestamp),
        "interval_seconds": int(interval_seconds or BUCKET_SECONDS),
        "payload": payload,
        "row_count": int((payload or {}).get("row_count") or 0)
        if isinstance(payload, dict)
        else 0,
    }
    if endpoint_aliases:
        item["endpoint_aliases"] = list(endpoint_aliases)
    return item


def _push_batch(token: str, info, items: List[Dict[str, Any]]) -> bool:
    if not items:
        return True
    body: Dict[str, Any] = {
        "token": token,
        "command": "report_edge_metrics",
        "reported_at": int(time.time()),
        "interval_seconds": BUCKET_SECONDS,
        "license_type": getattr(info, "license_type", "") or "",
        "allows_l4": bool(getattr(info, "allows_l4", False)),
        "allows_l7": bool(getattr(info, "allows_l7", False)),
        "item_count": len(items),
        "items": items,
        "source": items[0]["source"],
        "endpoint": items[0]["endpoint"],
        "timestamp": items[0]["timestamp"],
        "payload": items[0]["payload"],
    }
    return APIClient.report_edge_metrics(body)


def _bucket_limit(last: int) -> int:
    behind = last <= 0 or (int(time.time()) - last) > (MAX_BUCKETS_PER_TICK * BUCKET_SECONDS * 2)
    return CATCHUP_BUCKETS_PER_TICK if behind else MAX_BUCKETS_PER_TICK


def _collect_l4(items: List[Dict[str, Any]]) -> List[Tuple[str, str, int]]:
    """Aggregate Sparta per-second rates into closed 60s minutes; push as l4_attack_stats."""
    pending: List[Tuple[str, str, int]] = []
    ok, stamps_or_err = _sparta_timestamps()
    if not ok:
        return pending
    stamps = stamps_or_err if isinstance(stamps_or_err, list) else []
    if not stamps:
        return pending

    last = max(
        _last_ts("sparta", L4_ENDPOINT),
        _last_ts("sparta", "l4_traffic_stats"),
    )
    now = int(time.time())
    current_minute = now - (now % 60)

    by_minute: Dict[int, List[int]] = {}
    for ts in stamps:
        if ts <= last:
            continue
        minute = ts - (ts % 60)
        # Only closed minutes (do not emit the in-progress minute).
        if minute >= current_minute:
            continue
        by_minute.setdefault(minute, []).append(ts)

    closed_minutes = sorted(by_minute.keys())
    behind = last <= 0 or (current_minute - last) > (L4_MINUTES_PER_TICK * 60 * 2)
    limit = L4_MINUTES_PER_TICK if behind else max(1, MAX_BUCKETS_PER_TICK)
    for minute in closed_minutes[:limit]:
        ok_m, bucket = _aggregate_minute(minute, sorted(by_minute[minute]))
        if not ok_m:
            print(f"[METRICS_SYNC] L4 minute {minute} failed: {bucket}", flush=True)
            break
        items.append(
            _make_item(
                "sparta",
                L4_ENDPOINT,
                minute,
                bucket,
                endpoint_aliases=L4_ENDPOINT_ALIASES,
                interval_seconds=60,
            )
        )
        pending.append(("sparta", L4_ENDPOINT, minute))
    return pending


def _collect_athens(items: List[Dict[str, Any]]) -> List[Tuple[str, str, int]]:
    pending: List[Tuple[str, str, int]] = []
    for endpoint in ATHENS_ENDPOINTS:
        ok, data = list_closed_timestamps(endpoint)
        if not ok or not isinstance(data, list):
            continue
        stamps: List[int] = []
        for raw in data:
            try:
                stamps.append(int(raw))
            except (TypeError, ValueError):
                continue
        stamps = sorted(set(stamps))
        last = _last_ts("athens", endpoint)
        for ts in _new_timestamps(stamps, last, _bucket_limit(last)):
            ok_b, body = _get_json(f"/{endpoint}", {"timestamp": ts})
            if not ok_b:
                print(
                    f"[METRICS_SYNC] athens {endpoint} ts={ts} fetch failed: {body}",
                    flush=True,
                )
                break
            payload = _normalize_athens_payload(endpoint, ts, body)
            items.append(_make_item("athens", endpoint, ts, payload))
            pending.append(("athens", endpoint, ts))
    return pending


def _push_chunks(
    token: str,
    info,
    items: List[Dict[str, Any]],
    pending: List[Tuple[str, str, int]],
    counts: Dict[str, int],
) -> int:
    """POST items in chunks; advance cursors only for successfully sent chunks."""
    offset = 0
    committed = 0
    nonempty_note: Dict[str, int] = {}
    while offset < len(items):
        chunk = items[offset : offset + MAX_ITEMS_PER_POST]
        chunk_pending = pending[offset : offset + MAX_ITEMS_PER_POST]
        if not _push_batch(token, info, chunk):
            print(
                f"[METRICS_SYNC] batch push failed "
                f"(offset={offset}, size={len(chunk)}); will retry next tick",
                flush=True,
            )
            break
        for source, endpoint, ts in chunk_pending:
            _set_ts(source, endpoint, ts)
            if source == "sparta":
                counts["sparta"] += 1
            else:
                counts["athens"] += 1
        for it in chunk:
            if it.get("row_count"):
                ep = str(it.get("endpoint"))
                nonempty_note[ep] = nonempty_note.get(ep, 0) + 1
        committed += len(chunk)
        counts["posts"] += 1
        offset += MAX_ITEMS_PER_POST

    if committed and nonempty_note:
        print(
            "[METRICS_SYNC] nonempty="
            + ",".join(f"{k}:{v}" for k, v in sorted(nonempty_note.items())),
            flush=True,
        )
    return committed


def report_metrics_once() -> Dict[str, int]:
    counts = {"sparta": 0, "athens": 0, "posts": 0}
    info = _license()
    if info is None or info.status != 0:
        return counts

    token = get_token()
    if not token:
        print("[METRICS_SYNC] No API token; skipping", flush=True)
        return counts

    # Push L4 and Athens separately so a large L4 catch-up cannot starve L7,
    # and panel disconnects on one stream do not block the other.
    if info.allows_l4:
        l4_items: List[Dict[str, Any]] = []
        l4_pending: List[Tuple[str, str, int]] = []
        try:
            l4_pending.extend(_collect_l4(l4_items))
        except Exception as exc:
            print(f"[METRICS_SYNC] L4 sync error: {exc}", flush=True)
        if l4_items:
            n = _push_chunks(token, info, l4_items, l4_pending, counts)
            if n:
                print(
                    f"[METRICS_SYNC] pushed L4 minutes={counts['sparta']} posts={counts['posts']}",
                    flush=True,
                )

    if info.allows_l7:
        a_items: List[Dict[str, Any]] = []
        a_pending: List[Tuple[str, str, int]] = []
        try:
            a_pending.extend(_collect_athens(a_items))
        except Exception as exc:
            print(f"[METRICS_SYNC] athens sync error: {exc}", flush=True)
        if a_items:
            posts_before = counts["posts"]
            n = _push_chunks(token, info, a_items, a_pending, counts)
            if n:
                print(
                    f"[METRICS_SYNC] pushed athens items={counts['athens']} "
                    f"posts={counts['posts'] - posts_before}",
                    flush=True,
                )
    return counts


def _run_sync_loop() -> None:
    print(
        f"[METRICS_SYNC] starting (interval={SYNC_INTERVAL_SEC}s, "
        f"l4_endpoint={L4_ENDPOINT}, l4_minutes/tick={L4_MINUTES_PER_TICK}, "
        f"athens_catchup={CATCHUP_BUCKETS_PER_TICK}, backfill_sec={BACKFILL_SEC})",
        flush=True,
    )
    _rewind_cursors(BACKFILL_SEC)
    time.sleep(min(5, SYNC_INTERVAL_SEC))
    while True:
        try:
            report_metrics_once()
        except Exception as exc:
            print(f"[METRICS_SYNC] Unexpected error: {exc}", flush=True)
        time.sleep(SYNC_INTERVAL_SEC)


def start_metrics_sync() -> Optional[threading.Thread]:
    global _started
    with _lock:
        if _started:
            return None
        _started = True
    thread = threading.Thread(target=_run_sync_loop, daemon=True, name="metrics_sync")
    thread.start()
    return thread
