# core/temporary_blacklist_monitor.py
"""
Monitor Redis for new temporary blacklist entries and notify the backend.

Subscribes to channel "temporaryblacklist:added". When OpenResty (nginx) adds
a temporary blacklist entry it SETs the key and PUBLISHes the entry JSON to this
channel, so we don't rely on Redis keyspace notifications (notify-keyspace-events).

This coexists with acl_manager.lua, which subscribes to "acl:updates" and
__keyevent@0__:* for ACL rule keys only; both can monitor the same Redis.

Panel notifications go through a bounded queue drained by a worker thread: a
synchronous POST per message made the subscriber fall behind during attacks
(thousands of blocks per minute) until Redis dropped the pubsub client.
"""
import json
import logging
import os
import queue
import threading
import time

from core.redis_client import RedisClient
from core.api_client import APIClient
import config

logger = logging.getLogger(__name__)

CHANNEL_ADDED = "temporaryblacklist:added"
QUEUE_MAX = int(getattr(config, "TEMP_BL_NOTIFY_QUEUE_MAX", 20000))
NOTIFY_WORKERS = int(getattr(config, "TEMP_BL_NOTIFY_WORKERS", 4))

_notify_queue: "queue.Queue[dict]" = queue.Queue(maxsize=QUEUE_MAX)
_dropped = 0
_failed = 0


def _notify_worker():
    global _failed
    while True:
        item = _notify_queue.get()
        try:
            if not APIClient.notify_temporary_blacklist_added(item):
                _failed += 1
                if _failed % 100 == 1:
                    print(f"[TEMP_BL_MONITOR] backend notify failed (failures={_failed}) "
                          f"last ip={item.get('ip', '')}", flush=True)
        except Exception as exc:
            print(f"[TEMP_BL_MONITOR] notify error for ip={item.get('ip', '')}: {exc}", flush=True)
        finally:
            _notify_queue.task_done()


def _enqueue(item: dict) -> None:
    global _dropped
    try:
        _notify_queue.put_nowait(item)
    except queue.Full:
        _dropped += 1
        if _dropped % 1000 == 1:
            print(f"[TEMP_BL_MONITOR] notify queue full, dropping (dropped={_dropped})", flush=True)


def _run_monitor():
    """Subscribe to channel temporaryblacklist:added and queue backend notifications."""
    pid = os.getpid()
    retry_delay = 2
    max_retry_delay = 60
    print(f"[TEMP_BL_MONITOR] pid={pid} starting monitor loop "
          f"(queue={QUEUE_MAX} workers={NOTIFY_WORKERS})", flush=True)

    while True:
        pubsub = None
        try:
            pubsub = RedisClient.get_client().pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe(CHANNEL_ADDED)
            print(f"[TEMP_BL_MONITOR] pid={pid} subscribed to {CHANNEL_ADDED}", flush=True)
            retry_delay = 2

            for message in pubsub.listen():
                if message.get("type") != "message" or message.get("channel") != CHANNEL_ADDED:
                    continue
                data = message.get("data")
                if not data:
                    continue
                try:
                    item = json.loads(data)
                except json.JSONDecodeError as e:
                    print(f"[TEMP_BL_MONITOR] invalid JSON in channel message: {e}", flush=True)
                    continue
                if isinstance(item, dict):
                    _enqueue(item)
        except Exception as e:
            print(f"[TEMP_BL_MONITOR] pid={pid} exception in monitor loop: {e}; "
                  f"reconnecting in {retry_delay}s", flush=True)
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, max_retry_delay)
        finally:
            if pubsub is not None:
                try:
                    pubsub.close()
                except Exception:
                    pass


def start_temporary_blacklist_monitor():
    """Start the Redis temporary blacklist monitor and its notify workers."""
    for i in range(NOTIFY_WORKERS):
        threading.Thread(target=_notify_worker, daemon=True, name=f"temp_bl_notify_{i}").start()
    thread = threading.Thread(target=_run_monitor, daemon=True, name="temp_bl_monitor")
    thread.start()
    return thread
