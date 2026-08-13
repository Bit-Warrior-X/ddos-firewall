# core/temporary_blacklist_monitor.py
"""
Monitor Redis for new temporary blacklist entries and notify the backend.

Subscribes to channel "temporaryblacklist:added". When OpenResty (nginx) adds
a temporary blacklist entry it SETs the key and PUBLISHes the entry JSON to this
channel, so we don't rely on Redis keyspace notifications (notify-keyspace-events).

This coexists with acl_manager.lua, which subscribes to "acl:updates" and
__keyevent@0__:* for ACL rule keys only; both can monitor the same Redis.
"""
import json
import logging
import threading
import time
import os

from core.redis_client import RedisClient
from core.api_client import APIClient
import config

logger = logging.getLogger(__name__)

CHANNEL_ADDED = "temporaryblacklist:added"


def _run_monitor():
    """Subscribe to channel temporaryblacklist:added and notify backend on each message."""
    pid = os.getpid()
    thread_name = threading.current_thread().name
    retry_delay = 2
    max_retry_delay = 60
    print(f"[TEMP_BL_MONITOR] pid={pid} thread={thread_name} starting monitor loop")

    while True:
        try:
            rcli = RedisClient.get_client()
            pubsub = rcli.pubsub()
            pubsub.subscribe(CHANNEL_ADDED)

            print(
                f"[TEMP_BL_MONITOR] pid={pid} thread={thread_name} subscribed to {CHANNEL_ADDED}"
            )
            retry_delay = 2

            for message in pubsub.listen():
                # Raw message debug
                print(
                    f"[TEMP_BL_MONITOR] pid={pid} thread={thread_name} raw message: "
                    f"type={message.get('type')} channel={message.get('channel')} data={message.get('data')}"
                )

                if message.get("type") != "message":
                    continue
                if message.get("channel") != CHANNEL_ADDED:
                    continue
                data = message.get("data")
                if not data:
                    print(f"[TEMP_BL_MONITOR] pid={pid} empty data, skipping")
                    continue
                try:
                    item = json.loads(data)
                    if isinstance(item, dict):
                        print(
                            f"[TEMP_BL_MONITOR] pid={pid} parsed item ip={item.get('ip','')} "
                            f"site_id={item.get('site_id','')} "
                            f"trigger_rule={item.get('trigger_rule','')}"
                        )
                        ok = APIClient.notify_temporary_blacklist_added(item)
                        if ok:
                            print(
                                "[TEMP_BL_MONITOR] pid=%s notified backend for ip=%s trigger_rule=%s"
                                % (pid, item.get("ip", ""), item.get("trigger_rule", ""))
                            )
                        else:
                            print(
                                "[TEMP_BL_MONITOR] pid=%s backend notify FAILED for ip=%s"
                                % (pid, item.get("ip", ""))
                            )
                    else:
                        print(
                            f"[TEMP_BL_MONITOR] pid={pid} data is not dict after JSON load, type={type(item)}"
                        )
                except json.JSONDecodeError as e:
                    print(
                        f"[TEMP_BL_MONITOR] pid={pid} invalid JSON in channel message: {e}"
                    )
                except Exception as e:
                    print(
                        f"[TEMP_BL_MONITOR] pid={pid} error processing message: {e}"
                    )

        except Exception as e:
            print(
                f"[TEMP_BL_MONITOR] pid={pid} exception in monitor loop: {e}; "
                f"reconnecting in {retry_delay}s"
            )
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, max_retry_delay)


def start_temporary_blacklist_monitor():
    """Start the Redis temporary blacklist monitor in a daemon thread."""
    thread = threading.Thread(target=_run_monitor, daemon=True, name="temp_bl_monitor")
    thread.start()
    return thread
