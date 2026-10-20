# core/license_monitor.py
"""Periodic license validation and license_type-based service enforcement."""
import os
import shutil
import subprocess
import threading
import time
from typing import Optional

import config
from core import license_check as license_check_mod
from core.api_client import APIClient
from core.backend_whitelist import ensure_backend_ips_whitelisted
from core.license_check import LicenseInfo, get_license_info
from utils.auth import get_token

CHECK_INTERVAL_SEC = config.LICENSE_CHECK_INTERVAL
TRANSIENT_RETRY_SEC = 5

_lock = threading.Lock()
_last_reported_failure: Optional[str] = None
_last_status: Optional[int] = None
_last_l4_allowed: Optional[bool] = None
_last_l7_allowed: Optional[bool] = None


def _report_license_failure(reason: str) -> None:
    global _last_reported_failure

    with _lock:
        if _last_reported_failure == reason:
            return
        _last_reported_failure = reason

    token = get_token()
    if not token:
        print(f"[LICENSE_MONITOR] No API token; cannot report license failure: {reason}")
        return

    payload = {
        "command": "report_license",
        "data": reason,
        "token": token,
    }
    try:
        if APIClient.send_report_xdp(payload):
            print(f"[LICENSE_MONITOR] Reported license failure to backend: {reason}")
        else:
            print(f"[LICENSE_MONITOR] Backend did not accept license failure report: {reason}")
    except Exception as exc:
        print(f"[LICENSE_MONITOR] Failed to report license failure ({reason}): {exc}")


def _failure_reason(info: LicenseInfo) -> str:
    if info.status == -2:
        return "expired"
    return "manipulated"


def _systemctl(action: str, unit: str) -> None:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        print(f"[LICENSE_MONITOR] systemctl not found; cannot {action} {unit}")
        return

    try:
        proc = subprocess.run(
            [systemctl, action, unit],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode == 0:
            print(f"[LICENSE_MONITOR] systemctl {action} {unit} -> ok")
        else:
            stderr = (proc.stderr or proc.stdout or "").strip()
            print(
                f"[LICENSE_MONITOR] systemctl {action} {unit} failed "
                f"(exit={proc.returncode}): {stderr[:200]}"
            )
    except subprocess.TimeoutExpired:
        print(f"[LICENSE_MONITOR] systemctl {action} {unit} timed out")
    except Exception as exc:
        print(f"[LICENSE_MONITOR] systemctl {action} {unit} error: {exc}")


def _enforce_service_access(info: LicenseInfo) -> None:
    global _last_l4_allowed, _last_l7_allowed

    l4_allowed = info.allows_l4
    l7_allowed = info.allows_l7

    if l4_allowed != _last_l4_allowed:
        if l4_allowed:
            print("[LICENSE_MONITOR] L4 license type allowed; whitelisting backends then starting sparta")
            try:
                # Populate white_ips before systemd start so Sparta load_config
                # has origins in allowed_ips before XDP attach.
                ensure_backend_ips_whitelisted(apply_live=False)
            except Exception as exc:
                print(f"[LICENSE_MONITOR] Backend whitelist inject failed: {exc}")
            _systemctl("start", config.SPARTA_SERVICE)
        else:
            print("[LICENSE_MONITOR] L4 license type not allowed; stopping sparta")
            _systemctl("stop", config.SPARTA_SERVICE)
        _last_l4_allowed = l4_allowed

    if l7_allowed != _last_l7_allowed:
        if l7_allowed:
            print(
                "[LICENSE_MONITOR] L7 license type allowed; "
                "whitelisting origin IPs then starting athens"
            )
            try:
                # Origins must be on L4 whitelist whenever L7 proxies to them,
                # even if Sparta was already running before L7 was enabled.
                ensure_backend_ips_whitelisted(apply_live=True)
            except Exception as exc:
                print(f"[LICENSE_MONITOR] Origin whitelist inject failed: {exc}")
            _systemctl("start", config.L7_SERVICE)
        else:
            print("[LICENSE_MONITOR] L7 license type not allowed; stopping athens")
            _systemctl("stop", config.L7_SERVICE)
        _last_l7_allowed = l7_allowed


def _run_monitor() -> None:
    pid = os.getpid()
    thread_name = threading.current_thread().name
    transient_failures = 0

    print(
        f"[LICENSE_MONITOR] pid={pid} thread={thread_name} "
        f"starting (interval={CHECK_INTERVAL_SEC}s)"
    )

    while True:
        try:
            info = get_license_info()
        except Exception as exc:
            print(f"[LICENSE_MONITOR] License check error: {exc}")
            time.sleep(CHECK_INTERVAL_SEC)
            continue

        ret = info.status
        global _last_status, _last_reported_failure

        if ret != _last_status:
            if ret == 0:
                print(
                    f"[LICENSE_MONITOR] License valid "
                    f"(type={info.license_type}, days_left={info.days_left})"
                )
            elif ret == -3:
                print("[LICENSE_MONITOR] Transient license check failure")
            else:
                print(f"[LICENSE_MONITOR] License check failed (ret={ret})")
            _last_status = ret

        license_check_mod.license_info = info

        if ret == 0:
            transient_failures = 0
            with _lock:
                _last_reported_failure = None
            _enforce_service_access(info)
            time.sleep(CHECK_INTERVAL_SEC)
            continue

        if ret == -3:
            transient_failures += 1
            if transient_failures == 1 or (transient_failures % 10) == 0:
                print(
                    f"[LICENSE_MONITOR] Transient license check failure "
                    f"({transient_failures}); retrying in {TRANSIENT_RETRY_SEC}s"
                )
            time.sleep(TRANSIENT_RETRY_SEC)
            continue

        _enforce_service_access(info)
        _report_license_failure(_failure_reason(info))
        time.sleep(CHECK_INTERVAL_SEC)


def start_license_monitor():
    """Start the periodic license monitor in a daemon thread."""
    thread = threading.Thread(target=_run_monitor, daemon=True, name="license_monitor")
    thread.start()
    return thread
