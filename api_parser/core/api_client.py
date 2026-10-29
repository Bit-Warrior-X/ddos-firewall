# core/api_client.py
"""External API client for blocklist/whitelist operations."""
import socket
from typing import Any, Dict, Optional

import requests
import urllib3
import urllib3.util.connection as urllib3_connection

import config
from utils.auth import get_token

# Disable SSL warnings when verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# This edge often has IPv6 addresses (RA) but no default IPv6 route. DNS AAAA
# then makes requests fail with Errno 101 (Network is unreachable). Prefer A.
if getattr(config, "FORCE_IPV4", True):
    urllib3_connection.allowed_gai_family = lambda: socket.AF_INET  # type: ignore[assignment]


_panel_session: Optional[requests.Session] = None


def _session() -> requests.Session:
    global _panel_session
    if _panel_session is None:
        _panel_session = requests.Session()
    return _panel_session


class APIClient:
    """Handles external API requests."""

    @staticmethod
    def fetch_blocklist(token: str) -> tuple:
        """Fetch blocklist from API."""
        headers = {"Content-Type": "application/json"}
        data = {"token": token}

        try:
            response = _session().post(
                config.BLOCKLIST_API_URL,
                headers=headers,
                json=data,
                timeout=10,
                verify=False,
            )
            response.raise_for_status()
            return True, response.json()
        except requests.exceptions.RequestException as e:
            return False, str(e)

    @staticmethod
    def fetch_whitelist(token: str) -> tuple:
        """Fetch whitelist from API."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        data = {"token": token}

        try:
            response = _session().post(
                config.WHITELIST_API_URL,
                headers=headers,
                json=data,
                timeout=10,
                verify=False,
            )
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, str(e)

    @staticmethod
    def send_report_xdp(payload: Dict[str, Any]) -> bool:
        """Send report log to API. Failures are logged; callers must check the result."""
        ok, _retriable = APIClient.post_report_xdp(payload)
        return ok

    @staticmethod
    def post_report_xdp(payload: Dict[str, Any]) -> tuple:
        """POST one report. Returns (ok, retriable)."""
        headers = {"Content-Type": "application/json"}
        try:
            response = _session().post(
                config.REPORT_XDP_API_URL,
                headers=headers,
                json=payload,
                timeout=5,
                verify=False,
            )
            response.raise_for_status()
            return True, False
        except requests.exceptions.RequestException as exc:
            response = getattr(exc, "response", None)
            status = response.status_code if response is not None else None
            body = ""
            if response is not None and response.text:
                body = response.text.replace("\n", " ")[:300]
            retriable = isinstance(
                exc, (requests.exceptions.Timeout, requests.exceptions.ConnectionError)
            ) or status in (429, 500, 502, 503, 504)
            print(
                "[API_PARSER] report_xdp failed command="
                + str(payload.get("command") or "")
                + " data="
                + str(payload.get("data") or payload.get("attack_type") or "")
                + " req_id="
                + str(payload.get("req_id") or "")
                + " status="
                + str(status)
                + " retriable="
                + str(retriable)
                + " error="
                + str(exc)
                + " body="
                + str(body),
                flush=True,
            )
            return False, retriable

    @staticmethod
    def notify_temporary_blacklist_added(item: Dict[str, Any]) -> bool:
        """Notify backend that a new temporary blacklist entry was added."""
        token = get_token()
        payload = dict(item)
        if token:
            payload["token"] = token
        try:
            response = _session().post(
                config.TEMPORARY_BLACKLIST_NOTIFY_URL,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=5,
                verify=False,
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(
                "[TEMP_BL_NOTIFY] backend request failed for ip=%s error=%s"
                % (payload.get("ip", ""), str(e))
            )
            return False

    @staticmethod
    def report_edge_l4_lists(payload: Dict[str, Any]) -> bool:
        """Deprecated alias — use report_edge_configure."""
        return APIClient.report_edge_configure(payload)

    @staticmethod
    def report_edge_configure(payload: Dict[str, Any]) -> bool:
        """Push full edge L4+L7 configure snapshot to the panel."""
        headers = {"Content-Type": "application/json"}
        url = getattr(config, "EDGE_CONFIG_REPORT_URL", None) or getattr(
            config,
            "EDGE_L4_LISTS_REPORT_URL",
            f"{config.API_BASE_URL}/report_edge_configure",
        )
        try:
            response = _session().post(
                url,
                headers=headers,
                json=payload,
                timeout=30,
                verify=False,
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            body = ""
            resp = getattr(e, "response", None)
            if resp is not None and getattr(resp, "text", None):
                body = resp.text.replace("\n", " ")[:500]
            print(
                f"[EDGE_LIST_SYNC] report_edge_configure failed: {e}"
                + (f" body={body}" if body else ""),
                flush=True,
            )
            return False

    @staticmethod
    def report_l7_attack(payload: Dict[str, Any]) -> bool:
        """Push an L7 attack incident event (start / update / stop) to the panel."""
        headers = {"Content-Type": "application/json"}
        token = payload.get("token") or get_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        url = getattr(config, "L7_ATTACK_REPORT_URL", None) or (
            f"{config.API_BASE_URL}/report_l7_attack"
        )
        try:
            response = _session().post(
                url,
                headers=headers,
                json=payload,
                timeout=30,
                verify=False,
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            body = ""
            resp = getattr(e, "response", None)
            if resp is not None and getattr(resp, "text", None):
                body = resp.text.replace("\n", " ")[:300]
            print(
                f"[L7_ATTACK] report_l7_attack {payload.get('data')} "
                f"id={payload.get('req_id')} failed: {e}"
                + (f" body={body}" if body else ""),
                flush=True,
            )
            return False

    @staticmethod
    def report_cache_hit(payload: Dict[str, Any]) -> bool:
        """Push L7 cache-hit breakdown (content types + top miss URLs) to the panel."""
        headers = {"Content-Type": "application/json"}
        token = payload.get("token") or get_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        url = getattr(config, "CACHE_HIT_REPORT_URL", None) or (
            f"{config.API_BASE_URL}/report_cache_hit"
        )
        try:
            response = _session().post(
                url,
                headers=headers,
                json=payload,
                timeout=30,
                verify=False,
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            body = ""
            resp = getattr(e, "response", None)
            if resp is not None and getattr(resp, "text", None):
                body = resp.text.replace("\n", " ")[:500]
            print(
                f"[CACHE_HIT_SYNC] report_cache_hit failed: {e}"
                + (f" body={body}" if body else ""),
                flush=True,
            )
            return False
