# core/api_client.py
"""External API client for blocklist/whitelist operations."""
import requests
import urllib3
from typing import Dict, Any
import config
from utils.auth import get_token

# Disable SSL warnings when verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class APIClient:
    """Handles external API requests."""
    
    @staticmethod
    def fetch_blocklist(token: str) -> tuple:
        """Fetch blocklist from API."""
        headers = {'Content-Type': 'application/json'}
        data = {'token': token}
        
        try:
            response = requests.post(
                config.BLOCKLIST_API_URL, 
                headers=headers, 
                json=data,
                timeout=10,
                verify=False
            )
            response.raise_for_status()
            return True, response.json()
        except requests.exceptions.RequestException as e:
            return False, str(e)
    
    @staticmethod
    def fetch_whitelist(token: str) -> tuple:
        """Fetch whitelist from API."""
        headers = {'Content-Type': 'application/json', 'Authorization': f'Bearer {token}'}
        data = {'token': token}
        
        try:
            response = requests.post(
                config.WHITELIST_API_URL,
                headers=headers,
                json=data,
                timeout=10,
                verify=False
            )
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def send_report_xdp(payload: Dict[str, Any]) -> bool:
        """Send report log to API."""
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(
                config.REPORT_XDP_API_URL,
                headers=headers,
                json=payload,
                timeout=5,
                verify=False
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException:
            return False
        
    @staticmethod
    def notify_temporary_blacklist_added(item: Dict[str, Any]) -> bool:
        """Notify backend that a new temporary blacklist entry was added (with item details and token)."""
        # Include token in payload as requested
        token = get_token()
        payload = dict(item)
        if token:
            payload["token"] = token
        try:
            response = requests.post(
                config.TEMPORARY_BLACKLIST_NOTIFY_URL,
                headers={"Content-Type": "application/json"},
                json=payload,
                timeout=5,
                verify=False,
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            # Extra debug logging for failures
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
        url = getattr(
            config,
            "EDGE_CONFIG_REPORT_URL",
            None,
        ) or getattr(
            config,
            "EDGE_L4_LISTS_REPORT_URL",
            f"{config.API_BASE_URL}/report_edge_configure",
        )
        try:
            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=30,
                verify=False,
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException as e:
            print(f"[EDGE_LIST_SYNC] report_edge_configure failed: {e}", flush=True)
            return False

