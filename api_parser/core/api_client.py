# core/api_client.py
"""External API client for blocklist/whitelist operations."""
import requests
import urllib3
from typing import Dict, Any
import config

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
    def deploy_done(payload: Dict[str, Any]) -> tuple:
        """Call deploy_done endpoint."""
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post(
                config.BACKEND_DEPLOY_URL,
                headers=headers,
                json=payload,
                timeout=10,
                verify=False
            )
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def deploy_complete(payload: Dict[str, Any]) -> tuple:
        """Call deploy_complete endpoint."""
        headers = {'Content-Type': 'application/json'}
        try:
            response = requests.post(
                config.BACKEND_DEPLOY_COMPLETE_URL,
                headers=headers,
                json=payload,
                timeout=10,
                verify=False
            )
            response.raise_for_status()
            return True, response.json()
        except Exception as e:
            return False, str(e)

