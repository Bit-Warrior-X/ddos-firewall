# utils/validators.py
"""Input validation utilities."""
import ipaddress
from typing import Optional
from urllib.parse import urlparse

def validate_ip(ip: str) -> bool:
    """Validate IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_port(port: int) -> bool:
    """Validate port number."""
    return 1 <= port <= 65535

def validate_url(url: str) -> bool:
    """Validate HTTP/HTTPS URL."""
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

