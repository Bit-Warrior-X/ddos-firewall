# core/nginx_ops.py
"""Nginx operations (test, reload)."""
import re
import subprocess
from typing import Tuple

def _trim_nginx_error(stderr: str) -> str:
    """Trim nginx error message to human-readable format."""
    for raw in (stderr or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("nginx:"):
            line = re.sub(r"^nginx:\s*\[[^\]]+\]\s*", "", line)
            line = re.sub(r"\s+in\s+/.+?:\d+\s*$", "", line)
            line = re.sub(r"\s+at\s+.+$", "", line)
            return line
    lines = [l.strip() for l in (stderr or "").splitlines() if l.strip()]
    return lines[-1] if lines else "Unknown nginx error"

def _trim_nginx_line(line: str) -> str:
    """Clean a single nginx stderr line."""
    if not line or not line.strip():
        return "Unknown nginx message"
    line = line.strip()
    line = re.sub(r"^nginx:\s*\[[^\]]+\]\s*", "", line)
    line = re.sub(r"\s+in\s+/.+?:\d+\s*$", "", line)
    line = re.sub(r"\s+at\s+.+$", "", line)
    return line or "Unknown nginx message"

def nginx_test() -> Tuple[bool, str]:
    """
    Test nginx configuration.
    Returns: (success: bool, message: str)
    """
    proc = subprocess.run(
        ["nginx", "-t"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10
    )
    ok = (proc.returncode == 0)
    if ok:
        return True, (proc.stderr or proc.stdout or "").strip()
    return False, _trim_nginx_error(proc.stderr)

def nginx_reload() -> Tuple[bool, str]:
    """
    Reload nginx configuration.
    Returns: (success: bool, message: str)
    - On success: ok=True, usually 'signal process started'
    - On failure: ok=False, trimmed human-readable reason
    """
    proc = subprocess.run(
        ["nginx", "-s", "reload"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10
    )
    if proc.returncode == 0:
        lines = [l.strip() for l in (proc.stderr or proc.stdout or "").splitlines() if l.strip()]
        msg = lines[-1] if lines else "nginx reload signaled"
        if msg.startswith("nginx:"):
            msg = _trim_nginx_line(msg)
        return True, msg
    return False, _trim_nginx_error(proc.stderr)

