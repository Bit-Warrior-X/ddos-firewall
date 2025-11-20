# utils/nginx_utils.py
"""Nginx configuration utility functions."""
import os
import re
import tempfile
import base64
from datetime import datetime
from typing import Tuple, Optional, Union, List
import config

def normalize_methods(method_field: Union[str, List, tuple, set]) -> Tuple[Optional[str], Optional[str]]:
    """
    Normalize HTTP method field to space-separated string.
    Returns: (normalized_string, error_message)
    """
    if isinstance(method_field, str):
        parts = re.split(r"[,\s]+", method_field.strip())
    elif isinstance(method_field, (list, tuple, set)):
        parts = list(method_field)
    else:
        return None, "Invalid 'method' format. Use 'GET', 'POST', or a list."

    up = [p.strip().upper() for p in parts if p.strip()]
    if not up:
        return None, "No valid HTTP methods provided."

    seen = set()
    ordered = []
    for m in up:
        if m not in config.ALLOWED_HTTP_METHODS:
            return None, f"Unsupported method '{m}'. Allowed: {', '.join(sorted(config.ALLOWED_HTTP_METHODS))}."
        if m not in seen:
            seen.add(m)
            ordered.append(m)
    return " ".join(ordered), None

def replace_or_append(content: str, key: str, value_with_semicolon: str) -> str:
    """
    Replace a single-line directive like:
      <key> <...>;
    with:
      <key> <value_with_semicolon>
    or append it if not present. Preserves trailing comments.
    """
    pattern = rf"(^\s*{re.escape(key)}\s+)[^;]*;[ \t]*(?:#.*)?$"
    replacement = r"\g<1>" + value_with_semicolon
    new_content, n = re.subn(pattern, replacement, content, flags=re.MULTILINE)
    if n == 0:
        if not new_content.endswith("\n"):
            new_content += "\n"
        new_content += f"{key} {value_with_semicolon}\n"
    return new_content

def write_atomic(path: str, new_content: str) -> None:
    """Atomically write content to file."""
    d = os.path.dirname(path)
    os.makedirs(d, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".conf.tmp-", dir=d)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(new_content)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise

def backup_path(path: str) -> str:
    """Generate backup path with timestamp."""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{path}.{ts}.bak"

def remove_backup(path: str) -> bool:
    """
    Remove a backup file if it exists.
    Returns True if removed, False if not present.
    """
    try:
        if os.path.exists(path):
            os.unlink(path)
            return True
        return False
    except Exception as e:
        raise RuntimeError(f"Failed to remove backup {path}: {e}")

def file_to_base64(path: str) -> str:
    """Read a file as bytes and return a base64-encoded ASCII string."""
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")

