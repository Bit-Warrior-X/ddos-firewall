import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime

CONFIG_HTTP_REPORT_IP_PATH = "/usr/local/openresty/nginx/conf/http_report_ip.conf"
CONFIG_BACKEND_LIST_PATH = "/usr/local/openresty/nginx/conf/backend_list.conf"
CONFIG_HTTP_LUA_ACL_PATH = "/usr/local/openresty/nginx/conf/http_lua_acl.conf"
CONFIG_HEADER_CONF_PATH = "/usr/local/openresty/nginx/conf/header.conf"
CONFIG_HTTP_BASE_HEADER_CONF_PATH = "/usr/local/openresty/nginx/conf/http_base_header.conf"
CONFIG_LOCATION_PROXY_SETTING_CONF_PATH = "/usr/local/openresty/nginx/conf/location_proxy_setting.conf"
CONFIG_SERVER_ACL_PATH = "/usr/local/openresty/nginx/conf/server_acl.conf"
CONFIG_SERVER_LUA_ACL_SET_PATH = "/usr/local/openresty/nginx/conf/server_lua_acl_set.conf"
CONFIG_LOCATION_LUA_ACL_CHECK_PATH = "/usr/local/openresty/nginx/conf/location_lua_acl_check.conf"


def normalize_methods(method_field):
    allowed = {"GET", "HEAD", "POST", "PUT", "DELETE", "MKCOL", "COPY", "MOVE", "OPTIONS", "PROPFIND", "PROPPATCH", "LOCK", "UNLOCK", "PATCH", "TRACE", "CONNECT"}
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
        if m not in allowed:
            return None, f"Unsupported method '{m}'. Allowed: {', '.join(sorted(allowed))}."
        if m not in seen:
            seen.add(m)
            ordered.append(m)
    return " ".join(ordered), None

def replace_or_append(content, key, value_with_semicolon):
    """
    Replace a single-line directive like:
      <key> <...>;
    with:
      <key> <value_with_semicolon>
    or append it if not present. Preserves trailing comments.
    """
    # Match: start + optional space + key + spaces + (anything up to semicolon) + semicolon
    # Optional trailing spaces/comments until EOL.
    pattern = rf"(^\s*{re.escape(key)}\s+)[^;]*;[ \t]*(?:#.*)?$"
    # IMPORTANT: use \g<1> to avoid ambiguity when replacement starts with a digit.
    replacement = r"\g<1>" + value_with_semicolon
    new_content, n = re.subn(pattern, replacement, content, flags=re.MULTILINE)
    if n == 0:
        if not new_content.endswith("\n"):
            new_content += "\n"
        new_content += f"{key} {value_with_semicolon}\n"
    return new_content

def write_atomic(path, new_content):
    d = os.path.dirname(path)
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

def backup_path(path):
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"{path}.{ts}.bak"

def _trim_nginx_error(stderr: str) -> str:
    """
    Turn:
      nginx: [emerg] invalid method "AAA" in "report_available_methods" in /path/file:2
    into:
      invalid method "AAA" in "report_available_methods"
    """
    # Pick the first meaningful nginx line (typically [emerg]/[error])
    for raw in (stderr or "").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("nginx:"):
            # remove leading 'nginx: [level] '
            line = re.sub(r"^nginx:\s*\[[^\]]+\]\s*", "", line)
            # drop trailing location like: ' in /path/to/file:123'
            line = re.sub(r"\s+in\s+/.+?:\d+\s*$", "", line)
            # also drop generic trailing ' at ...' locations if present
            line = re.sub(r"\s+at\s+.+$", "", line)
            return line
    # Fallback: last non-empty line
    lines = [l.strip() for l in (stderr or "").splitlines() if l.strip()]
    return lines[-1] if lines else "Unknown nginx error"


def nginx_test():
    proc = subprocess.run(
        ["nginx", "-t"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    ok = (proc.returncode == 0)
    if ok:
        return True, (proc.stderr or proc.stdout or "").strip()
    # Return only the trimmed human-readable reason
    return False, _trim_nginx_error(proc.stderr)

def nginx_reload():
    """
    Returns (ok: bool, message: str)
    - On success: ok=True, usually 'signal process started'
    - On failure: ok=False, trimmed human-readable reason
    """
    proc = subprocess.run(
        ["nginx", "-s", "reload"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    if proc.returncode == 0:
        # Typically stderr has: 'nginx: signal process started'
        lines = [l.strip() for l in (proc.stderr or proc.stdout or "").splitlines() if l.strip()]
        msg = lines[-1] if lines else "nginx reload signaled"
        # If it starts with 'nginx:' trim the prefix for cleanliness
        if msg.startswith("nginx:"):
            msg = _trim_nginx_line(msg)
        return True, msg
    # failure -> trim
    return False, _trim_nginx_error(proc.stderr)

def remove_backup(path: str) -> bool:
    """
    Remove a backup file if it exists.
    Returns True if removed, False if not present.
    Raises only unexpected errors.
    """
    try:
        if os.path.exists(path):
            os.unlink(path)
            return True
        return False
    except Exception as e:
        # You can log this instead of raising if you prefer silent cleanup
        raise RuntimeError(f"Failed to remove backup {path}: {e}")
