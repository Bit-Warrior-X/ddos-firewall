import os
import re
import shutil
import subprocess
import tempfile
import base64
import math
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
    

_cfg_line = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(.*?)\s*;\s*$')

def parse_nginx_kv(path: str = CONFIG_HTTP_REPORT_IP_PATH) -> dict:
    """
    Reads simple 'key value;' directives from the given nginx conf.
    Ignores comments and blank lines. Returns dict {key: value_string}.
    """
    kv = {}
    with open(path, "r") as f:
        for raw in f:
            # strip inline comments
            line = raw.split('#', 1)[0].strip()
            if not line:
                continue
            m = _cfg_line.match(line)
            if m:
                key, val = m.group(1), m.group(2)
                kv[key] = val.strip()
    return kv

def get_report_settings(path: str = CONFIG_HTTP_REPORT_IP_PATH):
    """
    Returns: (status_onoff: 'on'|'off', methods_list: ['GET','POST', ...])
    Missing keys are handled gracefully with defaults.
    """
    kv = parse_nginx_kv(path)
    status = kv.get("report_module_check", "off").lower()
    methods_raw = kv.get("report_available_methods", "")
    methods = [m for m in re.split(r'[,\s]+', methods_raw) if m]
    return status, methods

def _parse_address(addr: str):
    """
    Returns (ip_or_host, port:int|None)
    Supports IPv6 like [2001:db8::1]:8080
    """
    addr = addr.strip()
    if addr.startswith('['):  # IPv6
        end = addr.find(']')
        host = addr[1:end]
        port = None
        rest = addr[end+1:]
        if rest.startswith(':'):
            port = int(rest[1:])
        return host, port
    if ':' in addr:
        host, port = addr.rsplit(':', 1)
        return host, int(port)
    return addr, None  # rare; nginx allows domain w/o port

def parse_backend_list(path: str = CONFIG_BACKEND_LIST_PATH):
    """
    Parses lines like:
      server 10.10.10.12:8080 weight=2; # backend0
    Returns: list[{"name": str, "ip": str, "port": int, "weight": int}]
    """
    servers = []
    in_block = False
    with open(path, "r") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            # Track upstream blocks (optional; we’ll parse server lines anywhere)
            if line.startswith('upstream '):
                in_block = True
                continue
            if in_block and line.startswith('}'):
                in_block = False
                continue
            if 'server ' not in line or line.lstrip().startswith('#'):
                continue

            # Split out trailing comment for the name
            before_hash, *after_hash = line.split('#', 1)
            name = after_hash[0].strip() if after_hash else ""

            # Trim to before ';'
            before_semicolon = before_hash.split(';', 1)[0]

            # Tokenize after the "server" keyword
            tokens = before_semicolon.split()
            # Expect: ["server", "<addr>", "weight=2", "..."]
            if len(tokens) < 2 or tokens[0] != 'server':
                continue

            addr = tokens[1]
            params = " ".join(tokens[2:]) if len(tokens) > 2 else ""

            # Extract weight (default 1)
            m = re.search(r"\bweight\s*=\s*(\d+)\b", params)
            weight = int(m.group(1)) if m else 1

            ip, port = _parse_address(addr)
            if port is None:
                # If no port is present, assume 80 (adjust if your config differs)
                port = 80

            if not name:
                name = f"backend-{ip}-{port}"

            servers.append({
                "name": name,
                "ip": ip,
                "port": port,
                "weight": weight
            })
    return servers

def file_to_base64(path: str) -> str:
    """Read a file as bytes and return a base64-encoded ASCII string."""
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")
    

# --- unit helpers ------------------------------------------------------------

_size_re = re.compile(r"^\s*(\d+)\s*([kKmMgG]?)\s*$")
_time_re = re.compile(r"^\s*(\d+)\s*([a-zA-Z]+)?\s*$")

def _to_megabytes(val: str) -> int:
    """
    Convert '10m', '200M', '1024k', '1g' -> MB (int).
    If 'k' is used, rounds up to the next MB.
    """
    m = _size_re.match(val)
    if not m:
        raise ValueError(f"Invalid size value: {val}")
    num = int(m.group(1))
    unit = (m.group(2) or "m").lower()
    if unit == "k":
        return max(1, math.ceil(num / 1024))  # 1024k -> 1 MB
    if unit == "m":
        return num
    if unit == "g":
        return num * 1024
    # No/unknown unit: treat as MB
    return num

def _to_seconds(val: str) -> int:
    """
    Convert '10s', '1500ms', '2m', '1h' -> seconds (int, ceil for sub-second).
    """
    m = _time_re.match(val)
    if not m:
        raise ValueError(f"Invalid time value: {val}")
    num = int(m.group(1))
    unit = (m.group(2) or "s").lower()

    if unit in ("s", "sec", "secs", "second", "seconds"):
        return num
    if unit in ("ms", "msec", "millisecond", "milliseconds"):
        return max(1, math.ceil(num / 1000))
    if unit in ("m", "min", "mins", "minute", "minutes"):
        return num * 60
    if unit in ("h", "hr", "hrs", "hour", "hours"):
        return num * 3600
    # Unknown unit -> assume seconds
    return num

# --- parser ------------------------------------------------------------------

def parse_acl_system_config(path: str = CONFIG_SERVER_LUA_ACL_SET_PATH) -> dict:
    """
    Parse http_lua_acl.conf and return:
      {
        "acl_rule_shm_size": <MB:int>,
        "acl_req_shm_size": <MB:int>,
        "acl_rsp_shm_size": <MB:int>,
        "acl_optimize_period": <seconds:int>
      }
    Ignores comments and blank lines.
    """
    wanted = {
        "acl_rule_shm_size": None,
        "acl_req_shm_size":  None,
        "acl_rsp_shm_size":  None,
        "acl_optimize_period": None,
    }

    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "r") as f:
        for raw in f:
            # strip inline comments
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            # match: key <value> ;
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s+([^;\s]+)\s*;\s*$", line)
            if not m:
                continue
            key, val = m.group(1), m.group(2)
            if key not in wanted:
                continue
            if key == "acl_optimize_period":
                wanted[key] = _to_seconds(val)
            else:
                wanted[key] = _to_megabytes(val)

    # Optional: fallbacks if any directive is missing (tweak/remove if not desired)
    defaults = {
        "acl_rule_shm_size": 10,
        "acl_req_shm_size": 200,
        "acl_rsp_shm_size": 200,
        "acl_optimize_period": 10,
    }
    for k, v in wanted.items():
        if v is None:
            wanted[k] = defaults[k]
    return wanted


def parse_acl_switch(path: str = CONFIG_SERVER_ACL_PATH) -> str:
    """
    Reads `server_acl.conf` and returns 'on' or 'off' from a line like:
      acl on;
      acl off;
    Ignores comments and blank lines.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    patt = re.compile(r"^\s*acl\s+(on|off)\s*;\s*$", re.IGNORECASE)
    with open(path, "r") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = patt.match(line)
            if m:
                return m.group(1).lower()

    # If directive not found, treat as error (or default to 'off' if you prefer)
    raise ValueError("Missing 'acl on|off;' directive in server_acl.conf")


_loc_re = re.compile(r'^\s*location\s+/\s*acl_rule(\d+)\s*\{')

def _extract_balanced_curly(text: str, start_idx: int) -> str:
    """
    Return the substring from the first '{' at/after start_idx up to its
    matching '}' (inclusive). We ignore braces inside single/double quotes
    and Lua long strings [[ ... ]].
    Raises ValueError if it can't find a balanced block.
    """
    i = text.find('{', start_idx)
    if i == -1:
        raise ValueError("Opening '{' for rules block not found")

    level = 0
    in_sq = False  # '
    in_dq = False  # "
    in_long = False  # [[ ... ]]
    j = i
    n = len(text)

    while j < n:
        ch = text[j]

        # Handle Lua long strings [[ ... ]]
        if not in_sq and not in_dq:
            # open long string?
            if not in_long and ch == '[' and j + 1 < n and text[j+1] == '[':
                in_long = True
                j += 2
                continue
            # close long string?
            if in_long and ch == ']' and j + 1 < n and text[j+1] == ']':
                in_long = False
                j += 2
                continue

        if in_long:
            j += 1
            continue

        # Handle normal quotes
        if not in_dq and ch == "'" and not in_sq:
            in_sq = True
            j += 1
            continue
        if in_sq:
            if ch == '\\':  # skip escape
                j += 2
                continue
            if ch == "'":
                in_sq = False
            j += 1
            continue

        if not in_sq and ch == '"' and not in_dq:
            in_dq = True
            j += 1
            continue
        if in_dq:
            if ch == '\\':  # skip escape
                j += 2
                continue
            if ch == '"':
                in_dq = False
            j += 1
            continue

        # Not inside any string → count braces
        if ch == '{':
            level += 1
        elif ch == '}':
            level -= 1
            if level == 0:
                return text[i:j+1]

        j += 1

    raise ValueError("Unbalanced '{' ... '}' in rules block")

def parse_acl_rule_management(path: str = CONFIG_SERVER_LUA_ACL_SET_PATH):
    """
    Parse server_lua_acl_set.conf and return:
      [
        {"id": 18, "rules": "<base64 of rules = { ... } >"},
        {"id": 21, "rules": "<base64 ... >"},
        ...
      ]
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "r") as f:
        lines = f.readlines()

    results = []
    i = 0
    L = len(lines)

    while i < L:
        m = _loc_re.match(lines[i])
        if not m:
            i += 1
            continue

        acl_id = int(m.group(1))
        # capture the full 'location { ... }' block to search for rules within
        brace_level = lines[i].count('{') - lines[i].count('}')
        block_lines = [lines[i]]
        i += 1

        while i < L and brace_level > 0:
            line = lines[i]
            brace_level += line.count('{')
            brace_level -= line.count('}')
            block_lines.append(line)
            i += 1

        block_text = "".join(block_lines)

        # Find 'rules = {' start within this location block
        rm = re.search(r"rules\s*=\s*\{", block_text)
        if not rm:
            # no rules → skip this location
            continue

        rules_block = _extract_balanced_curly(block_text, rm.start())
        rules_b64 = base64.b64encode(rules_block.encode("utf-8")).decode("ascii")

        results.append({
            "id": acl_id,
            "rules": rules_b64
        })

    return results