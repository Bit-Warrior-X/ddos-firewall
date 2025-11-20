# core/nginx_parser.py
"""Nginx configuration parsing functions."""
import os
import re
import math
import base64
from typing import List, Dict, Tuple, Optional
import config

# Regex patterns
_CFG_LINE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s+(.*?)\s*;\s*$')
_SIZE_RE = re.compile(r"^\s*(\d+)\s*([kKmMgG]?)\s*$")
_TIME_RE = re.compile(r"^\s*(\d+)\s*([a-zA-Z]+)?\s*$")
_LOC_RE = re.compile(r'^\s*location\s+/\s*acl_rule(\d+)\s*\{')

def _to_megabytes(val: str) -> int:
    """Convert size string ('10m', '200M', '1024k', '1g') to MB (int)."""
    m = _SIZE_RE.match(val)
    if not m:
        raise ValueError(f"Invalid size value: {val}")
    num = int(m.group(1))
    unit = (m.group(2) or "m").lower()
    if unit == "k":
        return max(1, math.ceil(num / 1024))
    if unit == "m":
        return num
    if unit == "g":
        return num * 1024
    return num

def _to_seconds(val: str) -> int:
    """Convert time string ('10s', '1500ms', '2m', '1h') to seconds (int)."""
    m = _TIME_RE.match(val)
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
    return num

def parse_nginx_kv(path: str) -> Dict[str, str]:
    """
    Reads simple 'key value;' directives from the given nginx conf.
    Ignores comments and blank lines. Returns dict {key: value_string}.
    """
    kv = {}
    with open(path, "r") as f:
        for raw in f:
            line = raw.split('#', 1)[0].strip()
            if not line:
                continue
            m = _CFG_LINE.match(line)
            if m:
                key, val = m.group(1), m.group(2)
                kv[key] = val.strip()
    return kv

def get_report_settings(path: str = config.CONFIG_HTTP_REPORT_IP_PATH) -> Tuple[str, List[str], str]:
    """
    Returns: (status_onoff: 'on'|'off', methods_list: ['GET','POST', ...], block_duration: str)
    """
    kv = parse_nginx_kv(path)
    status = kv.get("report_module_check", "off").lower()
    methods_raw = kv.get("report_available_methods", "")
    methods = [m for m in re.split(r'[,\s]+', methods_raw) if m]
    block_duration = kv.get("report_block_duration", "300")
    return status, methods, block_duration

def _parse_address(addr: str) -> Tuple[str, Optional[int]]:
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
    return addr, None

def parse_backend_list(path: str = config.CONFIG_BACKEND_LIST_PATH) -> List[Dict]:
    """
    Parses lines like: server 10.10.10.12:8080 weight=2; # backend0
    Returns: list[{"name": str, "ip": str, "port": int, "weight": int}]
    """
    servers = []
    in_block = False
    with open(path, "r") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('upstream '):
                in_block = True
                continue
            if in_block and line.startswith('}'):
                in_block = False
                continue
            if 'server ' not in line or line.lstrip().startswith('#'):
                continue

            before_hash, *after_hash = line.split('#', 1)
            name = after_hash[0].strip() if after_hash else ""
            before_semicolon = before_hash.split(';', 1)[0]
            tokens = before_semicolon.split()
            
            if len(tokens) < 2 or tokens[0] != 'server':
                continue

            addr = tokens[1]
            params = " ".join(tokens[2:]) if len(tokens) > 2 else ""
            m = re.search(r"\bweight\s*=\s*(\d+)\b", params)
            weight = int(m.group(1)) if m else 1

            ip, port = _parse_address(addr)
            if port is None:
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

def parse_acl_system_config(path: str = config.CONFIG_HTTP_LUA_ACL_PATH) -> Dict:
    """
    Parse http_lua_acl.conf and return:
      {
        "acl_rule_shm_size": <MB:int>,
        "acl_req_shm_size": <MB:int>,
        "acl_rsp_shm_size": <MB:int>,
        "acl_optimize_period": <seconds:int>
      }
    """
    wanted = {
        "acl_rule_shm_size": None,
        "acl_req_shm_size": None,
        "acl_rsp_shm_size": None,
        "acl_optimize_period": None,
    }

    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "r") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
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

def parse_acl_switch(path: str = config.CONFIG_SERVER_ACL_PATH) -> str:
    """
    Reads server_acl.conf and returns 'on' or 'off' from: acl on; / acl off;
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

    raise ValueError("Missing 'acl on|off;' directive in server_acl.conf")

def parse_set_ports(path: str = config.CONFIG_SERVER_DEFAULT_PORTS_PATH) -> str:
    """
    Reads server_default_ports.conf and returns '80,8080' from listen directives.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    patt = re.compile(r"^\s*listen\s+(\d+)\s*;\s*$", re.IGNORECASE)
    ports = []

    with open(path, "r") as f:
        for raw in f:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            m = patt.match(line)
            if m:
                ports.append(m.group(1))

    if not ports:
        raise ValueError("No 'listen' directives found in server_default_ports.conf")

    return ",".join(ports)

def _extract_balanced_curly(text: str, start_idx: int) -> str:
    """
    Return the substring from the first '{' at/after start_idx up to its
    matching '}' (inclusive). Handles quotes and Lua long strings.
    """
    i = text.find('{', start_idx)
    if i == -1:
        raise ValueError("Opening '{' for rules block not found")

    level = 0
    in_sq = in_dq = in_long = False
    j = i
    n = len(text)

    while j < n:
        ch = text[j]

        if not in_sq and not in_dq:
            if not in_long and ch == '[' and j + 1 < n and text[j+1] == '[':
                in_long = True
                j += 2
                continue
            if in_long and ch == ']' and j + 1 < n and text[j+1] == ']':
                in_long = False
                j += 2
                continue

        if in_long:
            j += 1
            continue

        if not in_dq and ch == "'" and not in_sq:
            in_sq = True
            j += 1
            continue
        if in_sq:
            if ch == '\\':
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
            if ch == '\\':
                j += 2
                continue
            if ch == '"':
                in_dq = False
            j += 1
            continue

        if ch == '{':
            level += 1
        elif ch == '}':
            level -= 1
            if level == 0:
                return text[i:j+1]

        j += 1

    raise ValueError("Unbalanced '{' ... '}' in rules block")

def parse_acl_rule_management(path: str = config.CONFIG_SERVER_LUA_ACL_SET_PATH) -> List[Dict]:
    """
    Parse server_lua_acl_set.conf and return:
      [{"id": 18, "rules": "<base64 of rules = { ... } >"}, ...]
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    with open(path, "r") as f:
        lines = f.readlines()

    results = []
    i = 0
    L = len(lines)

    while i < L:
        m = _LOC_RE.match(lines[i])
        if not m:
            i += 1
            continue

        acl_id = int(m.group(1))
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
        rm = re.search(r"rules\s*=\s*\{", block_text)
        if not rm:
            continue

        rules_block = _extract_balanced_curly(block_text, rm.start())
        rules_b64 = base64.b64encode(rules_block.encode("utf-8")).decode("ascii")

        results.append({
            "id": acl_id,
            "rules": rules_b64
        })

    return results

def _split_top_level_items(table_body: str) -> List[str]:
    """Given content inside the outer {...} of the rules table, return a list of '{...}' items."""
    items = []
    n = len(table_body)
    j = 0
    in_sq = in_dq = in_long = False
    level = 0
    start = None
    while j < n:
        ch = table_body[j]
        if not in_sq and not in_dq:
            if not in_long and ch == '[' and j + 1 < n and table_body[j+1] == '[':
                in_long = True
                j += 2
                continue
            if in_long and ch == ']' and j + 1 < n and table_body[j+1] == ']':
                in_long = False
                j += 2
                continue
        if in_long:
            j += 1
            continue
        if not in_dq and ch == "'" and not in_sq:
            in_sq = True
            j += 1
            continue
        if in_sq:
            if ch == '\\':
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
            if ch == '\\':
                j += 2
                continue
            if ch == '"':
                in_dq = False
            j += 1
            continue

        if ch == '{':
            if level == 0:
                start = j
            level += 1
        elif ch == '}':
            level -= 1
            if level == 0 and start is not None:
                items.append(table_body[start:j+1])
                start = None
        j += 1
    return items

def parse_acl_rule_apply(path: str = config.CONFIG_LOCATION_LUA_ACL_CHECK_PATH) -> List[Dict]:
    """
    Returns list of dicts:
      [{ "id": int, "checking_cond": "allow|block", "apply_code": "allow|block|return_code|redirect", "apply_content": <""|int|str> }, ...]
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    m = re.search(r"local\s+rules\s*=\s*\{", text)
    if not m:
        return []

    rules_block = _extract_balanced_curly(text, m.start())
    inner = rules_block[1:-1]
    entries = _split_top_level_items(inner)
    out = []

    id_re = re.compile(r"\bid\s*=\s*(\d+)")
    cond_re = re.compile(r'\bcond\s*=\s*"(?P<cond>allow|block)"', re.IGNORECASE)
    act_re = re.compile(r"\baction\s*=\s*\{")
    kind_re = re.compile(r'\bkind\s*=\s*"(?P<kind>allow|block|return_code|redirect)"', re.IGNORECASE)
    code_re = re.compile(r"\bcode\s*=\s*(\d+)")
    url_long = re.compile(r"\burl\s*=\s*\[\[(.*?)\]\]", re.S)
    url_quot = re.compile(r'\burl\s*=\s*"([^"]*)"')

    for item in entries:
        m_id = id_re.search(item)
        if not m_id:
            continue
        rid = int(m_id.group(1))

        m_cond = cond_re.search(item)
        checking_cond = (m_cond.group("cond").lower() if m_cond else "allow")

        m_act = act_re.search(item)
        if not m_act:
            continue
        act_block = _extract_balanced_curly(item, m_act.start())
        act_inner = act_block[1:-1]

        m_kind = kind_re.search(act_inner)
        if not m_kind:
            continue
        apply_code = m_kind.group("kind").lower()

        apply_content = ""
        if apply_code == "return_code":
            m_code = code_re.search(act_inner)
            if m_code:
                apply_content = int(m_code.group(1))
        elif apply_code == "redirect":
            m_url = url_long.search(act_inner) or url_quot.search(act_inner)
            if m_url:
                apply_content = m_url.group(1)

        out.append({
            "id": rid,
            "checking_cond": checking_cond,
            "apply_code": apply_code,
            "apply_content": apply_content
        })

    return out

