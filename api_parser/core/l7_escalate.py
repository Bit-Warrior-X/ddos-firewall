# core/l7_escalate.py
"""L7 network IP escalation: Sparta (unified) or nftables (L7-only).

Athens never opens the Sparta control socket. The flusher POSTs here and
angelos picks the backend from the current license.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
from typing import Any, Dict, Iterable, List, Sequence, Tuple

import config
from core import license_check as license_check_mod
from core.license_check import get_license_info

SPARTA_SOCK = getattr(config, "SPARTA_CONTROL_SOCK", "/tmp/ebpf_fw.sock")
NFT_TABLE = getattr(config, "L7_NFT_TABLE", "dorian")
NFT_SET = getattr(config, "L7_NFT_SET", "l7_block")
NFT_FAMILY = "inet"
REASON_DEFAULT = "l7-guard"
BACKEND_REDIS_KEY = "l7guard:backend"


def current_backend() -> str:
    """Return 'sparta', 'nft', or 'none' from cached/fresh license info."""
    info = license_check_mod.license_info
    if info is None:
        try:
            info = get_license_info()
            license_check_mod.license_info = info
        except Exception:
            return "none"
    if not info.allows_l7:
        return "none"
    if info.allows_l4:
        return "sparta"
    return "nft"


def _valid_ipv4(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv4Address)


def _normalize_ips(ips: Iterable[Any]) -> List[str]:
    out: List[str] = []
    seen = set()
    for raw in ips or []:
        ip = str(raw or "").strip()
        if not ip or ip in seen or not _valid_ipv4(ip):
            continue
        seen.add(ip)
        out.append(ip)
    return out


def _nft(*args: str) -> Tuple[bool, str]:
    try:
        proc = subprocess.run(
            ["nft", *args],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        return False, "nft not found"
    except subprocess.TimeoutExpired:
        return False, "nft timed out"
    except Exception as exc:
        return False, str(exc)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return False, err or f"nft exit {proc.returncode}"
    return True, (proc.stdout or "").strip()


def ensure_nft_table() -> Tuple[bool, str]:
    """Create inet table/set/input drop rule for L7-only escalate (idempotent)."""
    ok, err = _nft("list", "table", NFT_FAMILY, NFT_TABLE)
    if not ok:
        ok, err = _nft("add", "table", NFT_FAMILY, NFT_TABLE)
        if not ok:
            return False, f"add table: {err}"

    ok, _ = _nft("list", "set", NFT_FAMILY, NFT_TABLE, NFT_SET)
    if not ok:
        ok, err = _nft(
            "add",
            "set",
            NFT_FAMILY,
            NFT_TABLE,
            NFT_SET,
            "{",
            "type",
            "ipv4_addr",
            ";",
            "flags",
            "timeout",
            ";",
            "}",
        )
        if not ok:
            return False, f"add set: {err}"

    ok, out = _nft("list", "chain", NFT_FAMILY, NFT_TABLE, "input")
    if not ok:
        ok, err = _nft(
            "add",
            "chain",
            NFT_FAMILY,
            NFT_TABLE,
            "input",
            "{",
            "type",
            "filter",
            "hook",
            "input",
            "priority",
            "-100",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        )
        if not ok:
            return False, f"add chain: {err}"
        ok, out = _nft("list", "chain", NFT_FAMILY, NFT_TABLE, "input")

    needle = f"ip saddr @{NFT_SET} drop"
    if needle not in (out or ""):
        ok, err = _nft(
            "add",
            "rule",
            NFT_FAMILY,
            NFT_TABLE,
            "input",
            "ip",
            "saddr",
            f"@{NFT_SET}",
            "drop",
        )
        if not ok:
            return False, f"add rule: {err}"
    return True, "ok"


def teardown_nft_table() -> Tuple[bool, str]:
    """Remove the L7 nft table when L7 is not licensed or unified uses Sparta."""
    ok, err = _nft("list", "table", NFT_FAMILY, NFT_TABLE)
    if not ok:
        return True, "absent"
    ok, err = _nft("delete", "table", NFT_FAMILY, NFT_TABLE)
    if not ok:
        return False, err
    return True, "deleted"


def _sparta_add_block_ips(ips: Sequence[str], ttl: int, reason: str) -> Tuple[bool, str]:
    if not os.path.exists(SPARTA_SOCK):
        return False, f"sparta sock missing: {SPARTA_SOCK}"
    tag = (reason or REASON_DEFAULT).replace(" ", "_")[:64] or REASON_DEFAULT
    payload = f"ADD_BLOCK_IPS {int(ttl)} {tag}\n" + "\n".join(ips) + "\nEND\n"
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(SPARTA_SOCK)
        sock.sendall(payload.encode("utf-8"))
        chunks: List[bytes] = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b"\n" in data and len(chunks) > 0:
                joined = b"".join(chunks)
                if joined.count(b"\n") >= 1:
                    # status line is enough; detail may follow
                    if joined.count(b"\n") >= 2 or len(joined) > 16:
                        break
        sock.close()
    except OSError as exc:
        return False, f"sparta sock: {exc}"
    raw = b"".join(chunks).decode("utf-8", errors="replace")
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines or lines[0] != "ok":
        return False, raw.strip() or "sparta ADD_BLOCK_IPS failed"
    detail = lines[1] if len(lines) > 1 else "ok"
    return True, detail


def _nft_add_elements(ips: Sequence[str], ttl: int) -> Tuple[bool, str]:
    ok, err = ensure_nft_table()
    if not ok:
        return False, err
    secs = max(1, int(ttl))
    # One element command is enough; batch for speed.
    elems = ", ".join(f"{ip} timeout {secs}s" for ip in ips)
    ok, err = _nft(
        "add",
        "element",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_SET,
        "{",
        elems,
        "}",
    )
    if not ok:
        return False, err
    return True, f"added:{len(ips)}"


def escalate_ips(
    ips: Sequence[Any],
    ttl: int,
    reason: str = REASON_DEFAULT,
) -> Dict[str, Any]:
    """Block IPs at the network layer. Returns a JSON-serializable result dict."""
    clean = _normalize_ips(ips)
    try:
        ttl_i = int(ttl)
    except (TypeError, ValueError):
        ttl_i = int(getattr(config, "DEFAULT_BLOCK_DURATION", 3600))
    if ttl_i <= 0:
        ttl_i = int(getattr(config, "DEFAULT_BLOCK_DURATION", 3600))

    backend = current_backend()
    if backend == "none":
        return {
            "status": "error",
            "message": "L7 escalate not allowed for current license",
            "backend": backend,
            "added": 0,
        }
    if not clean:
        return {
            "status": "error",
            "message": "no valid IPv4 addresses",
            "backend": backend,
            "added": 0,
        }

    if backend == "sparta":
        ok, detail = _sparta_add_block_ips(clean, ttl_i, reason)
    else:
        ok, detail = _nft_add_elements(clean, ttl_i)

    if not ok:
        return {
            "status": "error",
            "message": detail,
            "backend": backend,
            "added": 0,
            "ips": clean,
            "ttl": ttl_i,
        }
    return {
        "status": "success",
        "backend": backend,
        "added": len(clean),
        "detail": detail,
        "ips": clean,
        "ttl": ttl_i,
        "reason": reason or REASON_DEFAULT,
    }


def sync_escalate_backend() -> str:
    """Install/teardown nft and publish Redis backend flag from license."""
    backend = current_backend()
    try:
        from core.redis_client import RedisClient

        rcli = RedisClient.get_client()
        if backend == "none":
            try:
                rcli.delete(BACKEND_REDIS_KEY)
            except Exception:
                pass
        else:
            rcli.set(BACKEND_REDIS_KEY, backend)
    except Exception as exc:
        print(f"[L7_ESCALATE] Redis backend flag update failed: {exc}", flush=True)

    if backend == "nft":
        ok, msg = ensure_nft_table()
        print(f"[L7_ESCALATE] nft ensure -> {'ok' if ok else 'fail'}: {msg}", flush=True)
    else:
        ok, msg = teardown_nft_table()
        print(f"[L7_ESCALATE] nft teardown -> {'ok' if ok else 'fail'}: {msg}", flush=True)
    return backend


