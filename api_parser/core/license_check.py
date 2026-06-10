# core/license_check.py
"""License validation wrapper around ebpf_firewall get_license_info()."""
import os
from dataclasses import dataclass
from typing import Optional

import config

try:
    from core._license_native import get_license_info as _native_get_license_info
except ImportError:
    _native_get_license_info = None

L4_LICENSE_TYPES = frozenset({"trial", "l4", "unified"})
L7_LICENSE_TYPES = frozenset({"trial", "l7", "unified"})
VALID_LICENSE_TYPES = L4_LICENSE_TYPES | L7_LICENSE_TYPES


@dataclass(frozen=True)
class LicenseInfo:
    status: int
    feature: int
    license_type: str
    days_left: int

    @property
    def allows_l4(self) -> bool:
        return self.status == 0 and self.license_type in L4_LICENSE_TYPES

    @property
    def allows_l7(self) -> bool:
        return self.status == 0 and self.license_type in L7_LICENSE_TYPES


def _ensure_license_env() -> None:
    """Set LICENSE_PATH/PUBKEY_PATH when not already in the environment."""
    if not os.environ.get("LICENSE_PATH"):
        os.environ["LICENSE_PATH"] = config.LICENSE_FILE
    if not os.environ.get("PUBKEY_PATH"):
        os.environ["PUBKEY_PATH"] = config.PUBKEY_FILE


def get_license_info() -> LicenseInfo:
    """
    Validate the license file using the same logic as ebpf_firewall_utils.c.

    status codes:
        0  - valid license
        1  - LICENSE_PATH env var missing
       -1  - invalid/manipulated license or machine id mismatch
       -2  - expired
       -3  - transient failure (e.g. fd pressure); caller should retry
    """
    if _native_get_license_info is None:
        raise RuntimeError(
            "core._license_native is not built; run api_parser/build.sh to compile the extension"
        )

    _ensure_license_env()
    raw = _native_get_license_info()
    return LicenseInfo(
        status=int(raw["status"]),
        feature=int(raw["feature"]),
        license_type=str(raw.get("license_type") or ""),
        days_left=int(raw.get("days_left") or 0),
    )


def get_license_status() -> int:
    """Return only the license status code."""
    return get_license_info().status


# Last known info for other modules (None = not checked yet).
license_info: Optional[LicenseInfo] = None
