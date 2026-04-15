"""Thin wrapper around MaxMind GeoLite2-City with graceful fallback."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import geoip2.database
import geoip2.errors

from .models import GeoPoint


class GeoResolver:
    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._reader: geoip2.database.Reader | None = None
        if db_path.exists():
            self._reader = geoip2.database.Reader(str(db_path))

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None

    @lru_cache(maxsize=4096)
    def lookup(self, ip: str) -> GeoPoint | None:
        """Resolve an IP to a GeoPoint. Returns None on miss or no DB."""
        if self._reader is None:
            return None
        try:
            r = self._reader.city(ip)
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None
        if r.location.latitude is None or r.location.longitude is None:
            return None
        return GeoPoint(
            lat=float(r.location.latitude),
            lon=float(r.location.longitude),
            country=r.country.iso_code,
            city=r.city.name,
        )


def prefix_ipv4(ip: str) -> str:
    """Return the /24 prefix of an IPv4 address (v6 is masked to /48)."""
    if ":" in ip:
        # Crude IPv6 /48 mask
        return ":".join(ip.split(":")[:3]) + "::/48"
    parts = ip.split(".")
    if len(parts) != 4:
        return "unknown"
    return ".".join(parts[:3]) + ".0/24"
