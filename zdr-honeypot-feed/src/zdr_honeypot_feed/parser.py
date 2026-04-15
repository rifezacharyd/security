"""Parse cowrie JSON events into normalized AttackEvent records.

Cowrie emits one JSON object per line. Relevant eventids we surface:

    cowrie.login.failed
    cowrie.login.success
    cowrie.command.input
    cowrie.session.file_download

Other events are ignored to keep the feed signal-rich.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import datetime

from .geo import GeoResolver, prefix_ipv4
from .models import AttackEvent, GeoPoint

# Map cowrie eventid → short human label.
_TECHNIQUE_MAP = {
    "cowrie.login.failed": "SSH brute-force",
    "cowrie.login.success": "SSH credential-stuffing",
    "cowrie.command.input": "Post-auth command execution",
    "cowrie.session.file_download": "Malware stage-2 download",
}


def parse_line(
    line: str,
    *,
    resolver: GeoResolver,
    sensor_location: GeoPoint,
) -> AttackEvent | None:
    """Parse one cowrie JSON log line into an AttackEvent, or None."""
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None

    eventid = obj.get("eventid")
    technique = _TECHNIQUE_MAP.get(eventid)
    if technique is None:
        return None

    src_ip = obj.get("src_ip")
    ts_raw = obj.get("timestamp")
    if not src_ip or not ts_raw:
        return None

    try:
        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
    except ValueError:
        return None

    src = resolver.lookup(src_ip) or GeoPoint(lat=0.0, lon=0.0)

    return AttackEvent(
        ts=ts,
        protocol="ssh",
        technique=technique,
        src=src,
        dst=sensor_location,
        src_ip_prefix=prefix_ipv4(src_ip),
    )


def parse_stream(
    lines: Iterable[str],
    *,
    resolver: GeoResolver,
    sensor_location: GeoPoint,
) -> Iterator[AttackEvent]:
    for line in lines:
        event = parse_line(line, resolver=resolver, sensor_location=sensor_location)
        if event is not None:
            yield event
