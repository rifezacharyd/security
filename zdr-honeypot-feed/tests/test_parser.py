"""Parser tests — no network, no MaxMind DB required."""

from __future__ import annotations

import json
from pathlib import Path

from zdr_honeypot_feed.geo import GeoResolver
from zdr_honeypot_feed.models import GeoPoint
from zdr_honeypot_feed.parser import parse_line

SENSOR = GeoPoint(lat=36.72, lon=-81.96)


def _resolver() -> GeoResolver:
    # Path that doesn't exist → reader is None, lookups return None.
    return GeoResolver(Path("/nonexistent/GeoLite2-City.mmdb"))


def test_parse_login_failed() -> None:
    line = json.dumps(
        {
            "eventid": "cowrie.login.failed",
            "timestamp": "2026-04-14T20:00:00.000000Z",
            "src_ip": "203.0.113.42",
            "username": "root",
            "password": "123456",
        }
    )
    event = parse_line(line, resolver=_resolver(), sensor_location=SENSOR)
    assert event is not None
    assert event.protocol == "ssh"
    assert event.technique == "SSH brute-force"
    assert event.src_ip_prefix == "203.0.113.0/24"
    assert event.dst == SENSOR


def test_parse_ignores_unknown_eventid() -> None:
    line = json.dumps(
        {
            "eventid": "cowrie.session.connect",
            "timestamp": "2026-04-14T20:00:00.000000Z",
            "src_ip": "203.0.113.42",
        }
    )
    assert parse_line(line, resolver=_resolver(), sensor_location=SENSOR) is None


def test_parse_skips_malformed() -> None:
    assert parse_line("not-json", resolver=_resolver(), sensor_location=SENSOR) is None
    assert parse_line("", resolver=_resolver(), sensor_location=SENSOR) is None
