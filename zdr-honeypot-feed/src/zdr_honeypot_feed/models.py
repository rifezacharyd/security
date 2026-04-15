"""Wire types for the public feed."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class GeoPoint(BaseModel):
    lat: float
    lon: float
    country: str | None = None
    city: str | None = None


class AttackEvent(BaseModel):
    """A single honeypot hit, normalized across source honeypots."""

    ts: datetime = Field(description="Event timestamp (UTC).")
    kind: Literal["attack"] = "attack"
    protocol: str = Field(description="ssh, http, telnet, smb, etc.")
    technique: str = Field(
        description="Short human label — e.g. 'SSH brute-force', 'cmd exec attempt'."
    )
    src: GeoPoint = Field(description="Attacker location (geo-ip'd).")
    dst: GeoPoint = Field(description="Honeypot sensor location (static).")
    src_ip_prefix: str = Field(
        description="Attacker IP /24 prefix. Full address is never published.",
        max_length=20,
    )


class FeedMeta(BaseModel):
    generated_at: datetime
    window_seconds: int
    event_count: int
    sensor_label: str


class FeedResponse(BaseModel):
    meta: FeedMeta
    events: list[AttackEvent]
