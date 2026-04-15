"""Runtime configuration — env-var driven, no secrets in code."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven settings.

    Loaded from `.env` in dev and from the systemd EnvironmentFile in prod.
    """

    model_config = SettingsConfigDict(env_prefix="ZDR_", env_file=".env", extra="ignore")

    # Where the honeypot writes its JSON event log. Cowrie's default is
    # /opt/cowrie/var/log/cowrie/cowrie.json when running under T-Pot.
    cowrie_log_path: Path = Field(
        default=Path("/data/cowrie/log/cowrie.json"),
        description="Path to the cowrie JSON log, tailed for new events.",
    )

    # MaxMind GeoLite2-City database. Download with `geoipupdate`.
    geoip_db_path: Path = Field(
        default=Path("/data/geoip/GeoLite2-City.mmdb"),
        description="Path to the GeoLite2-City MMDB.",
    )

    # HMAC key used to sign the public feed. Consumers can verify the
    # signature header to detect tampering at the CDN layer.
    feed_signing_key: str = Field(
        default="change-me-this-is-not-a-secret",
        description="HMAC-SHA256 signing key for the public feed.",
    )

    # Size of the in-memory event ring buffer. Older events age out.
    event_buffer_size: int = Field(default=500, ge=50, le=10_000)

    # Feed staleness window — how long an event remains in the public feed.
    feed_window_seconds: int = Field(default=600, ge=30, le=86_400)

    # Host/port the API binds to.
    host: str = "127.0.0.1"
    port: int = 8080


settings = Settings()
