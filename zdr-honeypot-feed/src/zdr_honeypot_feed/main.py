"""FastAPI entrypoint — exposes a signed, rate-limited attack feed."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import orjson
import uvicorn
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .geo import GeoResolver
from .models import FeedMeta, FeedResponse, GeoPoint
from .parser import parse_line
from .signing import sign
from .store import EventBuffer
from .tail import tail

log = logging.getLogger("zdr.feed")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


# Sensor location — the honeypot VPS. Populated from env or defaults to
# the ZDR home coordinates (SW Virginia).
SENSOR_LOCATION = GeoPoint(lat=36.72, lon=-81.96, country="US", city="Galax")
SENSOR_LABEL = "ZDR-HP-01"


async def _ingest_loop(resolver: GeoResolver, buffer: EventBuffer) -> None:
    log.info("ingest loop starting (cowrie log: %s)", settings.cowrie_log_path)
    async for line in tail(settings.cowrie_log_path):
        event = parse_line(line, resolver=resolver, sensor_location=SENSOR_LOCATION)
        if event is not None:
            buffer.push(event)


@asynccontextmanager
async def lifespan(app: FastAPI):
    resolver = GeoResolver(settings.geoip_db_path)
    buffer = EventBuffer(
        maxlen=settings.event_buffer_size,
        window_seconds=settings.feed_window_seconds,
    )
    task = asyncio.create_task(_ingest_loop(resolver, buffer))
    app.state.resolver = resolver
    app.state.buffer = buffer
    try:
        yield
    finally:
        task.cancel()
        resolver.close()


app = FastAPI(
    title="ZDR Honeypot Feed",
    version="0.1.0",
    description="Signed JSON feed of recent honeypot events.",
    lifespan=lifespan,
)

# The threat map on zerodayresearch.dev consumes this feed cross-origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://zerodayresearch.dev"],
    allow_methods=["GET"],
    allow_headers=["*"],
    expose_headers=["X-ZDR-Signature", "X-ZDR-Sensor"],
)


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "sensor": SENSOR_LABEL}


@app.get("/api/events")
async def events() -> Response:
    buf: EventBuffer = app.state.buffer
    recent = buf.recent()
    feed = FeedResponse(
        meta=FeedMeta(
            generated_at=datetime.now(timezone.utc),
            window_seconds=settings.feed_window_seconds,
            event_count=len(recent),
            sensor_label=SENSOR_LABEL,
        ),
        events=recent,
    )
    body = orjson.dumps(feed.model_dump(mode="json"))
    signature = sign(body, settings.feed_signing_key)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "X-ZDR-Signature": signature,
            "X-ZDR-Sensor": SENSOR_LABEL,
            "Cache-Control": "public, max-age=10",
        },
    )


def cli() -> None:
    uvicorn.run(
        "zdr_honeypot_feed.main:app",
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    cli()
