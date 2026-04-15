# zdr-honeypot-feed

Signed JSON feed of live honeypot events — consumed by the threat map on
[zerodayresearch.dev](https://zerodayresearch.dev).

**The map on the site is not simulated.** This service tails a
[T-Pot](https://github.com/telekom-security/tpotce) honeypot's cowrie log,
geo-resolves source IPs via MaxMind GeoLite2, and publishes a recent-events
feed over HTTPS. Every response is HMAC-signed so consumers can detect
tampering at the CDN layer.

## What it is

A small FastAPI service that:

1. Tails `cowrie.json` from a T-Pot deployment.
2. Normalizes each event to an `AttackEvent` record (timestamp, protocol,
   technique, source geo, sensor geo, source IP `/24` prefix).
3. Keeps the last ~500 events in an in-memory ring buffer, windowed by time.
4. Serves the recent window over `GET /api/events` with an HMAC-SHA256
   signature in `X-ZDR-Signature`.

It deliberately does not:

- Store full source IP addresses in the public feed (only `/24` prefixes)
- Store full attacker session transcripts
- Act as a SIEM, a detection platform, or durable storage

## Endpoints

| Method | Path            | Purpose                                                     |
| ------ | --------------- | ----------------------------------------------------------- |
| GET    | `/api/health`   | Liveness probe                                              |
| GET    | `/api/events`   | Recent events, HMAC-signed                                  |

Response shape (`/api/events`):

```json
{
  "meta": {
    "generated_at": "2026-04-14T21:00:00Z",
    "window_seconds": 600,
    "event_count": 42,
    "sensor_label": "ZDR-HP-01"
  },
  "events": [
    {
      "ts": "2026-04-14T20:59:37Z",
      "kind": "attack",
      "protocol": "ssh",
      "technique": "SSH brute-force",
      "src": {"lat": 55.75, "lon": 37.62, "country": "RU", "city": "Moscow"},
      "dst": {"lat": 36.72, "lon": -81.96, "country": "US", "city": "Galax"},
      "src_ip_prefix": "203.0.113.0/24"
    }
  ]
}
```

Clients verify the signature like so:

```python
from zdr_honeypot_feed.signing import verify
verify(response.content, response.headers["X-ZDR-Signature"], KEY)
```

## Local development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Populate .env
cp .env.example .env
# edit ZDR_FEED_SIGNING_KEY, ZDR_COWRIE_LOG_PATH, ZDR_GEOIP_DB_PATH

# Run
zdr-feed
# or: uvicorn zdr_honeypot_feed.main:app --reload --port 8080

# Test
pytest -q
ruff check src tests
```

No cowrie log? The service happily runs with an empty buffer — the tailer
waits for the file to appear and picks up writes when it does.

## Production deploy

See `deploy/bootstrap.sh` for a one-shot installer that provisions a fresh
Debian 12 / Ubuntu 24.04 VPS with T-Pot, MaxMind geoipupdate, this feed, and
a firewall. Tested on a $6/mo Hetzner CX22.

Basic flow:

1. Spin up a VPS with at least 4 GB RAM (T-Pot needs it).
2. `ssh root@vps`, then:
   ```bash
   export GEOIP_ACCOUNT_ID=... GEOIP_LICENSE_KEY=...
   curl -fsSL https://raw.githubusercontent.com/rifezacharyd/zdr-honeypot-feed/main/deploy/bootstrap.sh | bash
   ```
3. Save the printed `FEED_KEY` — the site's map loader needs it to verify.
4. Put the service behind a reverse proxy (Caddy / Nginx / Cloudflare Tunnel).
   The map consumes `https://feed.zerodayresearch.dev/api/events`.

## Threat model & intentional limits

- **Public feed is read-only and rate-limited** at the reverse proxy.
- **Signing is about integrity, not authz.** Anyone can read the feed; the
  HMAC lets consumers prove the bytes weren't modified in transit.
- **Source IPs are never published in full.** Only `/24` prefixes.
- **No honeypot session data** (credentials tried, commands issued) is surfaced.
- **Timestamps are rounded to the second.**

## License

Business Source License 1.1 — free for any non-commercial use; commercial
redistribution requires a separate license from ZDR Development LLC.
