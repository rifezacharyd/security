# zdr-honeypot-feed

Signed JSON feed of live honeypot events — consumed by the threat map on
[zerodayresearch.dev](https://zerodayresearch.dev).

**The map on the site is not simulated.** This service tails a
[T-Pot](https://github.com/telekom-security/tpotce) honeypot's cowrie log,
geo-resolves source IPs via MaxMind GeoLite2, and publishes a recent-events
feed over HTTPS. Every response is HMAC-signed so consumers can detect
tampering at the CDN layer.

---

## Contents

1. [What it is (and isn't)](#what-it-is-and-isnt)
2. [Endpoints](#endpoints)
3. [Local development](#local-development)
4. [Production deploy](#production-deploy)
5. [Wiring the site's threat map to the feed](#wiring-the-sites-threat-map-to-the-feed)
6. [Operations](#operations)
7. [Threat model & intentional limits](#threat-model--intentional-limits)
8. [License](#license)

---

## What it is (and isn't)

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

---

## Endpoints

| Method | Path            | Purpose                                                     |
| ------ | --------------- | ----------------------------------------------------------- |
| GET    | `/api/health`   | Liveness probe                                              |
| GET    | `/api/events`   | Recent events, HMAC-signed                                  |

Response shape of `/api/events`:

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

Response headers:

| Header             | Meaning                                                  |
| ------------------ | -------------------------------------------------------- |
| `X-ZDR-Signature`  | `sha256=<hex>` HMAC-SHA256 over the response body        |
| `X-ZDR-Sensor`     | Sensor label (e.g. `ZDR-HP-01`)                          |
| `Cache-Control`    | `public, max-age=10` — short cache at edge               |

---

## Local development

```bash
cd zdr-honeypot-feed

python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Populate .env
cp .env.example .env
# edit ZDR_FEED_SIGNING_KEY, ZDR_COWRIE_LOG_PATH, ZDR_GEOIP_DB_PATH

# Run
zdr-feed                      # uses src/zdr_honeypot_feed/main.py::cli
# or, with auto-reload:
uvicorn zdr_honeypot_feed.main:app --reload --port 8080

# Test
pytest -q
ruff check src tests
```

No cowrie log? The service happily runs with an empty buffer — the tailer
waits for the file to appear and picks up writes when it does. You can also
append synthetic lines to a test log path to exercise the pipeline:

```bash
export ZDR_COWRIE_LOG_PATH=/tmp/fake-cowrie.json
echo '{"eventid":"cowrie.login.failed","timestamp":"2026-04-14T20:00:00Z","src_ip":"203.0.113.42","username":"root","password":"toor"}' >> /tmp/fake-cowrie.json
curl -s http://127.0.0.1:8080/api/events | jq
```

---

## Production deploy

The intended deployment is a single small VPS running T-Pot alongside this
service. `deploy/bootstrap.sh` provisions the whole thing end-to-end.

### Step 1 — Create a MaxMind account

MaxMind's GeoLite2 databases are free but require a signup.

1. Sign up at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup).
2. Generate a license key under **Account → Manage License Keys**.
3. Note your **Account ID** and the license key — the bootstrap script needs
   both.

### Step 2 — Provision a VPS

Minimum sizing:

- **4 GB RAM** (T-Pot is hungry; 2 GB will OOM)
- 2 vCPU
- 40 GB disk
- Debian 12 or Ubuntu 24.04

Tested on Hetzner CX22 (~$6/mo). Make sure SSH is reachable on a
non-standard port or hardened with key-only auth **before** running T-Pot —
cowrie will claim port 22 after install, so move real SSH to 64295 or
similar first.

### Step 3 — Run the bootstrap

```bash
ssh root@your-vps
export GEOIP_ACCOUNT_ID=123456
export GEOIP_LICENSE_KEY=your-license-key
curl -fsSL https://raw.githubusercontent.com/rifezacharyd/security/main/zdr-honeypot-feed/deploy/bootstrap.sh | bash
```

The script:

1. Installs Docker, UFW, and build basics.
2. Clones and installs T-Pot in user-type mode under `/opt/tpotce`.
3. Downloads the MaxMind GeoLite2-City DB to `/data/geoip` and installs a
   weekly cron refresh.
4. Clones this repo into `/opt/zdr/security/` and starts the feed service
   via `docker compose`.
5. Enables UFW with the ports T-Pot and the feed need.
6. Prints the generated `FEED_KEY` — **save this**, the site needs it to
   verify feed signatures.

### Step 4 — Put the feed behind TLS

The service binds to `127.0.0.1:8080` by design. Expose it to the internet
via a reverse proxy with real TLS — pick one:

**Option A — Caddy (simplest):**

```caddyfile
feed.zerodayresearch.dev {
  reverse_proxy 127.0.0.1:8080
}
```

**Option B — Cloudflare Tunnel (no open ports):**

```bash
cloudflared tunnel create zdr-feed
cloudflared tunnel route dns zdr-feed feed.zerodayresearch.dev
# config.yml: service → http://127.0.0.1:8080
cloudflared tunnel run zdr-feed
```

### Step 5 — Verify

```bash
curl -fs https://feed.zerodayresearch.dev/api/health
curl -fsD - https://feed.zerodayresearch.dev/api/events | head -30
```

You should see `X-ZDR-Signature: sha256=...` in the response headers and a
JSON body with `meta` + `events`. Events will be sparse until attackers
find your box (typically within 10 minutes of exposing port 22 on the
public internet).

---

## Wiring the site's threat map to the feed

The site currently generates random source/target city pairs in
`docs/assets/js/site.js`. Swap that for a live fetch:

```js
// Replace spawnArc() with a fetcher.
async function pollFeed() {
  try {
    const res = await fetch("https://feed.zerodayresearch.dev/api/events", {
      cache: "no-store",
    });
    if (!res.ok) return;
    const sig = res.headers.get("X-ZDR-Signature");
    const body = await res.text();
    if (!(await verifySignature(body, sig, FEED_KEY))) {
      console.warn("[threat-map] feed signature mismatch — ignoring");
      return;
    }
    const { events } = JSON.parse(body);
    for (const e of events) {
      const a = project(e.src.lat, e.src.lon);
      const b = project(e.dst.lat, e.dst.lon);
      if (a && b) arcs.push({ ax: a[0], ay: a[1], bx: b[0], by: b[1],
                              t: 0, speed: 0.008, kind: "attack", triggered: false });
    }
  } catch { /* network blip, retry next interval */ }
}
setInterval(pollFeed, 15_000);
pollFeed();
```

Browser-side signature verification:

```js
async function verifySignature(body, header, key) {
  if (!header?.startsWith("sha256=")) return false;
  const cryptoKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", cryptoKey,
    new TextEncoder().encode(body));
  const hex = Array.from(new Uint8Array(mac))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  return `sha256=${hex}` === header;
}
```

**Note on the key:** publishing the HMAC key in a public JS bundle
defeats the purpose of signing — any adversary who can MITM the feed can
also read the site source. Signing is worth it when:

- The feed is consumed by a *server* you control (e.g. a static build job
  that regenerates a public JSON snapshot).
- Or you swap HMAC for **Ed25519 signatures**: publish the signed feed +
  detached signature, and hard-code the **public** key in the site. The
  VPS keeps the private key; the browser only ever needs the public half.

Ed25519 is the better long-term design — file an issue or open a branch
when you're ready to swap.

---

## Operations

### Rotate the feed signing key

```bash
ssh root@vps
cd /opt/zdr/security/zdr-honeypot-feed
NEW_KEY=$(openssl rand -hex 32)
sed -i "s|^ZDR_FEED_SIGNING_KEY=.*|ZDR_FEED_SIGNING_KEY=${NEW_KEY}|" .env
docker compose restart feed
echo "new key: ${NEW_KEY}"
# then update the site consumer with the new key
```

### Refresh the GeoIP database

A weekly cron installed by the bootstrap handles this automatically. To
force a refresh:

```bash
docker run --rm \
  -v /data/geoip:/data \
  -v /etc/GeoIP.conf:/etc/GeoIP.conf:ro \
  ghcr.io/maxmind/geoipupdate:latest
docker compose restart feed
```

### Rebuild the image after a code change

```bash
cd /opt/zdr/security
git pull
cd zdr-honeypot-feed
docker compose build
docker compose up -d
```

### Logs

```bash
docker compose logs -f feed           # feed service
docker logs -f cowrie-cowrie-1        # cowrie honeypot (ssh)
```

---

## Threat model & intentional limits

- **Public feed is read-only and rate-limited** at the reverse proxy.
- **Signing is about integrity, not authz.** Anyone can read the feed; the
  HMAC lets consumers prove the bytes weren't modified in transit.
- **Source IPs are never published in full.** Only `/24` prefixes.
- **No honeypot session data** (credentials tried, commands issued) is surfaced.
- **Timestamps are rounded to the second.**
- **The VPS itself is the honeypot.** Do not run this alongside production
  workloads on the same host.

---

## License

Business Source License 1.1 — free for any non-commercial use; commercial
redistribution requires a separate license from ZDR Development LLC.
