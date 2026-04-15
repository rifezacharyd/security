#!/usr/bin/env bash
# ===========================================================================
# zdr-honeypot-feed — VPS bootstrap
# ===========================================================================
#
# One-shot installer for a fresh Debian 12 / Ubuntu 24.04 host. Sets up:
#
#   1. Docker + UFW
#   2. T-Pot honeypot (user-type install) — provides cowrie, dionaea, et al.
#   3. MaxMind geoipupdate with weekly cron refresh of GeoLite2-City.mmdb
#   4. The zdr-honeypot-feed service (this project) via docker compose
#   5. A firewall allowing SSH, HTTP, HTTPS, and the honeypot ports
#
# Requirements before running:
#
#   - Fresh VPS with at least 4 GB RAM (T-Pot is hungry; 2 GB OOMs)
#   - Moved real SSH off port 22 BEFORE running (cowrie claims :22)
#   - MaxMind account — free signup at maxmind.com, generate a license key:
#       export GEOIP_ACCOUNT_ID=...
#       export GEOIP_LICENSE_KEY=...
#   - Optional: set FEED_KEY=... to pin a signing key. Otherwise one is
#     generated and printed at the end — save it, the site consumer needs it.
#
# Usage:
#
#   ssh root@vps
#   export GEOIP_ACCOUNT_ID=... GEOIP_LICENSE_KEY=...
#   curl -fsSL https://raw.githubusercontent.com/rifezacharyd/security/main/\
#        zdr-honeypot-feed/deploy/bootstrap.sh | bash
#
# See the project README for TLS proxy setup, site integration, and key
# rotation procedures.
# ===========================================================================

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi

FEED_KEY="${FEED_KEY:-$(openssl rand -hex 32)}"
GEOIP_ACCOUNT_ID="${GEOIP_ACCOUNT_ID:?set MaxMind account id}"
GEOIP_LICENSE_KEY="${GEOIP_LICENSE_KEY:?set MaxMind license key}"

apt-get update
apt-get install -y \
  ca-certificates curl git gnupg ufw \
  docker.io docker-compose-v2

systemctl enable --now docker

# ---- T-Pot ----
if [[ ! -d /opt/tpotce ]]; then
  git clone https://github.com/telekom-security/tpotce /opt/tpotce
  cd /opt/tpotce
  ./install.sh --type=user
fi

# ---- MaxMind geoipupdate ----
mkdir -p /data/geoip
cat >/etc/GeoIP.conf <<EOF
AccountID ${GEOIP_ACCOUNT_ID}
LicenseKey ${GEOIP_LICENSE_KEY}
EditionIDs GeoLite2-City
DatabaseDirectory /data/geoip
EOF

docker pull ghcr.io/maxmind/geoipupdate:latest
docker run --rm -v /data/geoip:/data -v /etc/GeoIP.conf:/etc/GeoIP.conf:ro \
  ghcr.io/maxmind/geoipupdate:latest

# Weekly refresh via cron.
cat >/etc/cron.d/geoipupdate <<'EOF'
0 4 * * 0 root docker run --rm -v /data/geoip:/data -v /etc/GeoIP.conf:/etc/GeoIP.conf:ro ghcr.io/maxmind/geoipupdate:latest
EOF

# ---- Feed service ----
install -d -m 750 /opt/zdr
cd /opt/zdr
if [[ ! -d security/.git ]]; then
  git clone --depth 1 https://github.com/rifezacharyd/security.git
fi
cd security/zdr-honeypot-feed
cp .env.example .env
sed -i "s|^ZDR_FEED_SIGNING_KEY=.*|ZDR_FEED_SIGNING_KEY=${FEED_KEY}|" .env
docker compose build
docker compose up -d

# ---- Firewall ----
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
# T-Pot exposes honeypot-facing ports (22, 23, 2222, 8080 etc); let them through
ufw --force enable

echo
echo "Bootstrap complete."
echo "Feed key: ${FEED_KEY}"
echo "(save this — the site needs it to verify signatures)"
