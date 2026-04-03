# Passive Reconnaissance Fundamentals

Python tools for gathering intelligence through publicly available sources without directly interacting with target systems. Covers DNS analysis, WHOIS lookups, certificate transparency, and OSINT aggregation.

## Prerequisites

- Python 3.10+
- Virtual environment (see `requirements.txt`)

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Tools

| Script | Purpose |
|--------|---------|
| `dns_resolver.py` | DNS record enumeration (A, MX, NS, TXT, CNAME) |
| `whois_lookup.py` | Domain registration and ownership data |
| `cert_transparency.py` | Subdomain discovery via certificate transparency logs |
| `osint_aggregator.py` | Combines all sources into a structured report |

## Usage

```bash
python dns_resolver.py example.com
python whois_lookup.py example.com
python cert_transparency.py example.com
python osint_aggregator.py example.com
```

## Important

Passive reconnaissance should only be performed as part of an authorized security assessment or for educational purposes within your own lab environment.

---

*Part of a cybersecurity portfolio. See the accompanying blog post for conceptual background.*
