# Active Reconnaissance and Target Analysis

Python tools for active reconnaissance in authorized security assessments. Covers port scanning, service enumeration, banner grabbing, and Nmap integration.

## Prerequisites

- Python 3.10+
- Nmap installed on the system (`brew install nmap` or `apt install nmap`)
- An isolated lab network with authorized targets

## Setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Tools

| Script | Purpose |
|--------|---------|
| `port_scanner.py` | TCP connect scanner using raw sockets |
| `nmap_scanner.py` | Nmap integration via python-nmap |
| `banner_grabber.py` | Service banner collection from open ports |
| `service_enumerator.py` | Combined scan + enumerate pipeline |

## Usage

```bash
# Scan a lab target
python port_scanner.py 192.168.1.100 1-1024

# Nmap service version detection
python nmap_scanner.py 192.168.1.0/24

# Grab banners from discovered services
python banner_grabber.py 192.168.1.100 22,80,443

# Full enumeration pipeline
python service_enumerator.py 192.168.1.100
```

## WARNING

These tools perform active network scanning that generates traffic and logs on target systems. **Only use against systems you own or have explicit written authorization to test.** Unauthorized scanning is illegal in most jurisdictions.

---

*Part of a cybersecurity portfolio. See the accompanying blog post for conceptual background.*
