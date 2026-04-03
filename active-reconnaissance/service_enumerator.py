"""
Service Enumerator

Combines port scanning and banner grabbing into a single enumeration
pipeline. Discovers open ports, grabs banners, and produces a report.

WARNING: Only use against systems you own or have explicit
written authorization to test. Unauthorized scanning is illegal.
"""

import sys
import json
from datetime import datetime

from port_scanner import scan_range
from banner_grabber import grab_banners


def enumerate_services(host: str, port_range: str = "1-1024", output_file: str | None = None) -> dict:
    """Full service enumeration: scan ports, grab banners, generate report."""
    print(f"\n{'=' * 60}")
    print(f"  SERVICE ENUMERATION: {host}")
    print(f"  Port range: {port_range}")
    print(f"  Time: {datetime.now().isoformat()}")
    print(f"{'=' * 60}")

    # Phase 1: Port scan
    print(f"\n--- Phase 1: Port Scanning ---")
    if "-" in port_range:
        start, end = port_range.split("-", 1)
        start, end = int(start), int(end)
    else:
        start = end = int(port_range)

    open_ports = scan_range(host, start, end)

    if not open_ports:
        print("\n[*] No open ports found. Enumeration complete.")
        return {"host": host, "open_ports": [], "services": {}}

    # Phase 2: Banner grabbing
    print(f"\n--- Phase 2: Banner Grabbing ---")
    banners = grab_banners(host, open_ports)

    # Compile report
    report = {
        "host": host,
        "scan_time": datetime.now().isoformat(),
        "port_range": port_range,
        "open_ports": open_ports,
        "services": {
            str(port): {
                "port": port,
                "banner": banners.get(port, "No banner"),
            }
            for port in open_ports
        },
    }

    # Summary
    print(f"\n{'=' * 60}")
    print("ENUMERATION SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Host: {host}")
    print(f"  Open ports: {len(open_ports)}")
    print(f"  Banners collected: {len(banners)}")
    for port in open_ports:
        banner_preview = banners.get(port, "N/A")
        if banner_preview and banner_preview != "N/A":
            banner_preview = banner_preview[:60].replace("\n", " ")
        print(f"  {port:>5} | {banner_preview}")

    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] Report saved to {output_file}")

    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port-range] [output.json]")
        print(f"  Example: {sys.argv[0]} 192.168.1.100 1-1024 report.json")
        sys.exit(1)

    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else "1-1024"
    outfile = sys.argv[3] if len(sys.argv) > 3 else None

    enumerate_services(target, ports, outfile)
