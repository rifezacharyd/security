"""
OSINT Aggregator

Combines DNS enumeration, WHOIS lookup, and certificate transparency
search into a single structured reconnaissance report.

DISCLAIMER: Only use as part of authorized security assessments.
"""

import sys
import json
from datetime import datetime

from dns_resolver import enumerate_dns
from whois_lookup import lookup_domain
from cert_transparency import search_crtsh


def generate_report(domain: str, output_file: str | None = None) -> dict:
    """Run all passive recon modules and compile results."""
    report = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "modules": {},
    }

    # DNS enumeration
    print(f"\n{'=' * 60}")
    print("MODULE: DNS Enumeration")
    print("=" * 60)
    report["modules"]["dns"] = enumerate_dns(domain)

    # WHOIS lookup
    print(f"\n{'=' * 60}")
    print("MODULE: WHOIS Lookup")
    print("=" * 60)
    whois_data = lookup_domain(domain)
    # Convert non-serializable objects to strings
    serializable = {}
    for k, v in whois_data.items():
        if isinstance(v, list):
            serializable[k] = [str(i) for i in v]
        else:
            serializable[k] = str(v)
    report["modules"]["whois"] = serializable

    # Certificate transparency
    print(f"\n{'=' * 60}")
    print("MODULE: Certificate Transparency")
    print("=" * 60)
    report["modules"]["cert_transparency"] = search_crtsh(domain)

    # Summary
    dns_records = sum(len(v) for v in report["modules"]["dns"].values())
    subdomains = len(report["modules"]["cert_transparency"])

    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    print(f"  Target: {domain}")
    print(f"  DNS records found: {dns_records}")
    print(f"  Subdomains (cert transparency): {subdomains}")
    print(f"  WHOIS fields: {len(report['modules']['whois'])}")

    if output_file:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n[+] Report saved to {output_file}")

    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <domain> [output.json]")
        sys.exit(1)

    target = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else None
    generate_report(target, outfile)
