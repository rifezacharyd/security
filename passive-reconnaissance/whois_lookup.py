"""
WHOIS Domain Lookup

Queries WHOIS registration data for a domain including registrar,
creation date, expiration, and name servers.

DISCLAIMER: Only use as part of authorized security assessments.
"""

import sys
import whois


def lookup_domain(domain: str) -> dict:
    """Perform a WHOIS lookup and return key registration details."""
    print(f"[*] WHOIS lookup for {domain}")
    print("=" * 50)

    try:
        w = whois.whois(domain)
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
        return {}

    fields = {
        "Domain": w.domain_name,
        "Registrar": w.registrar,
        "Creation Date": w.creation_date,
        "Expiration Date": w.expiration_date,
        "Updated Date": w.updated_date,
        "Name Servers": w.name_servers,
        "Status": w.status,
        "Org": w.org,
        "Country": w.country,
        "State": w.state,
    }

    results = {}
    for label, value in fields.items():
        if value:
            # Handle lists
            if isinstance(value, list):
                display = ", ".join(str(v) for v in value[:5])
                if len(value) > 5:
                    display += f" (+{len(value) - 5} more)"
            else:
                display = str(value)
            print(f"  {label}: {display}")
            results[label] = value

    if not results:
        print("[-] No WHOIS data returned")

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)

    lookup_domain(sys.argv[1])
