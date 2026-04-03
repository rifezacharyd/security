"""
Certificate Transparency Log Search

Queries crt.sh to discover subdomains from publicly logged
SSL/TLS certificates. This is a purely passive technique since
certificate transparency logs are public records.

DISCLAIMER: Only use as part of authorized security assessments.
"""

import sys
import requests


def search_crtsh(domain: str) -> list[str]:
    """Query crt.sh for certificates matching a domain."""
    print(f"[*] Certificate transparency search for {domain}")
    print("=" * 50)

    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}

    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Error querying crt.sh: {e}")
        return []

    try:
        data = response.json()
    except ValueError:
        print("[-] Invalid response from crt.sh")
        return []

    # Extract unique domain names from certificate common names
    subdomains = set()
    for entry in data:
        name_value = entry.get("name_value", "")
        for name in name_value.split("\n"):
            name = name.strip().lower()
            if name and "*" not in name:
                subdomains.add(name)

    sorted_subs = sorted(subdomains)
    print(f"[+] Found {len(sorted_subs)} unique subdomains:\n")
    for sub in sorted_subs:
        print(f"  {sub}")

    return sorted_subs


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)

    search_crtsh(sys.argv[1])
