"""
DNS Record Enumeration

Queries multiple DNS record types for a target domain using dnspython.
Reveals subdomains, mail servers, name servers, and configuration details.

DISCLAIMER: Only use as part of authorized security assessments.
"""

import sys
import dns.resolver


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def resolve_records(domain: str, record_type: str) -> list[str]:
    """Query DNS for a specific record type."""
    results = []
    try:
        answers = dns.resolver.resolve(domain, record_type)
        for rdata in answers:
            results.append(str(rdata))
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.resolver.NoNameservers:
        print(f"  [!] No nameservers available for {record_type}")
    except Exception as e:
        print(f"  [!] Error querying {record_type}: {e}")
    return results


def enumerate_dns(domain: str) -> dict[str, list[str]]:
    """Enumerate all common DNS record types for a domain."""
    print(f"[*] DNS enumeration for {domain}")
    print("=" * 50)

    all_records = {}
    for rtype in RECORD_TYPES:
        records = resolve_records(domain, rtype)
        if records:
            all_records[rtype] = records
            print(f"\n  [{rtype}]")
            for record in records:
                print(f"    {record}")

    if not all_records:
        print("[-] No DNS records found")

    return all_records


def reverse_lookup(ip: str) -> str | None:
    """Perform a reverse DNS lookup on an IP address."""
    try:
        from dns.reversename import from_address
        rev_name = from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        for rdata in answers:
            hostname = str(rdata)
            print(f"[+] {ip} -> {hostname}")
            return hostname
    except Exception:
        print(f"[-] No reverse DNS for {ip}")
        return None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <domain>")
        sys.exit(1)

    target = sys.argv[1]
    records = enumerate_dns(target)

    # Attempt reverse lookup on any A records found
    if "A" in records:
        print(f"\n[*] Reverse lookups")
        print("-" * 50)
        for ip in records["A"]:
            reverse_lookup(ip)
