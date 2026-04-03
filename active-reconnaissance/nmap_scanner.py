"""
Nmap Scanner Integration

Wraps the Nmap port scanner via python-nmap for service version
detection, OS fingerprinting, and structured output parsing.

WARNING: Only use against systems you own or have explicit
written authorization to test. Unauthorized scanning is illegal.
"""

import sys
import nmap


def service_scan(target: str, ports: str = "1-1024", arguments: str = "-sV -T4") -> dict:
    """Run an Nmap service version scan and return structured results."""
    print(f"[*] Nmap service scan: {target}")
    print(f"[*] Ports: {ports}")
    print(f"[*] Arguments: {arguments}")
    print("=" * 50)

    scanner = nmap.PortScanner()

    try:
        scanner.scan(target, ports, arguments=arguments)
    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
        return {}

    results = {}

    for host in scanner.all_hosts():
        host_info = {
            "hostname": scanner[host].hostname(),
            "state": scanner[host].state(),
            "protocols": {},
        }

        print(f"\n[+] Host: {host} ({host_info['hostname']})")
        print(f"    State: {host_info['state']}")

        for proto in scanner[host].all_protocols():
            ports_data = {}
            port_list = sorted(scanner[host][proto].keys())

            print(f"\n    Protocol: {proto}")
            print(f"    {'Port':<8} {'State':<10} {'Service':<15} {'Version'}")
            print(f"    {'-'*8} {'-'*10} {'-'*15} {'-'*20}")

            for port in port_list:
                info = scanner[host][proto][port]
                state = info["state"]
                service = info["name"]
                version = info.get("version", "")
                product = info.get("product", "")
                extra = info.get("extrainfo", "")

                version_str = f"{product} {version} {extra}".strip()
                print(f"    {port:<8} {state:<10} {service:<15} {version_str}")

                ports_data[port] = {
                    "state": state,
                    "service": service,
                    "version": version_str,
                }

            host_info["protocols"][proto] = ports_data

        results[host] = host_info

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [ports] [nmap-args]")
        print(f"  Example: {sys.argv[0]} 192.168.1.0/24 1-1024 '-sV -T4'")
        sys.exit(1)

    target = sys.argv[1]
    ports = sys.argv[2] if len(sys.argv) > 2 else "1-1024"
    args = sys.argv[3] if len(sys.argv) > 3 else "-sV -T4"

    service_scan(target, ports, args)
