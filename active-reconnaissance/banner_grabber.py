"""
Service Banner Grabber

Connects to open ports and attempts to retrieve service banners.
Banners reveal software versions which map to known vulnerabilities.

WARNING: Only use against systems you own or have explicit
written authorization to test. Unauthorized scanning is illegal.
"""

import sys
import socket


# Protocol-specific probes for common services
PROBES = {
    "http": b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    "smtp": None,  # SMTP sends banner on connect
    "ftp": None,   # FTP sends banner on connect
    "ssh": None,   # SSH sends banner on connect
    "pop3": None,  # POP3 sends banner on connect
    "imap": None,  # IMAP sends banner on connect
}

# Common port-to-protocol mapping
PORT_PROTOCOLS = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "http",
    8080: "http",
    8443: "http",
}


def grab_banner(host: str, port: int, timeout: float = 5.0) -> str | None:
    """Connect to a port and attempt to retrieve its service banner."""
    protocol = PORT_PROTOCOLS.get(port, "unknown")
    probe = PROBES.get(protocol)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            if probe:
                # Replace target placeholder in HTTP probe
                if protocol == "http":
                    probe = probe.replace(b"target", host.encode())
                sock.send(probe)

            banner = sock.recv(4096).decode(errors="replace").strip()
            return banner if banner else None
    except (socket.error, ConnectionRefusedError):
        return None


def grab_banners(host: str, ports: list[int]) -> dict[int, str]:
    """Grab banners from multiple ports on a host."""
    print(f"[*] Banner grabbing on {host}")
    print(f"[*] Ports: {', '.join(str(p) for p in ports)}")
    print("=" * 60)

    results = {}
    for port in ports:
        protocol = PORT_PROTOCOLS.get(port, "unknown")
        banner = grab_banner(host, port)
        if banner:
            # Truncate long banners for display
            display = banner[:200].replace("\n", " | ")
            print(f"\n  [+] {port}/{protocol}:")
            print(f"      {display}")
            results[port] = banner
        else:
            print(f"  [-] {port}/{protocol}: No banner")

    print(f"\n[*] Banners collected: {len(results)}/{len(ports)}")
    return results


def parse_ports(port_str: str) -> list[int]:
    """Parse comma-separated port list like '22,80,443'."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <host> <ports>")
        print(f"  Example: {sys.argv[0]} 192.168.1.100 22,80,443")
        sys.exit(1)

    target = sys.argv[1]
    port_list = parse_ports(sys.argv[2])
    grab_banners(target, port_list)
