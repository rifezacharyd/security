"""
TCP Connect Port Scanner

A basic port scanner using Python sockets. Performs full TCP
three-way handshake to determine if ports are open. Reliable
but generates connection logs on the target.

WARNING: Only use against systems you own or have explicit
written authorization to test. Unauthorized scanning is illegal.
"""

import sys
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(host: str, port: int, timeout: float = 2.0) -> tuple[int, bool]:
    """Attempt a TCP connection to a single port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return (port, result == 0)
    except socket.error:
        return (port, False)


def scan_range(host: str, start: int, end: int, threads: int = 50) -> list[int]:
    """Scan a range of ports using thread pool for speed."""
    print(f"[*] Scanning {host} ports {start}-{end}")
    print(f"[*] Using {threads} threads")
    print("-" * 40)

    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port): port
            for port in range(start, end + 1)
        }
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                print(f"  [+] Port {port} is OPEN")

    open_ports.sort()
    print(f"\n[*] Scan complete. {len(open_ports)} open port(s) found.")
    return open_ports


def parse_port_range(port_str: str) -> tuple[int, int]:
    """Parse a port range string like '1-1024' or '80'."""
    if "-" in port_str:
        start, end = port_str.split("-", 1)
        return int(start), int(end)
    else:
        port = int(port_str)
        return port, port


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host> [port-range]")
        print(f"  Example: {sys.argv[0]} 192.168.1.100 1-1024")
        sys.exit(1)

    target = sys.argv[1]
    port_range = sys.argv[2] if len(sys.argv) > 2 else "1-1024"

    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve {target}")
        sys.exit(1)

    start_port, end_port = parse_port_range(port_range)
    scan_range(ip, start_port, end_port)
