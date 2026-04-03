"""
Basic Socket Programming for Security Work

Demonstrates DNS resolution and TCP connection testing using
Python's built-in socket module. These are building blocks for
port scanners, banner grabbers, and custom network tools.

DISCLAIMER: Only use against systems you own or have authorization to test.
"""

import socket


def resolve_domain(domain: str) -> str | None:
    """Resolve a domain name to its IP address."""
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] {domain} -> {ip}")
        return ip
    except socket.gaierror:
        print(f"[-] Could not resolve {domain}")
        return None


def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if a TCP port is open on a given host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                print(f"[+] {host}:{port} is OPEN")
                return True
            else:
                print(f"[-] {host}:{port} is CLOSED")
                return False
    except socket.error as e:
        print(f"[!] Error connecting to {host}:{port} - {e}")
        return False


def get_banner(host: str, port: int, timeout: float = 3.0) -> str | None:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.send(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % host.encode())
            banner = sock.recv(1024).decode(errors="replace").strip()
            print(f"[+] Banner from {host}:{port}:\n{banner[:200]}")
            return banner
    except (socket.error, UnicodeDecodeError) as e:
        print(f"[-] No banner from {host}:{port} - {e}")
        return None


if __name__ == "__main__":
    # Example: resolve a public domain and check common ports
    target = "scanme.nmap.org"  # Nmap's authorized test target

    ip = resolve_domain(target)
    if ip:
        print(f"\n[*] Scanning common ports on {target} ({ip})...")
        for port in [22, 80, 443, 8080]:
            check_port(ip, port)
