"""
HTTP Requests for Security Work

Demonstrates using the requests library for web interaction,
header analysis, and response inspection — common tasks in
web application security testing.

DISCLAIMER: Only use against systems you own or have authorization to test.
"""

import requests


def get_headers(url: str) -> dict:
    """Fetch and display HTTP response headers for security analysis."""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        print(f"[+] {url}")
        print(f"    Status: {response.status_code}")
        print(f"    Final URL: {response.url}")
        print(f"    Headers:")

        security_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
        ]

        for header in security_headers:
            value = response.headers.get(header, "MISSING")
            status = "[+]" if value != "MISSING" else "[-]"
            print(f"      {status} {header}: {value}")

        return dict(response.headers)
    except requests.RequestException as e:
        print(f"[!] Error fetching {url}: {e}")
        return {}


def check_robots_txt(base_url: str) -> list[str]:
    """Check for and parse robots.txt entries."""
    url = f"{base_url.rstrip('/')}/robots.txt"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            print(f"[+] robots.txt found at {url}")
            disallowed = []
            for line in response.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
                        print(f"    Disallow: {path}")
            return disallowed
        else:
            print(f"[-] No robots.txt at {url} (status {response.status_code})")
            return []
    except requests.RequestException as e:
        print(f"[!] Error: {e}")
        return []


if __name__ == "__main__":
    target = "https://example.com"
    print("=" * 60)
    print("Security Header Analysis")
    print("=" * 60)
    get_headers(target)

    print(f"\n{'=' * 60}")
    print("Robots.txt Check")
    print("=" * 60)
    check_robots_txt(target)
