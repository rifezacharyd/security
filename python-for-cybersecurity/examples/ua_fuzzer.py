"""
User-Agent Fuzzer

Sends HTTP requests with mutated, malformed, and edge-case User-Agent
strings to test how a target web server handles unexpected input.
Useful for identifying WAF behavior, input validation gaps, and
error-handling differences across User-Agent values.

DISCLAIMER: Only use against systems you own or have authorization to test.
"""

import argparse
import random
import string
import time
import requests


# ── Payload Categories ───────────────────────────────────────────

KNOWN_BOTS = [
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.htm)",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "Slurp; (http://help.yahoo.com/help/us/ysearch/slurp)",
]

LEGACY_BROWSERS = [
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
    "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.5) Gecko/20041107 Firefox/1.0",
    "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.9.168 Version/11.50",
]

INJECTION_PAYLOADS = [
    "<script>alert('xss')</script>",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "${7*7}",
    "{{7*7}}",
    "../../../etc/passwd",
    "%00",
    "%0d%0aInjected-Header: true",
    "() { :; }; echo vulnerable",          # Shellshock pattern
    "; cat /etc/passwd",
    "| ls -la",
    "${jndi:ldap://127.0.0.1/test}",       # Log4Shell pattern
]

OVERFLOW_PAYLOADS = [
    "A" * 256,
    "A" * 1024,
    "A" * 4096,
    "A" * 8192,
    "A" * 65536,
]

ENCODING_PAYLOADS = [
    "\x00\x01\x02\x03\x04\x05",           # Null bytes and control chars
    "\\u0000\\u0001\\u0002",               # Unicode escapes
    "\r\n\r\n",                            # CRLF
    "\xff\xfe",                            # BOM markers
    "café☕🔥💀",                          # Mixed unicode and emoji
    "%E2%80%8B",                           # Zero-width space (URL encoded)
    "\t\t\t\n\n\n",                        # Whitespace chaos
]

EDGE_CASES = [
    "",                                    # Empty string
    " ",                                   # Single space
    "-",                                   # Minimal
    "a",                                   # Single char
    "Mozilla/5.0",                         # Truncated standard UA
    "curl/7.68.0",                         # CLI tool
    "python-requests/2.31.0",             # This library's default
    "Wget/1.21",                           # Wget
    "*",                                   # Wildcard
    "null",                                # Literal null
    "undefined",                           # Literal undefined
    "true",                                # Boolean-like
    "0",                                   # Falsy
    "-1",                                  # Negative
]


# ── Mutation Engine ──────────────────────────────────────────────

def mutate_ua(base_ua: str) -> str:
    """Apply a random mutation to a base User-Agent string."""
    mutations = [
        lambda s: s[::-1],                             # Reverse
        lambda s: s.upper(),                           # All caps
        lambda s: s.lower(),                           # All lower
        lambda s: s.replace("/", "\\"),                # Slash swap
        lambda s: s.replace(" ", "%20"),               # URL-encode spaces
        lambda s: s + "\x00" + "hidden",              # Null byte injection
        lambda s: "".join(random.sample(s, len(s))),   # Shuffle
        lambda s: s * 3,                               # Triple repeat
        lambda s: f"<!--{s}-->",                       # HTML comment wrap
    ]
    return random.choice(mutations)(base_ua)


def generate_random_ua(length: int = 64) -> str:
    """Generate a completely random User-Agent string."""
    charset = string.ascii_letters + string.digits + string.punctuation + " "
    return "".join(random.choices(charset, k=length))


# ── Fuzzer Core ──────────────────────────────────────────────────

def build_payload_list(include_mutations: bool = True) -> list[dict]:
    """Assemble the full fuzzing payload list with metadata."""
    payloads = []

    categories = [
        ("known_bot", KNOWN_BOTS),
        ("legacy_browser", LEGACY_BROWSERS),
        ("injection", INJECTION_PAYLOADS),
        ("overflow", OVERFLOW_PAYLOADS),
        ("encoding", ENCODING_PAYLOADS),
        ("edge_case", EDGE_CASES),
    ]

    for category, items in categories:
        for ua in items:
            payloads.append({"ua": ua, "category": category, "mutated": False})

    if include_mutations:
        base_strings = KNOWN_BOTS + LEGACY_BROWSERS
        for base in base_strings:
            for _ in range(3):
                payloads.append({
                    "ua": mutate_ua(base),
                    "category": "mutation",
                    "mutated": True,
                })

    for _ in range(10):
        length = random.choice([16, 64, 256, 1024])
        payloads.append({
            "ua": generate_random_ua(length),
            "category": "random",
            "mutated": False,
        })

    return payloads


def fuzz(target: str, delay: float = 0.5, verbose: bool = False,
         include_mutations: bool = True) -> list[dict]:
    """
    Send each User-Agent payload to the target and record responses.

    Returns a list of result dicts with status codes, response sizes,
    and any anomalies detected.
    """
    payloads = build_payload_list(include_mutations)
    results = []
    total = len(payloads)
    anomalies = 0

    print(f"[*] Target: {target}")
    print(f"[*] Payloads: {total}")
    print(f"[*] Delay: {delay}s between requests")
    print("=" * 70)

    # Baseline request with a normal User-Agent
    baseline_ua = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    try:
        baseline = requests.get(
            target,
            headers={"User-Agent": baseline_ua},
            timeout=10,
            allow_redirects=True,
        )
        baseline_status = baseline.status_code
        baseline_size = len(baseline.content)
        print(f"[*] Baseline: status={baseline_status} size={baseline_size}")
        print("=" * 70)
    except requests.RequestException as e:
        print(f"[!] Baseline request failed: {e}")
        print("[!] Aborting — target may be unreachable.")
        return results

    for i, payload in enumerate(payloads, 1):
        ua = payload["ua"]
        display_ua = ua[:80] + "..." if len(ua) > 80 else ua
        display_ua = repr(display_ua)

        try:
            response = requests.get(
                target,
                headers={"User-Agent": ua},
                timeout=10,
                allow_redirects=True,
            )

            status = response.status_code
            size = len(response.content)
            size_diff = abs(size - baseline_size)

            # Flag anomalies: status differs, large size change, or blocked
            is_anomaly = (
                status != baseline_status
                or size_diff > baseline_size * 0.2
                or status in (403, 406, 429, 503)
            )

            result = {
                "index": i,
                "category": payload["category"],
                "ua": ua,
                "mutated": payload["mutated"],
                "status": status,
                "size": size,
                "size_diff": size_diff,
                "anomaly": is_anomaly,
                "error": None,
            }

            marker = ">>>" if is_anomaly else "   "
            if is_anomaly:
                anomalies += 1

            if verbose or is_anomaly:
                print(
                    f"{marker} [{i:03d}/{total}] "
                    f"[{payload['category']:15s}] "
                    f"status={status} size={size:>7d} "
                    f"diff={size_diff:>+7d}  "
                    f"UA={display_ua}"
                )
            else:
                print(f"    [{i:03d}/{total}] [{payload['category']:15s}] status={status}", end="\r")

        except requests.RequestException as e:
            result = {
                "index": i,
                "category": payload["category"],
                "ua": ua,
                "mutated": payload["mutated"],
                "status": None,
                "size": None,
                "size_diff": None,
                "anomaly": True,
                "error": str(e),
            }
            anomalies += 1
            print(f">>> [{i:03d}/{total}] [{payload['category']:15s}] ERROR: {e}")

        results.append(result)
        time.sleep(delay)

    # ── Summary ──────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f"[*] Complete: {total} payloads sent, {anomalies} anomalies detected")
    print("=" * 70)

    if anomalies > 0:
        print("\n[*] Anomaly Summary:")
        print(f"    {'Category':<15s} {'Count':>5s}")
        print(f"    {'-' * 15} {'-' * 5}")

        category_counts = {}
        for r in results:
            if r["anomaly"]:
                cat = r["category"]
                category_counts[cat] = category_counts.get(cat, 0) + 1

        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            print(f"    {cat:<15s} {count:>5d}")

    return results


# ── CLI ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="User-Agent Fuzzer — test server behavior with mutated UA strings",
        epilog="Only use against systems you own or have authorization to test.",
    )
    parser.add_argument("target", help="Target URL to fuzz (e.g., https://example.com)")
    parser.add_argument("-d", "--delay", type=float, default=0.5,
                        help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show all responses, not just anomalies")
    parser.add_argument("--no-mutations", action="store_true",
                        help="Skip mutated User-Agent variants")

    args = parser.parse_args()
    fuzz(
        target=args.target,
        delay=args.delay,
        verbose=args.verbose,
        include_mutations=not args.no_mutations,
    )


if __name__ == "__main__":
    main()
