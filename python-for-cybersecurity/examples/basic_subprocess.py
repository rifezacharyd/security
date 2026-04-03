"""
Subprocess Integration for Security Work

Demonstrates using Python's subprocess module to wrap and
automate external security tools. This pattern is used to
build orchestration scripts that combine multiple tools.

DISCLAIMER: Only use against systems you own or have authorization to test.
"""

import subprocess
import shutil
import platform


def run_command(cmd: list[str], timeout: int = 30) -> str | None:
    """Run a shell command and return its output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"[-] Command failed: {' '.join(cmd)}")
            print(f"    stderr: {result.stderr.strip()}")
            return None
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out: {' '.join(cmd)}")
        return None
    except FileNotFoundError:
        print(f"[!] Command not found: {cmd[0]}")
        return None


def check_tool_availability(tools: list[str]) -> dict[str, bool]:
    """Check which security tools are installed on the system."""
    results = {}
    for tool in tools:
        available = shutil.which(tool) is not None
        status = "[+]" if available else "[-]"
        print(f"  {status} {tool}")
        results[tool] = available
    return results


def get_system_info() -> dict[str, str]:
    """Gather basic system information for environment documentation."""
    info = {
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
    }
    for key, value in info.items():
        print(f"  {key}: {value}")
    return info


def ping_host(host: str, count: int = 3) -> bool:
    """Ping a host to check if it's reachable."""
    flag = "-c" if platform.system() != "Windows" else "-n"
    cmd = ["ping", flag, str(count), host]

    print(f"[*] Pinging {host}...")
    output = run_command(cmd, timeout=15)
    if output:
        print(output)
        return True
    return False


if __name__ == "__main__":
    print("=" * 60)
    print("System Information")
    print("=" * 60)
    get_system_info()

    print(f"\n{'=' * 60}")
    print("Security Tool Availability")
    print("=" * 60)
    common_tools = ["nmap", "nikto", "gobuster", "hydra", "curl", "wget", "git", "python3"]
    check_tool_availability(common_tools)

    print(f"\n{'=' * 60}")
    print("Connectivity Check")
    print("=" * 60)
    ping_host("8.8.8.8")
