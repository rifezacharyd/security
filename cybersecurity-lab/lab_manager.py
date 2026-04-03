"""
Lab Manager - VirtualBox VM Management

Python wrapper around VBoxManage for managing cybersecurity lab
virtual machines, snapshots, and network configurations.

Requires VirtualBox to be installed with VBoxManage in PATH.
"""

import sys
import subprocess
import yaml
from pathlib import Path


CONFIG_FILE = Path(__file__).parent / "lab_config.yaml"


def run_vbox(args: list[str]) -> tuple[bool, str]:
    """Execute a VBoxManage command and return success status and output."""
    cmd = ["VBoxManage"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            return False, result.stderr.strip()
    except FileNotFoundError:
        return False, "VBoxManage not found. Is VirtualBox installed?"
    except subprocess.TimeoutExpired:
        return False, "Command timed out"


def load_config() -> dict:
    """Load lab configuration from YAML."""
    if not CONFIG_FILE.exists():
        print(f"[!] Config not found: {CONFIG_FILE}")
        sys.exit(1)
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)


def list_vms():
    """List all VirtualBox VMs and their states."""
    print("[*] Registered VMs:")
    print("=" * 50)
    success, output = run_vbox(["list", "vms"])
    if success:
        if output:
            print(output)
        else:
            print("  (no VMs registered)")
    else:
        print(f"  [!] {output}")

    print("\n[*] Running VMs:")
    print("-" * 50)
    success, output = run_vbox(["list", "runningvms"])
    if success:
        if output:
            print(output)
        else:
            print("  (none running)")
    else:
        print(f"  [!] {output}")


def list_snapshots(vm_name: str):
    """List all snapshots for a VM."""
    print(f"[*] Snapshots for '{vm_name}':")
    success, output = run_vbox(["snapshot", vm_name, "list"])
    if success:
        print(output)
    else:
        if "does not have" in output:
            print("  (no snapshots)")
        else:
            print(f"  [!] {output}")


def create_snapshot(vm_name: str, snapshot_name: str, description: str = ""):
    """Create a snapshot of a VM."""
    print(f"[*] Creating snapshot '{snapshot_name}' for '{vm_name}'...")
    args = ["snapshot", vm_name, "take", snapshot_name]
    if description:
        args += ["--description", description]
    success, output = run_vbox(args)
    if success:
        print(f"[+] Snapshot created: {snapshot_name}")
    else:
        print(f"[!] Failed: {output}")


def restore_snapshot(vm_name: str, snapshot_name: str):
    """Restore a VM to a previous snapshot."""
    print(f"[*] Restoring '{vm_name}' to snapshot '{snapshot_name}'...")
    success, output = run_vbox(["snapshot", vm_name, "restore", snapshot_name])
    if success:
        print(f"[+] Restored to '{snapshot_name}'")
    else:
        print(f"[!] Failed: {output}")


def delete_snapshot(vm_name: str, snapshot_name: str):
    """Delete a snapshot from a VM."""
    print(f"[*] Deleting snapshot '{snapshot_name}' from '{vm_name}'...")
    success, output = run_vbox(["snapshot", vm_name, "delete", snapshot_name])
    if success:
        print(f"[+] Snapshot deleted")
    else:
        print(f"[!] Failed: {output}")


def start_vm(vm_name: str, headless: bool = False):
    """Start a VM."""
    mode = "headless" if headless else "gui"
    print(f"[*] Starting '{vm_name}' ({mode})...")
    success, output = run_vbox(["startvm", vm_name, "--type", mode])
    if success:
        print(f"[+] VM started")
    else:
        print(f"[!] Failed: {output}")


def stop_vm(vm_name: str, force: bool = False):
    """Stop a VM gracefully or forcefully."""
    method = "poweroff" if force else "acpipowerbutton"
    print(f"[*] Stopping '{vm_name}' ({method})...")
    success, output = run_vbox(["controlvm", vm_name, method])
    if success:
        print(f"[+] VM stop signal sent")
    else:
        print(f"[!] Failed: {output}")


def show_config():
    """Display the lab configuration."""
    config = load_config()
    print("[*] Lab Configuration")
    print("=" * 50)

    print("\nNetworks:")
    for name, net in config["networks"].items():
        print(f"  {name}: {net['subnet']} ({net['name']})")

    print("\nVirtual Machines:")
    for name, vm in config["virtual_machines"].items():
        print(f"\n  {name}:")
        print(f"    IP: {vm['ip']}")
        print(f"    RAM: {vm['memory_mb']}MB | CPUs: {vm['cpus']} | Disk: {vm['disk_gb']}GB")
        print(f"    Network: {vm['network']}")
        print(f"    Description: {vm['description']}")


COMMANDS = {
    "list": ("List all VMs", list_vms),
    "snapshots": ("List snapshots for a VM", None),
    "snapshot": ("Create a snapshot", None),
    "restore": ("Restore a snapshot", None),
    "delete-snapshot": ("Delete a snapshot", None),
    "start": ("Start a VM", None),
    "stop": ("Stop a VM", None),
    "config": ("Show lab configuration", show_config),
}


def print_usage():
    print(f"Usage: {sys.argv[0]} <command> [args]")
    print("\nCommands:")
    for cmd, (desc, _) in COMMANDS.items():
        print(f"  {cmd:<20} {desc}")
    print(f"\nExamples:")
    print(f"  {sys.argv[0]} list")
    print(f"  {sys.argv[0]} config")
    print(f"  {sys.argv[0]} snapshots kali-linux")
    print(f"  {sys.argv[0]} snapshot kali-linux clean-state")
    print(f"  {sys.argv[0]} restore kali-linux clean-state")
    print(f"  {sys.argv[0]} start kali-linux")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    command = sys.argv[1]

    if command == "list":
        list_vms()
    elif command == "config":
        show_config()
    elif command == "snapshots" and len(sys.argv) >= 3:
        list_snapshots(sys.argv[2])
    elif command == "snapshot" and len(sys.argv) >= 4:
        desc = sys.argv[4] if len(sys.argv) > 4 else ""
        create_snapshot(sys.argv[2], sys.argv[3], desc)
    elif command == "restore" and len(sys.argv) >= 4:
        restore_snapshot(sys.argv[2], sys.argv[3])
    elif command == "delete-snapshot" and len(sys.argv) >= 4:
        delete_snapshot(sys.argv[2], sys.argv[3])
    elif command == "start" and len(sys.argv) >= 3:
        headless = "--headless" in sys.argv
        start_vm(sys.argv[2], headless)
    elif command == "stop" and len(sys.argv) >= 3:
        force = "--force" in sys.argv
        stop_vm(sys.argv[2], force)
    else:
        print_usage()
