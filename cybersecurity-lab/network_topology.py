"""
Lab Network Topology

Defines and visualizes the cybersecurity lab network layout.
Generates an ASCII diagram of the network segmentation design.
"""

import yaml
from pathlib import Path

CONFIG_FILE = Path(__file__).parent / "lab_config.yaml"


LAB_TOPOLOGY = """
╔══════════════════════════════════════════════════════════════╗
║                  CYBERSECURITY LAB TOPOLOGY                  ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║   ┌─────────────────────────────────────────────────────┐   ║
║   │              HOST MACHINE (Hypervisor)               │   ║
║   │              VirtualBox / VMware / Proxmox           │   ║
║   └─────┬──────────────┬──────────────┬─────────────────┘   ║
║         │              │              │                       ║
║   ┌─────┴─────┐  ┌─────┴─────┐  ┌────┴──────┐              ║
║   │ lab-atk   │  │ lab-tgt   │  │ lab-mon   │              ║
║   │ (intnet)  │  │ (intnet)  │  │ (intnet)  │              ║
║   └─────┬─────┘  └─────┬─────┘  └────┬──────┘              ║
║         │              │              │                       ║
║  ╔══════╧══════╗ ╔═════╧═══════════╗ ╔╧═══════════════╗     ║
║  ║  ATTACKER   ║ ║    TARGETS      ║ ║  MONITORING    ║     ║
║  ║ 10.0.1.0/24 ║ ║  10.0.2.0/24   ║ ║ 10.0.3.0/24   ║     ║
║  ╠═════════════╣ ╠═════════════════╣ ╠════════════════╣     ║
║  ║             ║ ║                 ║ ║                ║     ║
║  ║ Kali Linux  ║ ║ Metasploitable  ║ ║ Security Onion ║     ║
║  ║ 10.0.1.10   ║ ║ 10.0.2.10      ║ ║ 10.0.3.10     ║     ║
║  ║             ║ ║                 ║ ║                ║     ║
║  ║             ║ ║ DVWA            ║ ║ ELK Stack      ║     ║
║  ║             ║ ║ 10.0.2.20      ║ ║ (integrated)   ║     ║
║  ║             ║ ║                 ║ ║                ║     ║
║  ║             ║ ║ VulnHub VMs    ║ ║                ║     ║
║  ║             ║ ║ 10.0.2.30+     ║ ║                ║     ║
║  ╚═════════════╝ ╚═════════════════╝ ╚════════════════╝     ║
║                                                              ║
║  NOTE: All networks are host-only / internal only.           ║
║  No traffic reaches the internet from lab VMs.               ║
╚══════════════════════════════════════════════════════════════╝
"""


def display_topology():
    """Display the lab network topology diagram."""
    print(LAB_TOPOLOGY)


def display_config_summary():
    """Load config and display VM/network summary."""
    if not CONFIG_FILE.exists():
        print("[!] lab_config.yaml not found")
        return

    with open(CONFIG_FILE) as f:
        config = yaml.safe_load(f)

    print("\nNetwork Segments:")
    print("-" * 40)
    for name, net in config["networks"].items():
        print(f"  {name:<12} {net['subnet']:<18} ({net['name']})")

    print("\nVirtual Machines:")
    print("-" * 40)
    for name, vm in config["virtual_machines"].items():
        print(f"  {name:<20} {vm['ip']:<16} {vm['memory_mb']}MB RAM  {vm['description']}")


if __name__ == "__main__":
    display_topology()
    display_config_summary()
