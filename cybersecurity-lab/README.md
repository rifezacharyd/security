# Building an Advanced Cybersecurity Lab

Tools and configurations for building a professional cybersecurity development and testing environment. Covers virtualization management, network topology design, and reproducible lab configurations.

## Prerequisites

- VirtualBox installed (`brew install --cask virtualbox` or from virtualbox.org)
- Python 3.10+
- PyYAML (`pip install pyyaml`)

## Project Structure

```
cybersecurity-lab/
├── lab_manager.py       # VirtualBox VM management wrapper
├── network_topology.py  # Lab network design and visualization
├── setup_targets.sh     # Guide for setting up vulnerable VMs
├── lab_config.yaml      # Lab environment configuration
└── README.md
```

## Usage

```bash
# View lab network topology
python network_topology.py

# Manage VM snapshots
python lab_manager.py list
python lab_manager.py snapshot kali-linux "clean-state"
python lab_manager.py restore kali-linux "clean-state"

# Set up vulnerable targets (read the script first)
cat setup_targets.sh
```

## Lab Network Design

```
[Attacker: 10.0.1.0/24]  ──┐
[Targets:  10.0.2.0/24]  ──┼── Isolated lab network
[Monitor:  10.0.3.0/24]  ──┘
```

## Important

Your lab should be completely isolated from production networks and the public internet. Use host-only or internal networking in VirtualBox.

---

*Part of a cybersecurity portfolio. See the accompanying blog post for conceptual background.*
