#!/usr/bin/env bash
set -euo pipefail

# =============================================================
# Cybersecurity Lab - Target VM Setup Guide
# =============================================================
# This script documents the steps to download and configure
# intentionally vulnerable VMs for your lab environment.
#
# READ THROUGH THIS SCRIPT before running. Adjust paths and
# network settings to match your environment.
# =============================================================

echo "============================================="
echo "  Cybersecurity Lab - Target Setup"
echo "============================================="

# --- Configuration ---
LAB_DIR="${HOME}/cybersecurity-lab"
ISO_DIR="${LAB_DIR}/isos"
VM_DIR="${LAB_DIR}/vms"

mkdir -p "$ISO_DIR" "$VM_DIR"

# --- 1. Kali Linux (Attacker VM) ---
echo ""
echo "[1] Kali Linux - Attack Platform"
echo "    Download from: https://www.kali.org/get-kali/#kali-virtual-machines"
echo "    Recommended: Pre-built VirtualBox image (.ova)"
echo ""
echo "    Import with:"
echo "    VBoxManage import kali-linux-*.ova --vsys 0 --vmname kali-linux"
echo "    VBoxManage modifyvm kali-linux --memory 4096 --cpus 2"
echo "    VBoxManage modifyvm kali-linux --nic1 intnet --intnet1 lab-attacker"

# --- 2. Metasploitable 2 (Vulnerable Linux) ---
echo ""
echo "[2] Metasploitable 2 - Vulnerable Linux Target"
echo "    Download from: https://sourceforge.net/projects/metasploitable/"
echo "    Extract the .vmdk and create a VM:"
echo ""
echo "    VBoxManage createvm --name metasploitable2 --ostype Ubuntu_64 --register"
echo "    VBoxManage modifyvm metasploitable2 --memory 1024 --cpus 1"
echo "    VBoxManage storagectl metasploitable2 --name SATA --add sata"
echo "    VBoxManage storageattach metasploitable2 --storagectl SATA --port 0 --type hdd --medium path/to/Metasploitable.vmdk"
echo "    VBoxManage modifyvm metasploitable2 --nic1 intnet --intnet1 lab-targets"

# --- 3. DVWA (Vulnerable Web App via Docker) ---
echo ""
echo "[3] DVWA - Damn Vulnerable Web Application"
echo "    Easiest to run via Docker on a lightweight Ubuntu VM:"
echo ""
echo "    # On target VM:"
echo "    docker run -d --name dvwa -p 80:80 vulnerables/web-dvwa"
echo "    # Access at http://10.0.2.20"
echo "    # Default login: admin / password"

# --- 4. Security Onion (Monitoring) ---
echo ""
echo "[4] Security Onion - Network Security Monitoring"
echo "    Download from: https://securityonionsolutions.com/"
echo "    Requires 8GB+ RAM and 200GB+ disk"
echo ""
echo "    Import the ISO and install following the official guide."
echo "    Configure to monitor lab-targets network traffic."

# --- 5. Create Snapshots ---
echo ""
echo "[5] Create baseline snapshots for all VMs:"
echo ""
echo "    for vm in kali-linux metasploitable2 dvwa-host security-onion; do"
echo "      VBoxManage snapshot \$vm take 'factory-reset' --description 'Initial clean state'"
echo "    done"

echo ""
echo "============================================="
echo "  Setup guide complete."
echo "  Review and run commands individually."
echo "============================================="
