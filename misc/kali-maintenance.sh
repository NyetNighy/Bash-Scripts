#!/bin/bash

# Kali Linux System Maintenance Script
# This script performs basic system checks for common issues,
# updates packages, and safely clears unnecessary cache and temp files.
# Run as root: sudo ./this_script.sh
# WARNING: Review the script before running. It removes files permanently.

echo "=== Kali Linux Maintenance Script ==="
echo "Current date: $(date)"
echo

# 1. Basic system checks
echo "[1] Checking disk space usage..."
df -h

echo
echo "[2] Checking for broken packages..."
dpkg --configure -a
apt --fix-broken install -y

echo
echo "[3] Checking for available updates..."
apt update

echo
echo "[4] Listing upgradable packages..."
apt list --upgradable

echo
# Optional: Prompt for upgrade (uncomment if you want auto-upgrade)
# echo "[5] Upgrading packages..."
# apt upgrade -y
# apt full-upgrade -y

# 2. Cleaning package manager cache and unused packages
echo "[6] Removing unused dependencies..."
apt autoremove -y

echo
echo "[7] Cleaning old package cache..."
apt autoclean

echo
echo "[8] Fully clearing downloaded package cache (frees more space)..."
apt clean

# 3. Clearing temporary files
echo "[9] Clearing system temporary files (/tmp and /var/tmp)..."
rm -rf /tmp/*
rm -rf /var/tmp/*

echo
echo "[10] Clearing current user's cache (~/.cache)..."
# Safe for most apps; skips config files
rm -rf ~/.cache/*

# 4. Optional: Remove old journals (keep last 7 days)
echo "[11] Trimming system journals (keeping recent logs)..."
journalctl --vacuum-time=7d

# 5. Optional: Remove old kernels (careful!)
# Uncomment if you have multiple kernels and want to free space
# echo "[12] Removing old kernels..."
# echo $(dpkg --list | grep linux-image | awk '{ print $2 }' | sort -V | sed -n '/'"$(uname -r)"'/q;p') | xargs apt-get -y purge

echo
echo "=== Maintenance Complete ==="
echo "Reboot recommended if packages were upgraded or kernels removed."
echo "Final disk usage:"
df -h /
