#!/bin/bash

# AutoRecon Wrapper Script for Kali Linux
# Usage: ./autorecon-scan.sh <target_ip_or_file> [optional autorecon args]

if [ -z "$1" ]; then
    echo "Usage: $0 <target_ip | targets.txt> [additional autorecon options]"
    echo "Example: $0 192.168.1.100 -v"
    echo "Example: $0 targets.txt --dirbuster.threads 50"
    exit 1
fi

TARGET="$1"
shift  # Remove first argument, leave the rest for autorecon

echo "[+] Starting AutoRecon on $TARGET"
echo "[+] Additional options: $@"
echo "[+] Results will be in ./results/"

# Run with sudo (required for some scans)
sudo autorecon "$TARGET" "$@"

echo "[+] Scan complete! Check results/ directory."
