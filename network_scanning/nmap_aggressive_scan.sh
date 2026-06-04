#!/bin/bash

echo "Nmap Aggressive Scanner"
echo "Enter target IP or range (e.g., 192.168.1.1 or 192.168.1.0/24):"
read target

if [ -z "$target" ]; then
    echo "No target provided. Exiting."
    exit 1
fi

output="nmap_scan_$(date +%Y%m%d_%H%M%S).txt"
nmap -A -T4 -v "$target" -oN "$output"

echo "Scan complete! Results saved to $output"
