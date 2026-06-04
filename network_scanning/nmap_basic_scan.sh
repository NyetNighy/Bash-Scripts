#! /bin/bash
echo "Enter target IP or range (e.g., 192.168.1.0/24):"
read target
echo "Scanning $target..."
nmap -sV -O $target -oN scan_results.txt
echo "Scan complete! Results saved to scan_results.txt"
