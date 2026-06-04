#!/bin/bash

echo "Network Ping Sweep + Basic Port Scan"
echo "Enter network range (e.g., 192.168.1.0/24):"
read network

if [ -z "$network" ]; then
    echo "No network provided. Exiting."
    exit 1
fi

echo "Discovering live hosts..."
nmap -sn "$network" -oG live_hosts.txt

echo "Checking common ports on live hosts..."
grep "Up" live_hosts.txt | cut -d " " -f 2 > live_ips.txt

for ip in $(cat live_ips.txt); do
    echo "Scanning $ip for common ports..."
    nmap -F -v "$ip"
done

echo "Done! Live hosts saved to live_hosts.txt"
rm live_ips.txt  # Cleanup temporary file
