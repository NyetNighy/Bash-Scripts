#!/bin/bash

# Auto Recon Script for Domain
# Tools required: subfinder, assetfinder, amass, httpx, nmap
# Install if missing: sudo apt install subfinder assetfinder amass httpx-tool nmap
# Note: Run with proper authorization only (e.g., bug bounty programs or owned domains).

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

DOMAIN=$1
OUTPUT_DIR="recon_$DOMAIN"
mkdir -p "$OUTPUT_DIR"

echo "[+] Starting reconnaissance on $DOMAIN"
echo "[+] Results will be saved in $OUTPUT_DIR"

# Step 1: Subdomain Enumeration
echo "[+] Enumerating subdomains..."

subfinder -d $DOMAIN -silent -o "$OUTPUT_DIR/subfinder.txt"
assetfinder --subs-only $DOMAIN > "$OUTPUT_DIR/assetfinder.txt"
amass enum -passive -d $DOMAIN -o "$OUTPUT_DIR/amass.txt"

# Combine and unique
cat "$OUTPUT_DIR"/*.txt | sort -u > "$OUTPUT_DIR/all_subdomains.txt"
echo "[+] Found $(wc -l < "$OUTPUT_DIR/all_subdomains.txt") unique subdomains"

# Step 2: Probe for live hosts (HTTP/HTTPS)
echo "[+] Probing for live hosts with httpx..."
cat "$OUTPUT_DIR/all_subdomains.txt" | httpx -silent -threads 100 -o "$OUTPUT_DIR/live_hosts.txt"
echo "[+] Found $(wc -l < "$OUTPUT_DIR/live_hosts.txt") live hosts"

# Step 3: Basic port scan on live hosts (top 1000 ports)
echo "[+] Running basic Nmap scan on live hosts..."
nmap -iL "$OUTPUT_DIR/live_hosts.txt" -T4 --top-ports 1000 -oN "$OUTPUT_DIR/nmap_scan.txt"

echo "[+] Recon complete! Check $OUTPUT_DIR for results."
echo "    - all_subdomains.txt : All discovered subdomains"
echo "    - live_hosts.txt     : Live HTTP/HTTPS hosts"
echo "    - nmap_scan.txt      : Basic port scan results"
