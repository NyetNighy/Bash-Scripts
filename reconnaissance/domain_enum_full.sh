#!/bin/bash

# Modular Auto Recon Script for Kali Linux
# Tools: subfinder, assetfinder, amass, httpx, nmap, nuclei
# Usage: ./auto_recon.sh [-s] [-p] [-n] [-v] <domain>
#   -s : Skip subdomain enumeration (use existing all_subdomains.txt)
#   -p : Skip live host probing
#   -n : Skip Nmap scanning
#   -v : Skip Nuclei vulnerability scanning
#   No flags = run all stages

set -euo pipefail  # Better error handling

DOMAIN=""
OUTPUT_DIR=""
SKIP_SUBS=false
SKIP_PROBE=false
SKIP_NMAP=false
SKIP_NUCLEI=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[+] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[!] $1${NC}"
}

error() {
    echo -e "${RED}[!] $1${NC}"
}

# Parse arguments
while getopts "spnv" opt; do
    case $opt in
        s) SKIP_SUBS=true ;;
        p) SKIP_PROBE=true ;;
        n) SKIP_NMAP=true ;;
        v) SKIP_NUCLEI=true ;;
        *) echo "Usage: $0 [-s] [-p] [-n] [-v] <domain>"; exit 1 ;;
    esac
done
shift $((OPTIND -1))

if [ -z "${1:-}" ]; then
    error "Domain is required!"
    echo "Usage: $0 [-s] [-p] [-n] [-v] <domain>"
    echo "Example: $0 example.com"
    exit 1
fi

DOMAIN="$1"
OUTPUT_DIR="recon_$DOMAIN"
mkdir -p "$OUTPUT_DIR"

log "Starting modular reconnaissance on $DOMAIN"
log "Results directory: $OUTPUT_DIR"

# ==================== FUNCTIONS ====================

enumerate_subdomains() {
    if $SKIP_SUBS && [ -f "$OUTPUT_DIR/all_subdomains.txt" ]; then
        log "Skipping subdomain enumeration (file exists)"
        return
    fi

    log "Enumerating subdomains..."

    subfinder -d "$DOMAIN" -silent -o "$OUTPUT_DIR/subfinder.txt" 2>/dev/null || warn "subfinder failed or not installed"
    assetfinder --subs-only "$DOMAIN" > "$OUTPUT_DIR/assetfinder.txt" 2>/dev/null || warn "assetfinder failed or not installed"
    amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/amass.txt" 2>/dev/null || warn "amass failed or not installed"

    # Fallback: if all tools failed, create empty file
    if [ ! -f "$OUTPUT_DIR/subfinder.txt" ] && [ ! -f "$OUTPUT_DIR/assetfinder.txt" ] && [ ! -f "$OUTPUT_DIR/amass.txt" ]; then
        touch "$OUTPUT_DIR/subfinder.txt" "$OUTPUT_DIR/assetfinder.txt" "$OUTPUT_DIR/amass.txt"
    fi

    cat "$OUTPUT_DIR"/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/all_subdomains.txt"
    log "Found $(wc -l < "$OUTPUT_DIR/all_subdomains.txt") unique subdomains → all_subdomains.txt"
}

probe_live_hosts() {
    if $SKIP_PROBE && [ -f "$OUTPUT_DIR/live_hosts.txt" ]; then
        log "Skipping live host probing (file exists)"
        return
    fi

    if [ ! -s "$OUTPUT_DIR/all_subdomains.txt" ]; then
        warn "No subdomains found - skipping live host probing"
        return
    fi

    log "Probing for live HTTP/HTTPS hosts with httpx..."
    cat "$OUTPUT_DIR/all_subdomains.txt" | httpx -silent -threads 100 -timeout 10 -o "$OUTPUT_DIR/live_hosts.txt" || warn "httpx failed"
    
    if [ -s "$OUTPUT_DIR/live_hosts.txt" ]; then
        log "Found $(wc -l < "$OUTPUT_DIR/live_hosts.txt") live hosts → live_hosts.txt"
    else
        warn "No live hosts found"
        touch "$OUTPUT_DIR/live_hosts.txt"
    fi
}

run_nmap_scan() {
    if $SKIP_NMAP; then
        log "Skipping Nmap scan (-n flag)"
        return
    fi

    if [ ! -s "$OUTPUT_DIR/live_hosts.txt" ]; then
        warn "No live hosts - skipping Nmap scan"
        return
    fi

    log "Running Nmap top 1000 ports scan..."
    nmap -iL "$OUTPUT_DIR/live_hosts.txt" -T4 --top-ports 1000 --open -oN "$OUTPUT_DIR/nmap_scan.txt" >/dev/null 2>&1 || warn "nmap failed"
    log "Nmap results → nmap_scan.txt"
}

run_nuclei_scan() {
    if $SKIP_NUCLEI; then
        log "Skipping Nuclei scan (-v flag)"
        return
    fi

    if ! command -v nuclei &> /dev/null; then
        warn "nuclei not found - skipping vulnerability scan"
        return
    fi

    if [ ! -s "$OUTPUT_DIR/live_hosts.txt" ]; then
        warn "No live hosts - skipping Nuclei scan"
        return
    fi

    log "Updating Nuclei templates..."
    nuclei -update-templates -silent || warn "Failed to update templates"

    log "Running Nuclei vulnerability scan (critical/high/medium)..."
    nuclei -l "$OUTPUT_DIR/live_hosts.txt" \
           -t cves/,vulnerabilities/,exposures/,misconfiguration/,technologies/ \
           -severity critical,high,medium \
           -c 50 -rl 150 \
           -silent \
           -o "$OUTPUT_DIR/nuclei_results.txt" || warn "Nuclei scan had issues"

    if [ -s "$OUTPUT_DIR/nuclei_results.txt" ]; then
        log "Nuclei found vulnerabilities → nuclei_results.txt ($(wc -l < "$OUTPUT_DIR/nuclei_results.txt") findings)"
    else
        log "No vulnerabilities found by Nuclei"
    fi
}

# ==================== MAIN WORKFLOW ====================

enumerate_subdomains
probe_live_hosts
run_nmap_scan
run_nuclei_scan

log "Recon complete for $DOMAIN!"
echo
echo "Summary of results in $OUTPUT_DIR:"
echo "  • all_subdomains.txt   : All discovered subdomains"
echo "  • live_hosts.txt       : Live web hosts (with scheme)"
echo "  • nmap_scan.txt        : Open ports (top 1000)"
echo "  • nuclei_results.txt   : Vulnerability findings"
echo
warn "Always ensure you have explicit permission to test $DOMAIN."

exit 0
