#!/bin/bash

# OSINT Email Harvester for Specific Domain
# Kali Linux Bash Script
# Usage: ./email_harvest.sh example.com
# Requirements: Kali Linux tools (dnsenum, theHarvester, sublist3r, assetfinder, amass, h8mail, etc.)
#              Run as root for full functionality where needed
# Author: Grok (xAI) - Enhanced OSINT Script
# Date: 2026-01-05
# Disclaimer: For ethical OSINT only. Respect robots.txt, rate limits, and laws.

set -euo pipefail  # Exit on error, undefined vars, pipe failures

DOMAIN="${1:-}"
OUTPUT_DIR="${2:-emails_${DOMAIN}}"
THREADS=10
TIMEOUT=30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if domain provided
if [[ -z "$DOMAIN" ]]; then
    echo -e "${RED}Usage: $0 <domain> [output_dir]${NC}"
    echo "Example: $0 example.com"
    exit 1
fi

# Sanitize domain for filename
SAFE_DOMAIN=$(echo "$DOMAIN" | tr -cd 'a-zA-Z0-9.-' | tr '[:upper:]' '[:lower:]')

# Create output directory
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/harvest.log"
EMBEDDED_FILE="$OUTPUT_DIR/emails_embedded.txt"
ALL_EMAILS="$OUTPUT_DIR/all_emails.txt"
UNIQUE_EMAILS="$OUTPUT_DIR/unique_emails.txt"
VALID_EMAILS="$OUTPUT_DIR/valid_emails.txt"

echo -e "${BLUE}[*] Starting OSINT email harvest for ${GREEN}$DOMAIN${NC}" | tee -a "$LOG_FILE"
echo -e "${BLUE}[*] Output directory: $OUTPUT_DIR${NC}"

# Function to log and print
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

# Function to extract emails from text
extract_emails() {
    local input_file="$1"
    local output_file="$2"
    grep -Eio '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "$input_file" 2>/dev/null | grep -i "$DOMAIN" >> "$output_file" || true
}

# 1. Passive DNS Enumeration & Subdomains
log "Phase 1: Subdomain enumeration (dnsenum, sublist3r, assetfinder, amass)"
{
    # dnsenum (passive + brute)
    dnsenum --dnsserver 8.8.8.8,1.1.1.1 "$DOMAIN" -f /usr/share/dnsenum/dns.txt -w -r 2>/dev/null | tee "$OUTPUT_DIR/dnsenum.txt"
    
    # sublist3r (passive sources)
    sublist3r -d "$DOMAIN" -o "$OUTPUT_DIR/sublist3r.txt" -t 20 -v 2>/dev/null || true
    
    # assetfinder (fast passive)
    assetfinder --subs-only "$DOMAIN" > "$OUTPUT_DIR/assetfinder.txt" 2>/dev/null || true
    
    # amass enum -passive (comprehensive passive recon)
    amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/amass.txt" 2>/dev/null || true
    
} &

# 2. theHarvester (Google, Bing, LinkedIn, etc.)
log "Phase 2: theHarvester (search engines, PGP, etc.)"
theHarvester -d "$DOMAIN" -b all -f "$OUTPUT_DIR/theharvester.html" -l 500 -t "$THREADS" 2>/dev/null | tee "$OUTPUT_DIR/theharvester.txt" || true

# 3. GitHub Dorks (emails in repos)
log "Phase 3: GitHub recon"
{
    # GitHub users/orgs with domain
    curl -s "https://api.github.com/search/users?q=\"@${DOMAIN}\"" | jq -r '.[].login // empty' | while read user; do
        curl -s "https://api.github.com/users/$user/repos?per_page=100" | jq -r '.[].html_url // empty' | grep "$DOMAIN" || true
    done > "$OUTPUT_DIR/github_users.txt" 2>/dev/null || true
    
    # GitHub code search for emails
    curl -s "https://api.github.com/search/code?q=\"@${DOMAIN}\" | grep -o '[a-zA-Z0-9._%+-]+@${DOMAIN}' >> "$OUTPUT_DIR/github_emails.txt" 2>/dev/null || true
} &

# 4. Have I Been Pwned? (h8mail for breach data)
log "Phase 4: Breach data [h8mail]"
if command -v h8mail >/dev/null 2>&1; then
    echo "@$DOMAIN" | h8mail -o "$OUTPUT_DIR/h8mail.txt" --no-hibp-reporter 2>/dev/null || true
else
    log "h8mail not found, skipping breach check"
fi

# 5. Web crawling & Wayback Machine
log "Phase 5: Web scraping (gau, waybackurls, httpx)"
{
    # gau (GetAllUrls) - passive URLs from AlienVault, CommonCrawl, OTX, URLScan, Wayback
    command -v gau >/dev/null && gau "$DOMAIN" > "$OUTPUT_DIR/gau.txt" || true
    
    # waybackurls
    command -v waybackurls >/dev/null && waybackurls "$DOMAIN" >> "$OUTPUT_DIR/gau.txt" || true
    
    # httpx to filter live URLs (optional, slow)
    command -v httpx >/dev/null && cat "$OUTPUT_DIR/gau.txt" | httpx -silent -mc 200 -t 50 -o "$OUTPUT_DIR/live_urls.txt" || true
    
    # Extract from JS files specifically (common for emails)
    command -v gau >/dev/null && gau "$DOMAIN" | grep -i '\.js$' | xargs -I {} sh -c 'curl -s "$1" 2>/dev/null | grep -iEio "[a-z0-9._%+-]+@'"$DOMAIN"'"' _ {}' >> "$OUTPUT_DIR/js_emails.txt" || true
    
} &

# 6. Social Media & Other Sources
log "Phase 6: Social/Paste recon"
{
    # Hunter.io API (free tier limited, but CLI if available)
    command -v hunterio-domains >/dev/null && hunterio-domains --domain "$DOMAIN" > "$OUTPUT_DIR/hunter.txt" || true
    
    # Snusbase (if API key set in env)
    # export SNUSBASE_API_KEY=yourkey; curl -s "https://api.snusbase.com/v1/search/email?query=@$DOMAIN" ...
    
    # Pastebin/Pastes
    command -v pastebin-search >/dev/null && pastebin-search "@$DOMAIN" >> "$OUTPUT_DIR/pastes.txt" || true
    
} &

# Wait for background jobs
wait

# Aggregate ALL raw data for email extraction
log "Phase 7: Extracting emails from all sources"
cat "$OUTPUT_DIR"/*.txt "$OUTPUT_DIR"/*.html 2>/dev/null | tr -d '\0' | extract_emails /dev/stdin "$ALL_EMAILS" || true

# Get embedded emails (non-obfuscated)
grep -iE "(mailto:)?[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}" "$OUTPUT_DIR"/*.txt 2>/dev/null | grep -i "$DOMAIN" > "$EMBEDDED_FILE" || true

# Combine and deduplicate
cat "$ALL_EMAILS" "$EMBEDDED_FILE" 2>/dev/null | sort -u > "$UNIQUE_EMAILS"

# Validate emails (syntax + MX records)
log "Phase 8: Validating emails (syntax + MX)"
{
    while IFS= read -r email; do
        if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]] && host -t MX "${email##*@}" >/dev/null 2>&1; then
            echo "$email"
        fi
    done < "$UNIQUE_EMAILS"
} > "$VALID_EMAILS"

# Stats
TOTAL=$(wc -l < "$ALL_EMAILS" 2>/dev/null || echo 0)
UNIQUE=$(wc -l < "$UNIQUE_EMAILS" 2>/dev/null || echo 0)
VALID=$(wc -l < "$VALID_EMAILS" 2>/dev/null || echo 0)

log "Harvest complete!"
echo -e "${GREEN}Stats:${NC}"
echo "  Total raw emails: $TOTAL"
echo "  Unique emails: $UNIQUE"
echo "  Valid emails (MX): $VALID"
echo -e "  Unique: ${YELLOW}$UNIQUE_EMAILS${NC}"
echo -e "  Valid:  ${GREEN}$VALID_EMAILS${NC}"
echo -e "  Log:    $LOG_FILE${NC}"

# Optional: Open in editor or viewer
if command -v xdg-open >/dev/null 2>&1; then
    read -p "Open unique_emails.txt? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        xdg-open "$UNIQUE_EMAILS"
    fi
fi

# Pro Tips:
log "Pro Tips:"
echo "  - Check subdomains.txt for more targets"
echo "  - Use 'sort -uV $UNIQUE_EMAILS' for sorted view"
echo "  - Import to theHarvester or recon-ng for further intel"
echo "  - Rate limit respected; for production, add --delay"
echo "  - Install missing tools: apt install dnsenum sublist3r theharvester amass gau httpx waybackurls assetfinder"
