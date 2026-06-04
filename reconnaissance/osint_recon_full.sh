#!/bin/bash
# OSINT Email Harvesting Script for a Domain
# Tools: theHarvester (primary), optional: emailharvester
# Author: Adapted for Kali Linux OSINT workflows
# Usage: ./email_osint.sh example.com
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 example.com"
    exit 1
fi
DOMAIN="$1"
OUTPUT_DIR="osint_emails_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
echo "[+] Starting OSINT email harvesting for domain: $DOMAIN"
echo "[+] Results will be saved in: $OUTPUT_DIR"
echo
# Check if theHarvester is installed
if ! command -v theharvester >/dev/null 2>&1; then
    echo "[-] Error: theHarvester is not installed. Please install it (e.g., sudo apt install theharvester)."
    exit 1
fi
# 1. theHarvester with multiple sources (use safer subset to avoid rate limits; customize as needed)
echo "[+] Running theHarvester with selected sources (bing, duckduckgo, yahoo, linkedin) to avoid rate limits..."
theharvester -d "$DOMAIN" -l 500 -b bing,duckduckgo,yahoo,linkedin -f "$OUTPUT_DIR/theharvester_selected.xml" > "$OUTPUT_DIR/theharvester_selected.txt" 2>&1
# Extract and deduplicate emails
grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b" "$OUTPUT_DIR/theharvester_selected.txt" | sort -u > "$OUTPUT_DIR/emails_theharvester.txt"
echo "[+] theHarvester complete. Emails saved to $OUTPUT_DIR/emails_theharvester.txt"
# Optional: Separate runs for specific sources if needed (uncomment and adjust)
# theharvester -d "$DOMAIN" -l 300 -b google -f "$OUTPUT_DIR/theharvester_google.xml" > "$OUTPUT_DIR/theharvester_google.txt" 2>&1
# grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b" "$OUTPUT_DIR/theharvester_google.txt" | sort -u > "$OUTPUT_DIR/emails_google.txt"
# 2. Optional: emailharvester (another Kali tool for search engine scraping)
if command -v emailharvester >/dev/null 2>&1; then
    echo "[+] Running emailharvester (Google, Bing, Yahoo, etc.)..."
    emailharvester -d "$DOMAIN" -l 500 > "$OUTPUT_DIR/emailharvester_raw.txt" 2>&1
    # Extract and deduplicate emails
    grep -E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b" "$OUTPUT_DIR/emailharvester_raw.txt" | sort -u > "$OUTPUT_DIR/emails_emailharvester.txt"
    echo "[+] emailharvester complete. Emails saved to $OUTPUT_DIR/emails_emailharvester.txt"
else
    echo "[!] emailharvester not installed; skipping."
fi
# 3. Combine and deduplicate all found emails
echo "[+] Combining and deduplicating all emails..."
cat "$OUTPUT_DIR"/emails_*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/all_unique_emails.txt"
echo
echo "[+] Done! Total unique emails found: $(wc -l < "$OUTPUT_DIR/all_unique_emails.txt")"
echo "[+] Full list: $OUTPUT_DIR/all_unique_emails.txt"
echo "[+] All raw outputs are in: $OUTPUT_DIR"
