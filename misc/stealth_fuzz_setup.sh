#!/usr/bin/env bash

# stealth-fuzz-setup.sh
# Interactive script to build a stealthy ffuf or gobuster command
# Date: works in 2026 :)

set -u  # treat unset variables as error

echo "============================================================="
echo "  Stealthy Fuzzing Command Builder (ffuf / gobuster)"
echo "  Low threads + delay + browser-like headers"
echo "============================================================="
echo

# ──────────────────────────────────────────────
# 1. Target URL
# ──────────────────────────────────────────────
while true; do
    read -p "Target URL (e.g. https://example.com or https://example.com/path/) : " TARGET
    if [[ -z "$TARGET" ]]; then
        echo "Error: Target URL is required."
        continue
    fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        echo "Please include http:// or https://"
        continue
    fi
    break
done

# ──────────────────────────────────────────────
# 2. Wordlist
# ──────────────────────────────────────────────
echo
echo "Common SecLists wordlists (pick number or enter full path):"
echo " 1) common.txt              (~4.6k  – very quick)"
echo " 2) quickhits.txt           (~5k   – smoke test)"
echo " 3) raft-medium-directories (~30k  – good balance)"
echo " 4) raft-medium-files-lowercase (~110k)"
echo " 5) directory-list-2.3-medium (~220k – slower)"
echo " 6) Other / custom path"
echo

read -p "Choose wordlist [1-6] or enter full path: " WORDLIST_CHOICE

case "$WORDLIST_CHOICE" in
    1) WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt" ;;
    2) WORDLIST="/usr/share/seclists/Discovery/Web-Content/quickhits.txt" ;;
    3) WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" ;;
    4) WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt" ;;
    5) WORDLIST="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt" ;;
    6|"") read -p "Enter full wordlist path: " WORDLIST ;;
    *) WORDLIST="$WORDLIST_CHOICE" ;;
esac

if [[ ! -f "$WORDLIST" ]]; then
    echo "Warning: Wordlist not found → $WORDLIST"
    echo "You can continue, but the command will fail if path is wrong."
fi

# ──────────────────────────────────────────────
# 3. Tool choice
# ──────────────────────────────────────────────
echo
echo "Which tool do you want to use?"
echo " 1) ffuf     (more features, better recursion, json output)"
echo " 2) gobuster (simpler, very popular)"
read -p "Choose [1 or 2]: " TOOL_CHOICE

if [[ "$TOOL_CHOICE" == "1" || -z "$TOOL_CHOICE" ]]; then
    TOOL="ffuf"
else
    TOOL="gobuster"
fi

# ──────────────────────────────────────────────
# 4. Stealth level
# ──────────────────────────────────────────────
echo
echo "Stealth level (lower = stealthier but slower):"
echo " 1) Very stealthy     (5–10 req at a time, ~1s delay)"
echo " 2) Balanced stealth  (10–20 req, ~0.4–0.8s delay)"
echo " 3) Faster but riskier (25–40 req, light delay)"
read -p "Choose [1–3] (default 2): " STEALTH_LEVEL

case "${STEALTH_LEVEL:-2}" in
    1) THREADS=8;   DELAY="0.6-1.4" ;;
    2) THREADS=15;  DELAY="0.3-0.9" ;;
    3) THREADS=30;  DELAY="0.1-0.5" ;;
    *) THREADS=15;  DELAY="0.3-0.9" ;;
esac

# ──────────────────────────────────────────────
# 5. Output file (optional)
# ──────────────────────────────────────────────
read -p "Save results to file? (leave empty for no file) : " OUTPUT_FILE
OUTPUT_OPT=""
if [[ -n "$OUTPUT_FILE" ]]; then
    if [[ "$TOOL" == "ffuf" ]]; then
        OUTPUT_OPT="-o \"$OUTPUT_FILE\" -of json,csv"
    else
        OUTPUT_OPT="-o \"$OUTPUT_FILE\""
    fi
fi

# ──────────────────────────────────────────────
# Build final command
# ──────────────────────────────────────────────
echo
echo "============================================================="
echo "Generated stealthy command:"
echo

if [[ "$TOOL" == "ffuf" ]]; then

    cat << EOF
ffuf -u "${TARGET}FUZZ" \\
     -w "$WORDLIST" \\
     -t $THREADS \\
     -p $DELAY \\
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36" \\
     -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \\
     -ac -c \\
     -fc 404,429,500 \\
     -fs 0,123,4242 \\
     -mc 200,301,302,307,401,403 \\
     -s \\
     $OUTPUT_OPT
EOF

else  # gobuster

    cat << EOF
gobuster dir \\
  -u "${TARGET}" \\
  -w "$WORDLIST" \\
  -t $THREADS \\
  --delay ${DELAY//-/:}s \\
  -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36" \\
  --add-slash -r \\
  -s "200,204,301,302,307,401,403" \\
  -b "404,429,500" \\
  --no-error -q \\
  $OUTPUT_OPT
EOF

fi

echo
echo "Copy-paste the command above to run it."
echo "Review carefully – make sure you're authorized to scan this target!"
echo
read -p "Want to run it now? (y/N): " RUN_NOW
if [[ "${RUN_NOW,,}" == "y" ]]; then
    echo "Launching..."
    # You can uncomment the next line if you trust the generated command
    # eval "$(the command above)"   ← but better to copy-paste manually
    echo "(For safety, please copy-paste manually)"
fi

exit 0
