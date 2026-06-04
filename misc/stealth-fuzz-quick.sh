#!/usr/bin/env bash

# stealth-fuzz-quick-pass-run.sh
# Purpose:   Quick + stealthy first-pass enumeration
#            Small wordlist, low threads, generous delays, no recursion
# Changes:   Actually runs the command if user confirms "y"

set -u

echo "============================================================"
echo "  Quick & Stealthy First-Pass Fuzzer (with auto-run option)"
echo "  → small wordlist • low threads • high delay • no recursion"
echo "============================================================"
echo
echo -e "\033[1;33m!!! IMPORTANT !!!\033[0m"
echo "Only run this against targets you have **explicit written permission** to test."
echo "Unauthorized scanning may violate laws (CFAA, Computer Misuse Act, etc.)."
echo "Proceed only if you are in scope (bug bounty program, own infrastructure, CTF/lab)."
echo

# ──────────────────────────────────────────────
# 1. Target
# ──────────────────────────────────────────────
while true; do
    read -p "Target base URL[](https://example.com/) : " TARGET
    TARGET="${TARGET%/}"
    if [[ -z "$TARGET" ]]; then
        echo "Target URL is required."
        continue
    fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        echo "Please include http:// or https://"
        continue
    fi
    break
done

# ──────────────────────────────────────────────
# 2. Wordlist (quick ones only)
# ──────────────────────────────────────────────
echo
echo "Recommended quick wordlists:"
echo " 1) quickhits.txt      (~5k entries – ultra fast)"
echo " 2) common.txt         (~4.6k – very popular quick pass)"
echo " 3) Other (small list only – enter path)"
echo

read -p "Choose [1-3, default 1]: " WL_CHOICE

case "${WL_CHOICE:-1}" in
    1) WORDLIST="/usr/share/seclists/Discovery/Web-Content/quickhits.txt" ;;
    2) WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt" ;;
    3) read -p "Full path to small wordlist: " WORDLIST ;;
    *) WORDLIST="/usr/share/seclists/Discovery/Web-Content/quickhits.txt" ;;
esac

if [[ ! -f "$WORDLIST" ]]; then
    echo "Error: Wordlist not found → $WORDLIST"
    echo "Fix the path and try again."
    exit 1
fi

# ──────────────────────────────────────────────
# 3. Extensions? (optional – keep minimal for speed)
# ──────────────────────────────────────────────
echo
read -p "Append file extensions? (e.g. .php,.html,.txt or empty for none): " EXTENSIONS
EXTENSIONS="${EXTENSIONS// /}"   # remove spaces
[[ -n "$EXTENSIONS" ]] && echo "→ Will append: $EXTENSIONS"

# ──────────────────────────────────────────────
# 4. Tool (ffuf preferred)
# ──────────────────────────────────────────────
echo
read -p "Use ffuf (recommended) or gobuster? [f/g, default f]: " TOOL_CHOICE
if [[ "${TOOL_CHOICE,,}" == "g" ]]; then
    TOOL="gobuster"
else
    TOOL="ffuf"
fi

# ──────────────────────────────────────────────
# 5. Stealth & Speed presets (fixed for quick+stealth)
# ──────────────────────────────────────────────
THREADS=6
DELAY_MIN=0.7
DELAY_MAX=2.1

# ──────────────────────────────────────────────
# 6. Output (optional)
# ──────────────────────────────────────────────
read -p "Save results? Enter base filename (or empty to skip): " OUTPUT_BASE
OUTPUT_OPT=""
if [[ -n "$OUTPUT_BASE" ]]; then
    if [[ "$TOOL" == "ffuf" ]]; then
        OUTPUT_OPT="-o \"${OUTPUT_BASE}\" -of json,csv"
    else
        OUTPUT_OPT="-o \"${OUTPUT_BASE}.txt\""
    fi
fi

# ──────────────────────────────────────────────
# Build command
# ──────────────────────────────────────────────
echo
echo "============================================================"
echo "Generated quick & stealthy command:"
echo

if [[ "$TOOL" == "ffuf" ]]; then

    CMD="ffuf -u \"$TARGET/FUZZ\" \
     -w \"$WORDLIST\" \
     -t $THREADS \
     -p $DELAY_MIN-$DELAY_MAX \
     -H \"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\" \
     -H \"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\""

    [[ -n "$EXTENSIONS" ]] && CMD+=" \
     -e \"$EXTENSIONS\""

    CMD+=" \
     -ac -c \
     -fc 404,429,403,500,502,503 \
     -fs 0,123,424,1337,6666 \
     -mc 200,301,302,307,401 \
     -s"

    [[ -n "$OUTPUT_OPT" ]] && CMD+=" $OUTPUT_OPT"

else  # gobuster

    CMD="gobuster dir \
  -u \"$TARGET\" \
  -w \"$WORDLIST\" \
  -t $THREADS \
  --delay ${DELAY_MIN}s-${DELAY_MAX}s \
  -a \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36\" \
  --add-slash -r"

    [[ -n "$EXTENSIONS" ]] && CMD+=" \
  -x ${EXTENSIONS//./}"

    CMD+=" \
  -s \"200,204,301,302,307,401\" \
  -b \"404,403,429,500,502,503\" \
  --no-error -q"

    [[ -n "$OUTPUT_OPT" ]] && CMD+=" $OUTPUT_OPT"

fi

# Show the command
echo -e "\n$CMD\n"

echo "Expected runtime: usually 30 seconds – 5 minutes"
echo -e "\033[1;33mThis command is about to be executed if you confirm.\033[0m"
echo

read -p "Execute now? (y/N): " CONFIRM
if [[ "${CONFIRM,,}" == "y" || "${CONFIRM,,}" == "yes" ]]; then
    echo -e "\n\033[1;32mStarting scan...\033[0m\n"
    eval "$CMD"
    echo -e "\n\033[1;32mScan finished.\033[0m"
else
    echo -e "\n\033[1;33mScan cancelled.\033[0m"
    echo "You can copy-paste the command above to run it later."
fi

exit 0
