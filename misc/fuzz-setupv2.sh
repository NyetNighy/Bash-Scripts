#!/usr/bin/env bash

# stealth-fuzz-setup-v3.sh
# Added: extensions (-x/-e) + recursion support (toggle + depth)

set -u    # treat unset variables as error

echo "============================================================="
echo "  Stealthy Fuzzing Command Builder (ffuf / gobuster) – v3"
echo "  Low threads + delay + browser-like headers"
echo "  Now with extensions & recursion support"
echo "============================================================="
echo

# ──────────────────────────────────────────────
# 1. Target URL
# ──────────────────────────────────────────────
while true; do
    read -p "Target URL (e.g. https://example.com/) : " TARGET
    TARGET="${TARGET%/}"  # remove trailing slash if any
    if [[ -z "$TARGET" ]]; then
        echo "Error: Target URL is required."
        continue
    fi
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        echo "Please start with http:// or https://"
        continue
    fi
    break
done

# ──────────────────────────────────────────────
# 2. Wordlist
# ──────────────────────────────────────────────
echo
echo "Common SecLists wordlists (pick number or enter full path):"
echo " 1) common.txt                  (~4.6k  – very quick)"
echo " 2) quickhits.txt               (~5k   – smoke test)"
echo " 3) raft-medium-directories.txt (~30k  – good balance)"
echo " 4) raft-medium-files-lowercase.txt (~110k – files)"
echo " 5) directory-list-2.3-medium.txt (~220k)"
echo " 6) Other / custom path"
echo

read -p "Choose [1-6] or enter full path: " WORDLIST_CHOICE

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
fi

# ──────────────────────────────────────────────
# 2.5 File extensions (for files discovery)
# ──────────────────────────────────────────────
echo
read -p "File extensions to append? (comma-separated, e.g. .php,.html,.txt,.bak or empty to skip): " EXTENSIONS
EXTENSIONS="${EXTENSIONS// /}"  # remove spaces
if [[ -n "$EXTENSIONS" ]]; then
    echo "→ Extensions will be appended: $EXTENSIONS"
fi

# ──────────────────────────────────────────────
# 3. Recursion
# ──────────────────────────────────────────────
echo
read -p "Enable recursion / recursive scanning? (y/N): " RECURSION
RECURSION="${RECURSION,,}"
RECURSION_OPT=""
RECURSION_DEPTH=0

if [[ "$RECURSION" == "y" || "$RECURSION" == "yes" ]]; then
    read -p "Max recursion depth? (1–3 recommended, default 2): " RECURSION_DEPTH
    RECURSION_DEPTH="${RECURSION_DEPTH:-2}"
    if ! [[ "$RECURSION_DEPTH" =~ ^[1-3]$ ]]; then
        echo "Invalid depth → using 2"
        RECURSION_DEPTH=2
    fi
    echo "→ Recursion enabled (depth $RECURSION_DEPTH)"
fi

# ──────────────────────────────────────────────
# 4. Tool choice
# ──────────────────────────────────────────────
echo
echo "Which tool?"
echo " 1) ffuf     (better recursion control, json output, recommended)"
echo " 2) gobuster"
read -p "Choose [1 or 2, default 1]: " TOOL_CHOICE

if [[ "$TOOL_CHOICE" != "2" ]]; then
    TOOL="ffuf"
else
    TOOL="gobuster"
fi

# ──────────────────────────────────────────────
# 5. Stealth level
# ──────────────────────────────────────────────
echo
echo "Stealth level:"
echo " 1) Very stealthy     (5–10 threads, ~0.8–2s delay)"
echo " 2) Balanced          (12–20 threads, ~0.3–1s delay)"
echo " 3) Faster but riskier (25–40 threads, ~0.1–0.5s delay)"
read -p "Choose [1–3, default 2]: " STEALTH_LEVEL

case "${STEALTH_LEVEL:-2}" in
    1) THREADS=8;   DELAY_MIN=0.8; DELAY_MAX=2.0 ;;
    2) THREADS=15;  DELAY_MIN=0.3; DELAY_MAX=1.0 ;;
    3) THREADS=35;  DELAY_MIN=0.1; DELAY_MAX=0.5 ;;
    *) THREADS=15;  DELAY_MIN=0.3; DELAY_MAX=1.0 ;;
esac

# ──────────────────────────────────────────────
# 6. Output file (optional)
# ──────────────────────────────────────────────
read -p "Save results? Enter filename base (or empty to skip): " OUTPUT_BASE
OUTPUT_OPT=""
if [[ -n "$OUTPUT_BASE" ]]; then
    if [[ "$TOOL" == "ffuf" ]]; then
        OUTPUT_OPT="-o \"${OUTPUT_BASE}\" -of json,csv"
    else
        OUTPUT_OPT="-o \"${OUTPUT_BASE}.txt\""
    fi
fi

# ──────────────────────────────────────────────
# Build & display final command
# ──────────────────────────────────────────────
echo
echo "============================================================="
echo "Generated stealthy command:"
echo

if [[ "$TOOL" == "ffuf" ]]; then

    printf 'ffuf -u "%s/FUZZ" \\\n' "$TARGET"
    printf '     -w "%s" \\\n' "$WORDLIST"
    printf '     -t %d \\\n' "$THREADS"
    printf '     -p %.1f-%.1f \\\n' "$DELAY_MIN" "$DELAY_MAX"
    printf '     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36" \\\n'
    printf '     -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \\\n'
    [[ -n "$EXTENSIONS" ]] && printf '     -e "%s" \\\n' "$EXTENSIONS"
    if [[ $RECURSION_DEPTH -gt 0 ]]; then
        printf '     -recursion -recursion-depth %d -recursion-strategy greedy \\\n' "$RECURSION_DEPTH"
    fi
    printf '     -ac -c \\\n'
    printf '     -fc 404,429,500 \\\n'
    printf '     -fs 0,123,4242 \\\n'
    printf '     -mc 200,301,302,307,401,403 \\\n'
    printf '     -s'
    [[ -n "$OUTPUT_OPT" ]] && printf ' \\\n     %s' "$OUTPUT_OPT"
    printf '\n\n'

else  # gobuster

    printf 'gobuster dir \\\n'
    printf '  -u "%s" \\\n' "$TARGET"
    printf '  -w "%s" \\\n' "$WORDLIST"
    printf '  -t %d \\\n' "$THREADS"
    printf '  --delay %.1fs-%.1fs \\\n' "$DELAY_MIN" "$DELAY_MAX"
    printf '  -a "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36" \\\n'
    printf '  --add-slash -r \\\n'   # -r = follow redirects
    [[ -n "$EXTENSIONS" ]] && printf '  -x %s \\\n' "${EXTENSIONS//./}"   # gobuster wants php,html (no dots)
    if [[ $RECURSION_DEPTH -gt 0 ]]; then
        printf '  -r \\\n'   # gobuster uses -r for recursive (no depth control)
        echo "  # Note: gobuster recursion is basic (no depth limit) – use ffuf for better control"
    fi
    printf '  -s "200,204,301,302,307,401,403" \\\n'
    printf '  -b "404,429,500" \\\n'
    printf '  --no-error -q'
    [[ -n "$OUTPUT_OPT" ]] && printf ' \\\n  %s' "$OUTPUT_OPT"
    printf '\n\n'

fi

echo "Copy-paste the command above to run it."
echo "Review carefully – ensure you have permission to scan this target!"
echo

read -p "Run it now? (y/N): " RUN_NOW
if [[ "${RUN_NOW,,}" == "y" || "${RUN_NOW,,}" == "yes" ]]; then
    echo "Launching... (for safety, please copy-paste manually)"
fi

exit 0
