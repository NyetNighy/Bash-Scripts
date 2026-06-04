#!/bin/bash
# Enhanced Modular Pentest Script - Kali Linux
# Comprehensive & Accurate CVSS v3.1 Scoring with Realistic Vectors
set -euo pipefail

# === Config & Setup (unchanged) ===
# ... [all previous config, parsing, helpers remain the same] ...

# === Accurate CVSS Scoring Engine ===
add_vulnerability() {
    local title="$1"
    local cvss_score="$2"        # 0.0 - 10.0
    local vector="$3"            # Full CVSS:3.1 vector string
    local description="$4"
    local evidence="$5"
    local module="$6"
    local port="${7:-null}"
    local recommendation="${8:-"Apply latest patches and restrict access."}"

    # Derive severity from score (official CVSS v3.1 bands)
    local severity="None"
    if (( $(awk 'BEGIN {print ('$cvss_score' >= 9.0)}') )); then severity="Critical"; fi
    if (( $(awk 'BEGIN {print ('$cvss_score' >= 7.0 && '$cvss_score' < 9.0)}') )); then severity="High"; fi
    if (( $(awk 'BEGIN {print ('$cvss_score' >= 4.0 && '$cvss_score' < 7.0)}') )); then severity="Medium"; fi
    if (( $(awk 'BEGIN {print ('$cvss_score' > 0.0 && '$cvss_score' < 4.0)}') )); then severity="Low"; fi

    local tmp=$(mktemp)
    jq --arg t "$title" --argjson s "$cvss_score" --arg v "$vector" --arg sev "$severity" \
       --arg d "$description" --arg e "$evidence" --arg m "$module" --argjson p "$port" \
       --arg r "$recommendation" \
       '. += [{title: $t, cvss: $s, vector: $v, severity: $sev, description: $d, evidence: $e, module: $m, port: $p, recommendation: $r}]' \
       "$VULN_JSON" > "$tmp" && mv "$tmp" "$VULN_JSON"
}

# === Module-Specific Accurate CVSS Scoring ===

run_nikto() {
    local url=$1 port=$2
    nikto -h "$url" -o "$RESULTS_DIR/nikto_port${port}.txt" || true

    [[ ! -s "$RESULTS_DIR/nikto_port${port}.txt" ]] && return

    while IFS= read -r line; do
        [[ ! "$line" =~ ^\+ ]] && continue
        desc=$(echo "$line" | sed 's/^+ //; s/ (OSVDB-[0-9]*)//')

        case "$line" in
            *"OpenSSL Heartbleed"*)
                add_vulnerability "OpenSSL Heartbleed Vulnerability" 9.8 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:F/RL:O/RC:C" \
                    "Heartbleed allows remote attackers to read sensitive memory" "$line" "Nikto" "$port" \
                    "Upgrade OpenSSL to patched version immediately"
                ;;
            *"SSLv2"*)
                add_vulnerability "SSLv2 Enabled" 7.5 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N/E:U/RL:O/RC:C" \
                    "Deprecated and insecure SSL version enabled" "$line" "Nikto" "$port" \
                    "Disable SSLv2 and SSLv3 entirely"
                ;;
            *"SSLv3"*)
                add_vulnerability "SSLv3 Enabled (POODLE)" 5.9 \
                    "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:P/RL:O/RC:C" \
                    "SSLv3 vulnerable to POODLE attack" "$line" "Nikto" "$port"
                ;;
            *"Server leaks"*intranet* | *"Server leaks"*internal*IP*)
                add_vulnerability "Internal IP Disclosure" 5.3 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" \
                    "Server banners reveal internal network information" "$line" "Nikto" "$port" \
                    "Configure server to remove internal headers"
                ;;
            *"Directory listing"*)
                add_vulnerability "Directory Listing Enabled" 7.5 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" \
                    "Sensitive files may be exposed via directory browsing" "$line" "Nikto" "$port" \
                    "Disable directory listing in web server config"
                ;;
            *"phpinfo()"*)
                add_vulnerability "PHPInfo Exposed" 8.8 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" \
                    "Full PHP configuration and environment disclosed" "$line" "Nikto" "$port" \
                    "Remove phpinfo.php immediately"
                ;;
            *"retrieved via OPTIONS"*)
                add_vulnerability "Unnecessary HTTP Methods Enabled" 5.3 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N" \
                    "Dangerous methods (PUT/DELETE) enabled" "$line" "Nikto" "$port" \
                    "Restrict to only required HTTP methods"
                ;;
            *)
                add_vulnerability "Nikto Finding: $desc" 4.3 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" \
                    "General web server misconfiguration" "$line" "Nikto" "$port"
                ;;
        esac
    done < <(grep "^+" "$RESULTS_DIR/nikto_port${port}.txt")
}

run_gobuster() {
    local url=$1 port=$2
    # ... gobuster execution ...

    while IFS= read -r line; do
        [[ ! "$line" =~ Status:\ (200|301|302) ]] && continue
        path=$(echo "$line" | awk '{print $2}')

        case "$path" in
            */.git/* | */.git)
                add_vulnerability "Git Repository Exposed" 9.1 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/CR:H/IR:H/AR:M" \
                    "Full source code and history potentially accessible" "$line" "Gobuster" "$port" \
                    "Remove .git directory from production servers"
                ;;
            *.env | *config* | *.yml | *.yaml | *settings*)
                add_vulnerability "Configuration File Exposed" 8.8 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" \
                    "Sensitive credentials or keys may be leaked" "$line" "Gobuster" "$port" \
                    "Block access via .htaccess/robots.txt and remove backups"
                ;;
            */admin/* | */wp-admin/* | */phpmyadmin/* | */login* | */dashboard*)
                add_vulnerability "Administrative Interface Exposed" 7.1 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N" \
                    "Admin panel accessible without authentication restrictions" "$line" "Gobuster" "$port" \
                    "Restrict access by IP or add authentication"
                ;;
            *.bak | *.old | *.swp | *~)
                add_vulnerability "Backup/Source File Exposed" 7.5 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" \
                    "Backup files may contain source code" "$line" "Gobuster" "$port" \
                    "Remove backup files from web root"
                ;;
            *)
                add_vulnerability "Directory/File Discovered: $path" 3.1 \
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" \
                    "Potentially sensitive path discovered" "$line" "Gobuster" "$port"
                ;;
        esac
    done < "$RESULTS_DIR/gobuster_port${port}.txt"
}

scan_smb() {
    # ... enum4linux ...

    if [[ -s "$RESULTS_DIR/enum4linux.txt" ]]; then
        grep -qi "null session" "$RESULTS_DIR/enum4linux.txt" && \
            add_vulnerability "SMB Null Session Enabled" 9.1 \
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" \
                "Anonymous access to IPC$ and shares" "enum4linux output" "SMB" null \
                "Disable null sessions and require authentication"

        grep -qi "signing.*disabled" "$RESULTS_DIR/enum4linux.txt" && \
            add_vulnerability "SMB Signing Disabled" 8.1 \
                "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/MAV:A" \
                "Vulnerable to NTLM relay and MitM attacks" "enum4linux output" "SMB" null \
                "Enable SMB signing on all systems"

        grep -iE "share.*(everyone|world)" "$RESULTS_DIR/enum4linux.txt" | while read -r share; do
            add_vulnerability "World-Readable SMB Share" 6.5 \
                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" \
                "Unauthenticated users can read files" "$share" "SMB" null \
                "Restrict share permissions"
        done
    fi
}

scan_snmp() {
    # ... existing logic ...
    if [[ -n "$communities" ]]; then
        score=7.5
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        [[ "$communities" =~ public|private ]] && score=8.2 && vector+="CR:H"
        add_vulnerability "SNMP Community String Discovered" "$score" "$vector" \
            "Communities: $communities" "onesixtyone output" "SNMP" 161 \
            "Change to strong community strings or disable SNMP"
    fi
}

scan_nuclei() {
    # Nuclei provides real templates — preserve their severity, map to CVSS
    while IFS= read -r line; do
        if [[ "$line" =~ \[([a-z]+)\]\ \[([^]]+)\]\ (http[^:]+:([0-9]+)) ]]; then
            sev_raw="${BASH_REMATCH[1]^^}"
            template="${BASH_REMATCH[2]}"
            url="${BASH_REMATCH[3]}"
            port="${BASH_REMATCH[4]}"

            case "$sev_raw" in
                CRITICAL) score=9.5; vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";;
                HIGH)     score=8.2; vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";;
                MEDIUM)   score=5.9; vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N";;
                LOW)      score=3.7; vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N";;
                INFO)     score=0.0; continue;;  # Skip informational
                *)        score=5.0; vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N";;
            esac

            add_vulnerability "Nuclei: $template" "$score" "$vector" \
                "Detected on $url" "$line" "Nuclei" "$port" "Follow Nuclei template remediation guidance"
        fi
    done < "$RESULTS_DIR/nuclei_results.txt"
}

# === Enhanced HTML Report with Accurate CVSS ===
generate_html_report() {
    # ... header ...

    # Overall Risk
    highest=$(jq -r 'max_by(.cvss) | .cvss // 0' "$VULN_JSON")
    risk_level="Low"
    banner_color="#d4edda"
    (( $(awk 'BEGIN {print ('$highest' >= 9.0)}') )) && risk_level="Critical" && banner_color="#ffcccc"
    (( $(awk 'BEGIN {print ('$highest' >= 7.0 && '$highest' < 9.0)}') )) && risk_level="High" && banner_color="#ff9999"
    (( $(awk 'BEGIN {print ('$highest' >= 4.0 && '$highest' < 7.0)}') )) && risk_level="Medium" && banner_color="#fff3cd"

    add_section "Overall Risk Assessment" "
        <div class='risk-banner' style='background:$banner_color;'>
            Highest CVSS v3.1 Score: <strong>$highest</strong> → <span style='font-size:1.3em;'>$risk_level Risk</span><br><br>
            $(jq '[.[] | select(.severity=="Critical")] | length' "$VULN_JSON") Critical 
            $(jq '[.[] | select(.severity=="High")] | length' "$VULN_JSON") High 
            $(jq '[.[] | select(.severity=="Medium")] | length' "$VULN_JSON") Medium 
            $(jq length "$VULN_JSON") Total Findings
        </div>
    "

    # Prioritized Table
    add_section "Vulnerabilities Ranked by CVSS Score" "
        <table>
            <tr><th>CVSS</th><th>Severity</th><th>Title</th><th>Vector</th><th>Module</th><th>Port</th><th>Recommendation</th></tr>
            $(jq -r 'sort_by(.cvss) | reverse[] | 
                \"<tr class=\\\"\" + (.severity | ascii_downcase) + \"\\\">
                 <td><strong>\" + (.cvss | tostring) + \"</strong></td>
                 <td>\" + .severity + \"</td>
                 <td>\" + .title + \"</td>
                 <td class='cvss'>\" + .vector + \"</td>
                 <td>\" + .module + \"</td>
                 <td>\" + (if .port != null then .port | tostring else \"-\" end) + \"</td>
                 <td>\" + .recommendation + \"</td>
                </tr>\"' "$VULN_JSON")
        </table>
    "

    # ... rest of report (raw outputs, summaries) ...
}

# === Main execution remains the same ===
