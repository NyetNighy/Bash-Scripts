# Bash Script Arsenal

A collection of offensive security / OSINT bash scripts for Kali Linux.

## 📁 Structure

```
Bash-Git/
├── email_harvester/       # Domain email harvesting + LinkedIn enum + JSON output
│   ├── email_harvester.sh       # Main (delay, -j, -f, -r flags)
│   ├── email_harvester_v2.sh    # Pre-update backup
│   ├── email_harvester_fixed.sh  # Partial fix variant
│   └── email_harvester_test.sh   # Test variant
│
├── reconnaissance/        # Subdomain enum, recon, OSINT
│   ├── osint_recon_basic.sh     # Basic OSINT scan
│   ├── osint_recon_extended.sh  # Extended OSINT
│   ├── osint_recon_full.sh      # Full OSINT sweep
│   ├── domain_enum_basic.sh      # Basic domain enumeration
│   ├── domain_enum_dnsbrute.sh  # DNS brute-force enum
│   ├── domain_enum_full.sh      # Full domain enumeration
│   ├── AutoRecon.sh             # Automated recon wrapper
│   ├── MEGA.sh                  # MEGA recon framework
│   ├── Recon.sh                 # Recon main
│   └── ReconExp.sh              # Recon expanded
│
├── vulnerability_scanning/  # Nuclei, Burp, ZAP, web vuln
│   ├── nuclei_web_scanner.sh
│   ├── web_vuln_scan.sh
│   ├── zap_web_vuln_scanner.sh
│   └── burp_auto_scan.sh
│
├── web_scanning/         # Web assessment
│   ├── web_scan_auto.sh
│   └── web_scan_full.sh
│
├── network_scanning/     # Nmap, MySQL, ping sweeps
│   ├── nmap_basic_scan.sh
│   ├── nmap_aggressive_scan.sh
│   ├── nmap_xml_auto.sh
│   ├── ping_sweep.sh
│   ├── mysql_enum_basic.sh
│   └── mysql_enum_variants.sh
│
├── active_directory/     # AD assessment
│   ├── ad_enum_basic.sh
│   ├── ad_enum_http_enum.sh
│   ├── ad_enum_http_enum_v1.sh
│   ├── ad_enum_http_enum_nc.sh
│   └── ad_enum_http_enum_ops.sh
│
├── automation/           # Metasploit automation
│   ├── msf_exploit_framework.sh
│   ├── msf_nmap_autopwn.sh
│   ├── msf_reverse_handler_auto.sh
│   ├── msf_meterpreter_handler.sh
│   └── msf_auto_enhanced.sh
│
└── misc/                # Fuzzing, maintenance, AI tools
    ├── stealth_fuzz_quick.sh
    ├── stealth_fuzz_setup.sh
    ├── fuzz_setup_v2.sh
    ├── robin_ai.sh
    ├── system_update.sh
    └── kali-maintenance.sh
```

## ⚠️ Disclaimer

All scripts are for **authorized, ethical security testing only**. Do not use against targets without explicit permission.

## 📧 Email Harvester Quick Start

```bash
# Basic
./email_harvester/email_harvester.sh example.com

# With delays, JSON output, staff subdomain filter
./email_harvester/email_harvester.sh example.com -d 1 -j -f staff

# With rate-limit backoff
./email_harvester/email_harvester.sh example.com -r -d 2 -j

# Help
./email_harvester/email_harvester.sh -h
```

## 🔧 Requirements

- Kali Linux
- Core: `dnsenum`, `theHarvester`, `sublist3r`, `assetfinder`, `amass`, `gau`, `httpx`, `curl`, `jq`
- Optional: `h8mail`, `nuclei`, `nmap`, `nikto`, `zap`, `burp`

## 📝 License

MIT — see individual scripts for authorship notes.