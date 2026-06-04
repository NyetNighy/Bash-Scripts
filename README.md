# Bash Script Arsenal

A collection of offensive security / OSINT bash scripts for Kali Linux.

## 📁 Structure

```
Bash-Git/
├── email_harvester/    # Domain email harvesting with LinkedIn + JSON output
├── reconnaissance/     # Subdomain enum, recon, OSINT frameworks
├── vulnerability_scanning/  # Nuclei, Burp, ZAP wrappers
├── web_scanning/      # Web assessment automation
├── network_scanning/  # Nmap, MySQL, ping sweeps
├── active_directory/  # AD assessment scripts
├── automation/        # Metasploit automation
├── misc/              # Fuzzing, updates, maintenance
└── payloads/          # Payload generation helpers
```

## ⚠️ Disclaimer

All scripts are for **authorized, ethical security testing only**. Do not use against targets without explicit permission.

## 📧 Email Harvester Quick Start

```bash
# Basic run
./email_harvester/email_harvester.sh example.com

# With delays, JSON output, staff subdomain filter
./email_harvester/email_harvester.sh example.com -d 1 -j -f staff

# Help
./email_harvester/email_harvester.sh -h
```

## 🔧 Requirements

- Kali Linux
- Core tools: `dnsenum`, `theHarvester`, `sublist3r`, `assetfinder`, `amass`, `gau`, `httpx`, `curl`, `jq`
- Optional: `h8mail`, `hunterio` CLI, `nuclei`, `nmap`, `nikto`, `zap`

## 📝 License

MIT — see individual scripts for authorship notes.