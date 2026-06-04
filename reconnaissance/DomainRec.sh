#! /bin/bash
echo "Enter domain (e.g., example.com):"
read domain
echo "Gathering info for $domain..."
whois $domain > whois.txt
nslookup $domain > dns.txt
echo "Recon done! Check whois.txt and dns.txt"
