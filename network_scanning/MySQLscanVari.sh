#! /bin/bash
echo "Enter starting IP address:"
read FirstIP

echo "Enter last octet of the last IP address:"
Read LastOctetIP

echo "Enter port number to scan for:"
read port

nmap -sT $firstIP-$lastOctetIP -p $port >/dev/null -oG MySQLscan

cat MySQLscan | grep open > MySQLscan2

cat MySQLscan2
