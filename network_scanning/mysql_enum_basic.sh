#! /bin/bash

# This Script is designed to find hosts with hosts with MySQL installed

nmap -sT 10.10.100.0/24 -p 3306 >/dev/null -oG MySQLscan

cat MySQLscan | grep open > MySQLscan2

cat MySQLscan2
