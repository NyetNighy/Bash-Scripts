#! /bin/bash
echo "Updating Kali ..."
sudo apt update && sudo apt full-upgrade -y
sudo apt autoremove -y
echo "Updating finished"
