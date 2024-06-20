#!/bin/bash

# Script to enable RDP and SSH User

# Define color codes
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[+] Updating system.${NC}"
sudo apt-get update -y
echo -e "${GREEN}[✓] System updated successfully.${NC}"

# Prompt the user for a username

echo -e "${YELLOW}[+] Adding a user.${NC}"
read -p "Enter the username to add: " username
sudo adduser $username
echo -e "${GREEN} [✓] Adding $username user DONE.${NC}"

echo -e "${YELLOW}[+] Adding user to sudo group.${NC}"
sudo usermod -aG sudo $username
echo -e "${GREEN}[✓] $username added to the sudo group.${NC}"

echo -e "${YELLOW}[+] Installing the XRDP server.${NC}"
sudo apt-get install xrdp -y
echo -e "${GREEN}[✓] XRDP server installation DONE.${NC}"

echo -e "${YELLOW}[+] Starting the XRDP server.${NC}"
sudo systemctl start xrdp
echo -e "${GREEN}[✓] Successfully started XRDP server.${NC}"

echo -e "${YELLOW}[+] Starting the XRDP session manager.${NC}"
sudo systemctl start xrdp-sesman
echo -e "${GREEN}[✓] Successfully started XRDP-SESMAN server.${NC}"

echo -e "${YELLOW}[+] Enabling XRDP to automatically run after boot.${NC}"
sudo systemctl enable xrdp
echo -e "${GREEN}[✓] Enabled XRDP to automatically run after boot.${NC}"

echo -e "${YELLOW}[+] Enabling XRDP-SESMAN to automatically run after boot.${NC}"
sudo systemctl enable xrdp-sesman
echo -e "${GREEN}[✓] Enabled XRDP-SESMAN to automatically run after boot.${NC}"

# Edit the /etc/xrdp/startwm.sh file to solve the "second session" problem
echo -e "${YELLOW}[+] Configuring XRDP session management.${NC}"
sudo sed -i '1i \
unset DBUS_SESSION_BUS_ADDRESS\n\
unset XDG_RUNTIME_DIR\n\
. $HOME/.profile\n' /etc/xrdp/startwm.sh

echo -e "${YELLOW}[+] Starting SSH service.${NC}"
sudo systemctl start ssh
echo -e "${GREEN}[✓] SSH service started successfully.${NC}"

echo -e "${YELLOW}[+] Enabling SSH service to automatically run after boot.${NC}"
sudo systemctl enable ssh
echo -e "${GREEN}[✓] SSH service enabled successfully.${NC}"

echo -e "${GREEN}[✓] Done.${NC}"
