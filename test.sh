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

echo -e "${YELLOW}[+] Installing the full desktop environment.${NC}"
sudo apt-get install raspberrypi-ui-mods xserver-xorg xinit -y
echo -e "${GREEN}[✓] Full desktop environment installation DONE.${NC}"

echo -e "${YELLOW}[+] Configuring XRDP to use the correct desktop environment.${NC}"
sudo bash -c 'cat << EOF > /etc/xrdp/startwm.sh
#!/bin/sh
if [ -r /etc/default/locale ]; then
    . /etc/default/locale
    export LANG LANGUAGE
fi

unset DBUS_SESSION_BUS_ADDRESS
unset XDG_RUNTIME_DIR

. \$HOME/.profile

exec startlxde-pi
EOF'
sudo chmod +x /etc/xrdp/startwm.sh
echo -e "${GREEN}[✓] XRDP session management configured.${NC}"

echo -e "${YELLOW}[+] Copying necessary configuration files to the new user.${NC}"
sudo cp /etc/skel/.Xauthority /home/$username/.Xauthority
sudo cp /etc/skel/.xsession /home/$username/.xsession
sudo chown $username:$username /home/$username/.Xauthority
sudo chown $username:$username /home/$username/.xsession
echo -e "${GREEN}[✓] Configuration files copied.${NC}"

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

echo -e "${YELLOW}[+] Starting SSH service.${NC}"
sudo systemctl start ssh
echo -e "${GREEN}[✓] SSH service started successfully.${NC}"

echo -e "${YELLOW}[+] Enabling SSH service to automatically run after boot.${NC}"
sudo systemctl enable ssh
echo -e "${GREEN}[✓] SSH service enabled successfully.${NC}"

echo -e "${GREEN}[✓] Done.${NC}"

# Reboot the system to apply changes
echo -e "${YELLOW}[+] Rebooting the system.${NC}"
sudo reboot
