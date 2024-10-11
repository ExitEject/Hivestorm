#!/bin/bash

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "Please run this script as root."
   exit 1
fi

echo "Removing unauthorized users maroon and rose..."

if id -u maroon >/dev/null 2>&1; then
    userdel -r maroon
    echo "Removed user maroon."
else
    echo "User maroon does not exist."
fi

if id -u rose >/dev/null 2>&1; then
    userdel -r rose
    echo "Removed user rose."
else
    echo "User rose does not exist."
fi

echo "Setting minimum password length to 10..."

# Modify /etc/pam.d/common-password
sed -i '/pam_unix.so/ s/$/ minlen=10/' /etc/pam.d/common-password

echo "Disabling IPv4 forwarding..."

# Modify /etc/sysctl.conf
if grep -q '^net.ipv4.ip_forward=' /etc/sysctl.conf; then
    sed -i 's/^net.ipv4.ip_forward=.*/net.ipv4.ip_forward=0/' /etc/sysctl.conf
else
    echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf
fi

# Apply the changes
sysctl -p

echo "Enabling Uncomplicated Firewall (UFW)..."

ufw --force enable

echo "Disabling and removing POP3 service..."

systemctl stop dovecot
systemctl disable dovecot

echo "Uncommenting security updates source..."

if [ -f /etc/apt/sources.list.d/official-package-repositories.list ]; then
    sed -i 's/^#\(deb http:\/\/security\.ubuntu\.com\/ubuntu\/ jammy-security main\)/\1/' /etc/apt/sources.list.d/official-package-repositories.list
else
    echo "Security updates source file does not exist."
fi

echo "Updating system packages..."

apt update -y
apt upgrade -y

echo "Removing prohibited MP3 files..."

if [ -d /home/cyan/Music ]; then
    rm -f /home/cyan/Music/*.mp3
    echo "Removed MP3 files from /home/cyan/Music."
else
    echo "Directory /home/cyan/Music does not exist."
fi

echo "Removing prohibited software Game Conqueror and ManaPlus..."

apt remove -y gameconqueror manaplus

echo "Configuring Chromium to block pop-ups and redirects..."

mkdir -p /etc/chromium/policies/managed/

cat <<EOF > /etc/chromium/policies/managed/block_popups.json
{
    "DefaultPopupsSetting": 2
}
EOF

echo "Configured Chromium to block pop-ups via policy."

echo "Configuring SSH to not permit empty passwords..."

if grep -q '^PermitEmptyPasswords' /etc/ssh/sshd_config; then
    sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
else
    echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config
fi

# Restart SSH service
systemctl restart sshd

echo "Remediation script completed successfully."
