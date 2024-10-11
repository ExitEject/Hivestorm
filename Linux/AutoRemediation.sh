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
apt install unattended-upgrades -y
dpkg-reconfigure --priority=low unattended-upgrades

# Set strong password policies
echo "Enforcing strong password policies..."
apt install libpam-cracklib -y
sed -i '/pam_cracklib.so/ s/retry=3 minlen=8 difok=3/retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

echo "Installing Fail2Ban to prevent brute-force attacks..."
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban

echo "Setting up system auditing with auditd..."
apt install auditd audispd-plugins -y
systemctl enable auditd
systemctl start auditd

echo "Applying security kernel parameters..."
echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
echo "fs.protected_hardlinks = 1" | sudo tee -a /etc/sysctl.conf
echo "fs.protected_symlinks = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

echo "Configuring password expiration policies..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs


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
