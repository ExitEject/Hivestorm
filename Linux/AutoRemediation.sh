#!/bin/bash

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "Please run this script as root."
   exit 1
fi

echo "Removing unauthorized users, make sure to replace the names not allowed here"

# Define authorized and sudo/root allowed users
AUTHORIZED_USERS=("blue" "green" "brown" "purple" "orange" "lime" "yellow" "black" "cyan" "red" "white" "pink")
SUDO_ALLOWED_USERS=("cyan" "red" "white" "pink")

# Get current users from the system
CURRENT_USERS=$(cut -d: -f1 /etc/passwd)

# Function to remove unauthorized sudo/root privileges
remove_sudo_privileges() {
    local user=$1
    if groups "$user" | grep -qE '\bsudo\b|\broot\b'; then
        deluser "$user" sudo
        deluser "$user" root
        echo "Removed sudo/root privileges from user $user."
    fi
}

# Remove users not in the authorized list
for user in $CURRENT_USERS; do
    if [[ ! " ${AUTHORIZED_USERS[@]} " =~ " ${user} " ]]; then
        echo "User $user is not authorized. Deleting user..."
        userdel -r "$user"
    fi
done

# Check users with sudo or root privileges
for user in $CURRENT_USERS; do
    if groups "$user" | grep -qE '\bsudo\b|\broot\b'; then
        if [[ ! " ${SUDO_ALLOWED_USERS[@]} " =~ " ${user} " ]]; then
            echo "User $user is not allowed sudo/root privileges. Removing privileges..."
            remove_sudo_privileges "$user"
        else
            echo "User $user is allowed sudo/root privileges."
        fi
    fi
done

echo "Script execution completed."

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

echo "deb http://archive.ubuntu.com/ubuntu jammy-security main restricted universe multiverse" >> /etc/apt/sources.list.d/official-package-repositories.list

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

###############################EXPERIMENTAL TEST CODE###############################################
# Function to check and fix permissions on the shadow file
fix_shadow_permissions() {
    echo "Fixing permissions on /etc/shadow..."
    chmod 640 /etc/shadow || echo "Failed to fix shadow permissions"
}

# Function to enable firewall
enable_firewall() {
    echo "Enabling firewall..."
    ufw enable || echo "Failed to enable firewall"
}

# Enable IPv4 TCP SYN cookies
enable_syn_cookies() {
    echo "Enabling IPv4 TCP SYN cookies..."
    sysctl -w net.ipv4.tcp_syncookies=1 || echo "Failed to enable SYN cookies"
}

# Ignore bogus ICMP errors
ignore_bogus_icmp() {
    echo "Ignoring bogus ICMP errors..."
    sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 || echo "Failed to ignore bogus ICMP errors"
}

# Enable logging of martian packets
enable_martian_logging() {
    echo "Enabling logging of martian packets..."
    sysctl -w net.ipv4.conf.all.log_martians=1 || echo "Failed to enable martian packet logging"
}

# Disable IRC daemon
remove_irc_daemon() {
    echo "Removing IRC daemon..."
    apt remove --purge ircd || echo "Failed to remove IRC daemon"
}

# Disable Minetest service
remove_minetest_service() {
    echo "Removing Minetest service..."
    apt remove --purge minetest || echo "Failed to remove Minetest service"
}

# Update Apache
update_apache() {
    echo "Updating Apache..."
    apt update && apt upgrade apache2 || echo "Failed to update Apache"
}

# Update PHP
update_php() {
    echo "Updating PHP..."
    apt update && apt upgrade php || echo "Failed to update PHP"
}

# Remove prohibited software
remove_prohibited_software() {
    echo "Removing prohibited software..."
    apt remove --purge nmap john netcat ophcrack fcrackzip dsniff rfdump || echo "Failed to remove prohibited software"
}

# Disable SSH root login
disable_ssh_root_login() {
    echo "Disabling SSH root login..."
    sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || echo "Failed to disable SSH root login"
    systemctl restart sshd
}

# Disable unnecessary services (FTP, POP3, SMTP)
disable_services() {
    echo "Disabling FTP, POP3, and SMTP services..."
    systemctl disable vsftpd || echo "Failed to disable FTP"
    systemctl disable dovecot || echo "Failed to disable POP3"
    systemctl disable postfix || echo "Failed to disable SMTP"
}

# Update Sudo
update_sudo() {
    echo "Updating sudo..."
    apt update && apt upgrade sudo || echo "Failed to update sudo"
}

# Enable IPv4 protection features
enable_ipv4_protection() {
    echo "Enabling IPv4 protection features..."
    sysctl -w net.ipv4.tcp_syncookies=1 || echo "Failed to enable SYN cookies"
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 || echo "Failed to enable ICMP broadcast ignore"
    sysctl -w net.ipv4.conf.all.accept_redirects=0 || echo "Failed to disable ICMP redirects"
    sysctl -w net.ipv4.tcp_rfc1337=1 || echo "Failed to enable TIME-WAIT assassination protection"
}

# Restrict unprivileged access to kernel syslog
restrict_syslog_access() {
    echo "Restricting unprivileged access to kernel syslog..."
    sysctl -w kernel.dmesg_restrict=1 || echo "Failed to restrict syslog access"
}

# Fix insecure permissions on PostgreSQL configuration
fix_postgresql_permissions() {
    echo "Fixing insecure permissions on PostgreSQL configuration files..."
    chmod 640 /etc/postgresql/*/main/*.conf || echo "Failed to fix PostgreSQL permissions"
}

# Set Apache server tokens to least and disable trace requests
harden_apache() {
    echo "Hardening Apache configuration..."
    echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf || echo "Failed to set Apache server tokens"
    echo "TraceEnable off" >> /etc/apache2/conf-available/security.conf || echo "Failed to disable Apache trace requests"
    systemctl restart apache2
}

# Fix GRUB configuration permissions
fix_grub_permissions() {
    echo "Fixing GRUB configuration permissions..."
    chmod 600 /boot/grub/grub.cfg || echo "Failed to fix GRUB permissions"
}

# Apply all security updates
apply_security_updates() {
    echo "Applying security updates..."
    apt update && apt upgrade -y || echo "Failed to apply security updates"
}

# Disable Samba SMB1 protocol and require encryption
harden_samba() {
    echo "Hardening Samba configuration..."
    echo "server min protocol = SMB2" >> /etc/samba/smb.conf || echo "Failed to disable SMB1"
    echo "smb encrypt = required" >> /etc/samba/smb.conf || echo "Failed to require Samba encryption"
    systemctl restart smbd
}

# Main execution
fix_shadow_permissions
enable_firewall
enable_syn_cookies
ignore_bogus_icmp
enable_martian_logging
remove_irc_daemon
remove_minetest_service
update_apache
update_php
remove_prohibited_software
disable_ssh_root_login
disable_services
update_sudo
enable_ipv4_protection
restrict_syslog_access
fix_postgresql_permissions
harden_apache
fix_grub_permissions
apply_security_updates
harden_samba

echo "Remediation script complete."
