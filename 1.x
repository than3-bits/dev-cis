

#1.1.2a Setup Separate Partitions

# /tmp (rw,nosuid,nodev,noexec,relatime) World Writable
# /var (rw,relatime,data=ordered)
# /var/tmp (rw,nosuid,nodev,noexec,relatime) World Writable
# /var/log (rw,relatime,data=ordered)
# /var/log/audit (rw, relatime,data=ordered)
# /home (rw, nodev,relatime,data=ordered)
# /dev/shm, (rw,nosuid,nodev,noexec,relatime)

# mount -o remount, ^ {dir}

# set sticky bit on all world writable directories
// validate
// df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev
// -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
// set
// df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev
// -type d -perm -0002 2>/dev/null | xargs chmod a+t


# Configure Package Management Repo
# apt-cache policy


# Install AIDE (disable preload)
# aide aide-common
#prelink -ua
# crontab -u root -e
# 0 5 * * * /usr/bin/aide --config /etc/aide/aide.conf --check

#Set password on root (single user mode)
# grep ^root:[*\!]: /etc/shadow
# passwd root

# Process Hardening
# grep "hard core" /etc/security/limits.conf /etc/security/limits.d/*
# * hard core 0
# sysctl fs.suid_dumpable
# fs.suid_dumpable = 0
# grep "fs\.suid_dumpable" /etc/sysctl.conf /etc/sysctl.d/*

# Enable ASLR Page69
# Enable XD/NX Page67
# Uninstall Prelink dpkg -s prelink
# Setup AppArmor aa-status
# Make sure none are unconfined and all are in enforcing mode
# aa-enforce /etc/apparmor.d/<profile>
# aa-complain /etc/apparmor.d/<profile>

# Warning Banners
# Name of the organization that owns the system
# Subject to monitoring and that monitoring is in compliance with local status,
# use of the system implies consent to such monitoring.
# /etc/motd
# /etc/issue (prelogin)
# /etc/issue.net (pre.login)
# permissions 644, root

# gdm = 644 /etc/dconf/profile/gdm
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults

# banner-message-enable banner-message-text
# /etc/dconf/db/gdm.d/*
# banner-message-enable=true
# banner-message-text='the message'
# run 'dconf update'

# Check for inetd services
# /etc/inetd.* (null return)
# Disable
# List:
# check for exist /etc/inetd.*|/etc/xinetd.conf|/etc/xinet.d/*
# if exist check grep -R "^chargen" /etc/inetd.* | /etc/xinetd.conf /etc/xinet.d/* chargen; disable = yes
# disable = yes in xinet; comment /etc/inetd.conf and /etc/inetd.d/*
# service list:
# chargen | daytime | discard | echo | time |
# rsh | rlogin | rexec | shell | login | exec
# talk | ntalk | telnet | tftp


Check for package installation
#Install
#List:
dpkg -s chrony | ntp
iptables
rsyslog
sshd

#Check for enabled systemd services
#Install & Configure
#List:
Chrony|NTP
auditd
rsyslog ()
cron daemon
sshd

#Check configuration for services
#Install & Configure
#List:
 -Chrony or NTP
 - Auditd Rules (x32/64)
    Timechange 32/64bit page203)
    User/Group Information Changes (pg205)
    Network Environment Changes
    AppArmor Changes
    Login/Logout Events
    Session Initiation Information
    Log DACL permission modifications
    Log Unauthorized Access Attempts (pg219)
    Log Privileged Commands (pg 221)
    Log Successful File System Mounts (pg 223)
    Log File Deletion Events
    Log Changes to Sudoers
    Log system administrator actions (sudolog)
    Log kernel module load/unload
    Ensure auditd configuration is immutable (pg233)
 -Rsyslogd
    logging & log permissions(page 237)
    remote logging
 -Logrotate
 -Systemd Cron Daemon (Configuration & Permissions) pg 260
 -Restrict at/Cron to Authorized Users
 -


# Check whether services are disabled
# Disable Services
# List:
# xinetd
# avahi-daemon
# cups
# isc-dhcp-server
# isc-dhcp-server6
# slapd
# nfs-server
# rpcbind
# bind9
# vsftpd
# apache2
# nginx
# dovecot
# smbd (samba)
# squid
# snmpd
# rsync
# nis


# Check whether packages are installed
# Remove packages
# List:
dpkg -s ldap-utils
dpkg -s openbsd-inetd
dpkg -s nis
dpkg -s rsh-client
dpkg -s rsh-redone-client
dpkg -s talk
dpkg -s telnet

#Server - No X Window System
# dpkg -l xserver-xorg*
# apt-get remove xserver-xorg*

# Postfix Local-Delivery Only? (Page 134)

#logs archived and digitally signed

# Network Parameters

Check sysctl options (sysctl.conf | sysctl.d/*):
#changes need net.ipv4.route.flush=1
sysctl [option] | sysctl -w [option] (writing)
net.ipv4.conf.ip_forward (0)
net.ipv4.conf.all.send_redirects (0)
net.ipv4.conf.default.send_redirects (0)
net.ipv4.conf.all.accept_source_route (0) [source routed packets]
net.ipv4.conf.default.accept_source_route (0) ''
net.ipv4.conf.all.accept_redirects (0) [ICMP redirect system routing]
net.ipv4.conf.default.accept_redirects(0)
net.ipv4.conf.all.secure_redirects (0) [From trusted gateways]
net.ipv4.conf.default.secure_redirects (0)
net.ipv4.conf.all.log_martians (1) [Log suspicious packets to kernel log]
net.ipv4.conf.default.log_martians (1)
net.ipv4.icmp_echo_ignore_broadcasts (1) [Prevent Smurf Attack]
net.ipv4.icmp_ignore_bogus_error_responses [Prevent log resource exhaust attack]
net.ipv4.conf.all.rp_filter (1) [Reverse Path Filtering]
net.ipv4.tcp_syncookies (1) [Allow syn cookies during FLOOD]
net.ipv6.conf.all.accept_ra (0) [ Yes = set static route]
net.ipv6.conf.default.accept_ra (0)
net.ipv6.conf.all.accept_redirects (0) [Accept ipv6 redirects]
net.ipv6.conf.default.accept_redirects (0)

# redirects may need cronjob sysctl -p ubuntu
# crontab: @reboot root /bin/sleep 5 && /sbin/sysctl --system


# If no ipv6
# Update Grub Boot Params
#grub_cmdline_linux="ipv6.disable=1" && update-grub
ipv6.disable=1
audit=1


# Ensure iptables is installed


# Setup Basic Firewall (Install Persist)
# Example
# #!/bin/bash
# Flush IPtables rules
iptables -F
# Ensure
iptables
iptables
iptables default deny firewall policy
-P INPUT DROP
-P OUTPUT DROP
-P FORWARD DROP
# Ensure
iptables
iptables
iptables loopback traffic is configured
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -s 127.0.0.0/8 -j DROP
# Ensure
iptables
iptables
iptables
iptables
iptables
iptables outbound and established connections are configured
-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
# Open inbound ssh(tcp port 22) connections
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# Configure Logging (4.1.1)
# Set Max Log Filesize Change Default 4 copies
# Disable system when audit logs full (p198)
# Ensure audit logs are not automatically deleted (p199)
