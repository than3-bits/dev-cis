

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
# This will need follow-up snap directories appear world writable but are not?
// validate
// df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev
// -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
// set
// df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev
// -type d -perm -0002 2>/dev/null | xargs chmod a+t


# Configure Package Management Repo
# apt-cache policy


# Enable ASLR Page69
# Enable XD/NX Page67
# Uninstall Prelink dpkg -s prelink
# Setup AppArmor aa-status
# Make sure none are unconfined and all are in enforcing mode
# aa-enforce /etc/apparmor.d/<profile>
# aa-complain /etc/apparmor.d/<profile>

# permissions 644, root


# TODO
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


#Check for enabled systemd services
#Configure
auditd
rsyslog ()
cron daemon
sshd

#Check configuration for services
#Install & Configure
#List:
 -Rsyslogd
    logging & log permissions(page 237)
    remote logging
 -Logrotate
 -Systemd Cron Daemon (Configuration & Permissions) pg 260
 -Restrict at/Cron to Authorized Users
 -


#Server - No X Window System
# dpkg -l xserver-xorg*
# apt-get remove xserver-xorg*

# Postfix Local-Delivery Only? (Page 134)

#logs archived and digitally signed


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
