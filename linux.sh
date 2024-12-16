

apt-get -V -y install firefox hardinfo chkrootkit iptables portsentry lynis ufw gufw sysv-rc-conf nessus clamav auditd

auditctl -e 1
apt-get -V -y install --reinstall coreutils
apt-get update
apt-get upgrade
apt-get dist-upgrade
sudo apt-get --purge --reinstall install firefox -y
apt-get install -y apparmor
systemctl enable apparmor
systemctl start apparmor

#nano /etc/apt/sources.list #check for malicious sources
nano /etc/resolv.conf #make sure if safe, use 8.8.8.8 for name server
#nano /etc/hosts #make sure is not redirecting
nano /etc/rc.local #should be empty except for 'exit 0'
#nano /etc/sysctl.conf #change net.ipv4.tcp_syncookies entry from 0 to 1

#nano /etc/login.defs #FAILLOG_ENAB YES, LOG_UNKFAIL_ENAB YES. SYSLOG_SU_ENAB YES, SYSLOG_SG_ENAB YES ,PASS_MAX_DAYS 	90, PASS_MIN_DAYS 	10, PASS_WARN_AGE 7

nano /etc/ssh/sshd_config # LoginGraceTime 60 PermitRootLogin no Protocol 2 PermitEmptyPasswords no PasswordAuthentication yes X11Fowarding no UsePAM yes UsePrivilegeSeparation yes

    
remove_malware () {
    # Files necessary:
    #   NONE

    echo "${RED}Please make sure you are 100% sure that there is no critcial services in this before running!!${RESET}"
    declare -a arr=(john, abc, sqlmap, aria2
                    aquisition, bitcomet, bitlet, bitspirit
                    endless-sky, zenmap, minetest, minetest-server
                    armitage, crack, apt pureg knocker, aircrack-ng
                    airbase-ng, hydra, freeciv
                    wireshark, tshark
                    hydra-gtk, netcat, netcat-traditional, netcat-openbsd
                    netcat-ubuntu, netcat-minimal, qbittorrent, ctorrent
                    ktorrent, rtorrent, deluge, transmission-common
                    transmission-bittorrent-client, tixati, frostwise, vuse
                    irssi, transmission-gtk, utorrent, kismet
                    medusa, telnet, exim4, telnetd
                    bind9, crunch, tcpdump, tomcat
                    tomcat6, vncserver, tightvnc, tightvnc-common
                    tightvncserver, vnc4server, nmdb, dhclient
                    telnet-server, ophcrack, cryptcat, cups
                    cupsd, tcpspray, ettercap
                    wesnoth, snort, pryit
                    weplab, wireshark, nikto, lcrack
                    postfix, snmp, icmp, dovecot
                    pop3, p0f, dsniff, hunt
                    ember, nbtscan, rsync, freeciv-client-extras
                    freeciv-data, freeciv-server, freeciv-client-gtk
                    )

    for i in "${arr[@]}"
    do
        sudo $APT purge -y --force-yes $i
    done
}


check_and_reset_crontabs () {
    local normal_crontab='# /etc/crontab: system-wide crontab\n
    # Unlike any other crontab you dont have to run the crontab\n
    # command to install the new version when you edit this file\n
    # and files in /etc/cron.d. These files also have username fields,\n
    # that none of the other crontabs do.\n

    SHELL=/bin/sh\n
    PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n

    # m h dom mon dow user  command\n
    17 \*    \* \* \*   root    cd / && run-parts --report /etc/cron.hourly\n
    25 6    \* \* \*   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n
    47 6    \* \* 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n
    52 6    1 \* \*   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n
    #'
    
    # Save a backup of the crontab and then just replace it with an empty one
    sudo cp /etc/crontab backup/services/crons/crontab
    echo -e $normal_crontab | sed "s/^ //g; s/\\\*//g" | sudo tee /etc/crontab > /dev/null

    # List all the crontabs 
    #sudo ls -la /var/spool/cron/* 2> /dev/null | tee backup/services/crontabs_
    sudo ls -la /etc/cron.d/* 2> /dev/null      | tee backup/services/crons/crontab_system_crons.log > /dev/null
    sudo ls -la /etc/cron.hourly/ 2> /dev/null  | tee -a backup/services/crons/crontab_system_crons.log > /dev/null
    sudo ls -la /etc/cron.daily/* 2> /dev/null  | tee -a backup/services/crons/crontab_system_crons.log  > /dev/null
    sudo ls -la /etc/cron.weekly/* 2> /dev/null | tee -a backup/services/crons/crontab_system_crons.log > /dev/null
    sudo ls -la /etc/cron.monthly/* 2> /dev/null| tee -a backup/services/crons/crontab_system_crons.log > /dev/null

    local user_crons=$(sudo ls /var/spool/cron/crontabs)
    local answer=""
    if [[ ! -z $user_crons ]]
    then 
        echo "${YELLOW}[!] Detected user crontabs at /var/spool/cron/crontabs for users: ${user_crons}${RESET}"
        echo -n "${CYAN}Move user crontabs to quarantine [${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
        read -rp "" answer
        case $answer in 
            y|Y)
                echo
                echo "${GREEN}[*] Crontabs moved to backup/services/crons/ ${RESET}"
                for cron in $user_crons
                do 
                    sudo mv /var/spool/cron/crontabs/$cron backup/services/crons/$cron
                done 
                ;;
            n|N)
                ;; # Do nothing
        esac
    fi
}

disable_guests () {
    # Makes the self-added configs directory
    # Adds a new local config

    sudo mkdir -p /etc/lightdm/lightdm.conf.d
    sudo touch /etc/lightdm/lightdm.conf.d/myconfig.conf

    echo "[SeatDefaults]"                   | sudo tee /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "autologin-user=`whoami`"          | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "allow-guest=false"                | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "greeter-hide-users=true"          | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "greeter-show-manual-login=true"   | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "greeter-allow-guest=false"        | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "autologin-guest=false"            | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "AutomaticLoginEnable=false"       | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "xserver-allow-tcp=false"          | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    
    sudo lightdm --test-mode --debug 2> backup/users/lightdm_setup.log
    CONFIGSET=$(grep myconfig.conf backup/users/lightdm_setup.log)  
    if [[ -z CONFIGSET ]] 
    then 
        echo "${RED}LightDM config not set, please check manually.${RESET}"
        read -rp "Press <enter> to continue"
    fi

    sudo service lightdm restart
}
user_policies_install () {
    # Installs required packages for user policies hardening 

    sudo $APT install --force-yes -y libpam-cracklib fail2ban
}

# -------------------- Networking functions -------------------- 
networking_sysctl_config () {
    # Add a new local sysctl config file for the networking section
    sudo touch /etc/sysctl.d/cybercent-networking.conf

    # Add each config listed below 

    # IPv4 TIME-WAIT assassination protection
    echo net.ipv4.tcp_rfc1337=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # IP Spoofing protection, Source route verification  
    # Scored
    echo net.ipv4.conf.all.rp_filter=1      | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.rp_filter=1  | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Ignore ICMP broadcast requests
    echo net.ipv4.icmp_echo_ignore_broadcasts=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Ignore Directed pings
    echo net.ipv4.icmp_echo_ignore_all=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Log Martians
    echo net.ipv4.conf.all.log_martians=1               | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.icmp_ignore_bogus_error_responses=1   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Disable source packet routing
    echo net.ipv4.conf.all.accept_source_route=0        | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.accept_source_route=0    | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.all.accept_source_route=0        | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_source_route=0    | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Block SYN attacks
    echo net.ipv4.tcp_syncookies=1          | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.tcp_max_syn_backlog=2048  | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.tcp_synack_retries=2      | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.tcp_syn_retries=4         | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # Try values 1-5


    # Ignore ICMP redirects
    echo net.ipv4.conf.all.send_redirects=0         | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.send_redirects=0     | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.all.accept_redirects=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.accept_redirects=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.all.secure_redirects=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.secure_redirects=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    echo net.ipv6.conf.all.send_redirects=0         | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # ignore ?
    echo net.ipv6.conf.default.send_redirects=0     | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # ignore ?
    echo net.ipv6.conf.all.accept_redirects=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_redirects=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.all.secure_redirects=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # ignore ?
    echo net.ipv6.conf.default.secure_redirects=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # ignore ?

    # Note disabling ipv6 means you dont need the majority of the ipv6 settings

    # General options
    echo net.ipv6.conf.default.router_solicitations=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_ra_rtr_pref=0     | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_ra_pinfo=0        | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_ra_defrtr=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.autoconf=0               | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.dad_transmits=0          | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.max_addresses=1          | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.all.disable_ipv6=1               | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.lo.disable_ipv6=1                | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Reload the configs 
    # sudo sysctl -p /etc/sysctl.d/cybercent.conf
    sudo sysctl --system

    # Disable IPV6
    sudo sed -i '/^IPV6=yes/ c\IPV6=no\ /etc/default/ufw'
    echo 'blacklist ipv6' | sudo tee -a /etc/modprobe.d/blacklist > /dev/null
}

firewall_setup () {
    # UFW Firewall setup
    # Since idk critical services, I didnt do these commands 
    #   * sudo ufw default deny incoming
    #   * sudo ufw default allow outgoing
    #   * sudo ufw allow <PORT>  (this is for each critical service) 

    # Flush/Delete firewall rules
    sudo iptables -F
    sudo iptables -X
    sudo iptables -Z

    sudo $APT install -y ufw
    sudo ufw status verbose > backup/networking/firewall_ufw_before.log 
    echo "y" | sudo ufw reset
    sudo ufw enable 
    sudo ufw logging full

    # The particular firewall exceptions will be added depending on critical services
    sudo ufw default deny incoming 
    sudo ufw default allow outgoing

    sudo ufw deny 23    #Block Telnet
    sudo ufw deny 2049  #Block NFS
    sudo ufw deny 515   #Block printer port
    sudo ufw deny 111   #Block Sun rpc/NFS
    sudo ufw status verbose > backup/networking/firewall_ufw_after.log 

    # Iptables specific
    # Block null packets (DoS)
    sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

    # Block syn-flood attacks (DoS)
    sudo iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

    #Drop incoming packets with fragments
    sudo iptables -A INPUT -f -j DROP

    # Block XMAS packets (DoS)
    sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

    # Allow internal traffic on the loopback device
    sudo iptables -A INPUT -i lo -j ACCEPT

    # Allow ssh access
    # sudo iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT

    # Allow established connections
    sudo iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow outgoing connections
    sudo iptables -P OUTPUT ACCEPT

    # Set default deny firewall policy
    sudo iptables -P INPUT DROP

    #Block Telnet
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP

    #Block NFS
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP

    #Block X-Windows
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP

    #Block X-Windows font server
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP

    #Block printer port
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP

    #Block Sun rpc/NFS
    sudo iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP

    # Deny outside packets from internet which claim to be from your loopback interface.
    sudo iptables -A INPUT -p all -s localhost  -i eth0 -j DROP

    # Save rules
    sudo iptables-save > /etc/sudo iptables/rules.v4

}

monitor_ports () { 
    # Pipes open tcp and udp ports into a less window
    sudo netstat -peltu | column -t > backup/networking/open_ports.log

    sudo $APT install nmap -y
    sudo nmap -oN backup/networking/nmap.log -p- -v localhost 
    sudo $APT purge nmap -y
}


system_sysctl_config() {

    # Add a new config file
    sudo touch /etc/sysctl.d/cybercent-networking.conf

    # Add these configs
    echo kernel.dmesg_restrict=1            | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Scored
    echo fs.suid_dumpable=0                 | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Core dumps # Scored
    echo kernel.msgmnb=65536                | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.msgmax=65536                | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.sysrq=0                     | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.maps_protect=1              | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.core_uses_pid=1             | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.shmmax=68719476736          | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.shmall=4294967296           | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.exec_shield=1               | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.panic=10                    | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.kptr_restrict=2             | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo vm.panic_on_oom=1                  | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo fs.protected_hardlinks=1           | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo fs.protected_symlinks=1            | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.randomize_va_space=2        | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Scored ASLR; 2 = full; 1 = semi; 0 = none
    echo kernel.unprivileged_userns_clone=0 | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Scored
    echo kernel.ctrl-alt-del=0              | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Scored CTRL-ALT-DEL disable

    sudo sysctl --system
}

disable_ctrl_alt_del () {
    echo 'exec shutdown -r now "Control-Alt-Delete pressed"' | sudo tee -a /etc/init/control-alt-delete.conf
    
    sudo systemctl mask ctrl-alt-del.target
    sudo systemctl daemon-reload
}

file_perms () {
    sudo chown root:root /etc/fstab     # Scored
    sudo chmod 644 /etc/fstab           # Scored
    sudo chown root:root /etc/group     # Scored
    sudo chmod 644 /etc/group           # Scored
    sudo chown root:root /etc/shadow    # Scored
    sudo chmod 400 /etc/shadow  	    # Scored	
    sudo chown root:root /etc/apache2   # Scored
    sudo chmod 755 /etc/apache2         # Scored

    sudo chmod 0600 /etc/securetty
    sudo chmod 644 /etc/crontab
    sudo chmod 640 /etc/ftpusers
    sudo chmod 440 /etc/inetd.conf
    sudo chmod 440 /etc/xinetd.conf
    sudo chmod 400 /etc/inetd.d
    sudo chmod 644 /etc/hosts.allow
    sudo chmod 440 /etc/ers
    sudo chmod 640 /etc/shadow              # Scored
    sudo chmod 600 /boot/grub/grub.cfg      # Scored
    sudo chmod 600 /etc/ssh/sshd_config     # Scored
    sudo chmod 600 /etc/gshadow-            # Scored
    sudo chmod 600 /etc/group-              # Scored
    sudo chmod 600 /etc/passwd-             # Scored

    sudo chown root:root /etc/ssh/sshd_config # Scored
    sudo chown root:root /etc/passwd-         # Scored
    sudo chown root:root /etc/group-          # Scored
    sudo chown root:root /etc/shadow          # Scored
    sudo chown root:root /etc/securetty
    sudo chown root:root /boot/grub/grub.cfg  # Scored

    sudo chmod og-rwx /boot/grub/grub.cfg  	# Scored
    sudo chown root:shadow /etc/shadow-
    sudo chmod o-rwx,g-rw /etc/shadow-
    sudo chown root:shadow /etc/gshadow-
    sudo chmod o-rwx,g-rw /etc/gshadow-

   
}





password_policies () {
    # common-password
    # Assumes you have run user_policies_install

    # Back the file up to correct directory
    cp /etc/pam.d/common-password backup/pam/common-password

    # sed -i is inplace so updates file, else prints to stdout
    sudo sed -ie "s/pam_cracklib\.so.*/pam_cracklib.so retry=3 minlen=8 difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1/" /etc/pam.d/common-password
    sudo sed -ie "s/pam_unix\.so.*/pam_unix.so obscure use_authtok try_first_pass sha512 minlen=8 remember=5/" /etc/pam.d/common-password

    # Remove any nullok (no password authentication)
    sudo sed -i 's/nullok//g' /etc/pam.d/common-password
}

login_policies () {
    # /etc/logins.def
    
    # Back the file up 
    cp /etc/login.defs backup/pam/login.defs

    # Replace the arguments
    sudo sed -ie "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\\t90/" /etc/login.defs
    sudo sed -ie "s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\\t10/" /etc/login.defs
    sudo sed -ie "s/PASS_WARN_AGE.*/PASS_WARN_AGE\\t7/" /etc/login.defs
    sudo sed -ie "s/FAILLOG_ENAB.*/FAILLOG_ENAB\\tyes/" /etc/login.defs
    sudo sed -ie "s/LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB\\tyes/" /etc/login.defs
    sudo sed -ie "s/LOG_OK_LOGINS.*/LOG_OK_LOGINS\\tyes/" /etc/login.defs
    sudo sed -ie "s/SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB\\tyes/" /etc/login.defs
    sudo sed -ie "s/SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB\\tyes/" /etc/login.defs
    sudo sed -ie "s/LOGIN_RETRIES.*/LOGIN_RETRIES\\t5/" /etc/login.defs
    sudo sed -ie "s/ENCRYPT_METHOD.*/ENCRYPT_METHOD\\tSHA512/" /etc/login.defs
    sudo sed -ie "s/LOGIN_TIMEOUT.*/LOGIN_TIMEOUT\\t60/" /etc/login.defs
    
}

account_policies () {
    # common-auth
    # Assumes you have ran user_policies_install
    
    RANBEFORE=$(grep "pam_tally2.so" /etc/pam.d/common-auth)
    if [[ -z $RANBEFORE ]]
    then 
        echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800 audit even_deny_root silent" | sudo tee -a /etc/pam.d/common-auth > /dev/null
    fi
    
    sudo sed -i 's/nullok//g' /etc/pam.d/common-auth
}


enable_autoupdate () {
    # Files necessary:
    #   NONE
    sudo $APT install -y unattended-upgrades apt-listchanges
    
    # Set automatic updates
    echo 'APT::Periodic::Update-Package-Lists "1";'             | sudo tee /etc/apt/apt.conf.d/10periodic > /dev/null
    echo 'APT::Periodic::Download-Upgradeable-Packages "1";'    | sudo tee -a /etc/apt/apt.conf.d/10periodic > /dev/null
    echo 'APT::Periodic::Unattended-Upgrade "1";'               | sudo tee -a /etc/apt/apt.conf.d/10periodic > /dev/null
    echo 'APT::Periodic::AutocleanInterval "7";'                | sudo tee -a /etc/apt/apt.conf.d/10periodic > /dev/null

    echo 'APT::Periodic::Update-Package-Lists "1";'             | sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
    echo 'APT::Periodic::Download-Upgradeable-Packages "1";'    | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
    echo 'APT::Periodic::Unattended-Upgrade "1";'               | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
    echo 'APT::Periodic::AutocleanInterval "7";'                | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
}

fix_sources_list () { 
    local ubuntu_sources="
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME main restricted\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates main restricted\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME universe\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates universe\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME multiverse\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates multiverse\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME-backports main restricted universe multiverse\n
deb http://security.ubuntu.com/ubuntu CHANGEME-security main restricted\n
deb http://security.ubuntu.com/ubuntu CHANGEME-security universe\n
deb http://security.ubuntu.com/ubuntu CHANGEME-security multiverse\n

deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME main restricted\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates main restricted\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME universe\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates universe\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME multiverse\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates multiverse\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME-backports main restricted universe multiverse\n
deb-src http://security.ubuntu.com/ubuntu CHANGEME-security main restricted\n
deb-src http://security.ubuntu.com/ubuntu CHANGEME-security universe\n
deb-src http://security.ubuntu.com/ubuntu CHANGEME-security multiverse\n
"

    local debian_sources="
deb http://deb.debian.org/debian CHANGEME main\n
deb-src http://deb.debian.org/debian CHANGEME main\n
deb http://deb.debian.org/debian-security/ CHANGEME/updates main\n
deb-src http://deb.debian.org/debian-security/ CHANGEME/updates main\n
deb http://deb.debian.org/debian CHANGEME-updates main\n
deb-src http://deb.debian.org/debian CHANGEME-updates main\n
"

    sudo cp -r /etc/apt/sources.list* backup/apt/ 
    sudo rm -f /etc/apt/sources.list 
    case $DISTRO in 
        Debian)
            echo -e $debian_sources | sed "s/ deb/deb/g; s/CHANGEME/${CODENAME}/g" | sudo tee /etc/apt/sources.list > /dev/null
            ;;
        Ubuntu)
            echo -e $ubuntu_sources | sed "s/ deb/deb/g; s/CHANGEME/${CODENAME}/g" | sudo tee /etc/apt/sources.list > /dev/null
            ;;
        *)  
            sudo cp backup/apt/sources.list /etc/apt/sources.list
            echo -e "${RED}${BOLD}Distro not recognised!\nExiting#${RESET}"
            exit 1
            ;;

    esac
}

install_necessary_packages () {
    sudo $APT install -y ufw
    sudo $APT install -y tmux
    sudo $APT install -y vim
    sudo $APT install -y unhide
    sudo $APT install -y auditd
    sudo $APT install -y psad
    sudo $APT install -y fail2ban
    sudo $APT install -y aide
    sudo $APT install -y tcpd
    sudo $APT install -y libpam-cracklib
    sudo $APT install -y tree
}

update () {
    # Files necessary:
    #   NONE
    sudo $APT update && sudo $APT upgrade -y
}

iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP         #Block Telnet
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP       #Block NFS
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP  #Block X-Windows
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP       #Block X-Windows font server
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP        #Block printer port
iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP        #Block Sun rpc/NFS
iptables -A INPUT -p all -s localhost  -i eth0 -j DROP            #Deny outside packets from internet which claim to be 

chmod 640 /etc/shadow
passwd –l root

ufw enable
ufw deny 23
ufw deny 2049
ufw deny 515
ufw deny 111
##lsof  -i -n -P
netstat -tulpn
    #media file deletion
find / -name '*.mp3' -type f -delete
find / -name '*.mov' -type f -delete
find / -name '*.mp4' -type f -delete
find / -name '*.avi' -type f -delete
find / -name '*.mpg' -type f -delete
find / -name '*.mpeg' -type f -delete
find / -name '*.flac' -type f -delete
find / -name '*.m4a' -type f -delete
find / -name '*.flv' -type f -delete
find / -name '*.ogg' -type f -delete
find /home -name '*.gif' -type f -delete
find /home -name '*.png' -type f -delete
find /home -name '*.jpg' -type f -delete
find /home -name '*.jpeg' -type f -delete
    #information gathering
hardinfo -r -f html 
chkrootkit 
lynis -c 

sudo sshd -t

passwd -l root
nmap zenmap apache2 nginx lighttpd wireshark tcpdump netcat-traditional nikto ophcrack

sudo apt remove --purge ophcrack JTR Hydra Nginx Samba Bind9 X11vnc/tightvncserver Snmp Nfs Sendmail/postfix Xinetd

echo 'install usb-storage /bin/true' >> /etc/modprobe.d/disable-usb-storage.conf

grep -qF 'multi on' && sed 's/multi/nospoof/' || echo 'nospoof on' >> /etc/host.conf

sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
find /dir -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' >> /etc/pam.d/common-auth
apt-get install libpam-cracklib
sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/' /etc/pam.d/common-password
sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

echo "blacklist firewire-core" >> /etc/modprobe.d/firewire.conf
echo "blacklist thunderbolt" >> /etc/modprobe.d/thunderbolt.conf
apt-get install auditd && auditctl -e 1

mawk -F: '$1 == "sudo"' /etc/group

mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd

mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd

mawk -F: '$2 == ""' /etc/passwd

apt-get remove .*samba.* .*smb.*
sudo apt-get remove netcat-traditional

sudo apt-get install chkrootkit rkhunter
sudo chkrootkit
sudo rkhunter --update
sudo rkhunter --check

apt-get install bum

sudo apt install fail2ban
sudo systemctl restart fail2ban.service

    # Stop every service
    # Will be restarted manually depending on critical_services.txt

sudo systemctl disable pop3
sudo systemctl disable imap 
sudo systemctl disable icmp 
sudo systemctl disable sendmail
sudo systemctl disable smbd
    # sudo systemctl disable samba-ad-dc
sudo systemctl disable nginx
sudo systemctl disable apache2
sudo systemctl disable mysql
sudo systemctl disable ssh
sudo systemctl disable vsftpd
sudo systemctl disable pure-ftpd
sudo systemctl disable proftp

sudo systemctl disable cups
sudo systemctl disable cups-browsed
sudo systemctl disable cupsd
sudo systemctl disable avahi-daemon         # Scored
sudo systemctl disabled isc-dhcp-server
sudo systemctl disabled isc-dhcp-server6
sudo systemctl disabled slapd
sudo systemctl disable autofs               # Scored
sudo systemctl disable nfs-server           # Scored
sudo systemctl disable rpcbind              # Scored
sudo systemctl disable bind9                # Scored
sudo systemctl disable dovecot
sudo systemctl disable squid
sudo systemctl disable rsync
sudo systemctl disable nis

    # $APT purge -y xserver-xorg*
sudo $apt purge -y openbsd-inetd
sudo $apt purge -y ldap-utils 
sudo $apt purge -y nis
sudo $apt purge -y talk
sudo $apt purge -y telnet # Scored

#running functions
remove_malware
check_and_reset_crontabs
disable_guests
install_necessary_packages
user_policies_install
networking_sysctl_config
system_sysctl_config
monitor_ports
disable_ctrl_alt_del
file_perms
firewall_setup
password_policies
account_policies
login_policies
enable_autoupdate
fix_sources_list

update
sudo systemctl restart sshd

