

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

nano /etc/apt/sources.list #check for malicious sources
nano /etc/resolv.conf #make sure if safe, use 8.8.8.8 for name server
nano /etc/hosts #make sure is not redirecting
nano /etc/rc.local #should be empty except for 'exit 0'
nano /etc/sysctl.conf #change net.ipv4.tcp_syncookies entry from 0 to 1

nano /etc/login.defs #FAILLOG_ENAB YES, LOG_UNKFAIL_ENAB YES. SYSLOG_SU_ENAB YES, SYSLOG_SG_ENAB YES ,PASS_MAX_DAYS 	90, PASS_MIN_DAYS 	10, PASS_WARN_AGE 7

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


# -------------------- APT functions -------------------- 
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

echo "PermitRootLogin no"
echo "ChallengeResponseAuthentication no"
echo "PasswordAuthentication no"
echo "UsePAM no"
echo "PermitEmptyPasswords no"

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
    $APT purge -y openbsd-inetd
    $APT purge -y ldap-utils 
    $APT purge -y nis
    $APT purge -y talk
    $APT purge -y telnet # Scored


sudo systemctl restart sshd

