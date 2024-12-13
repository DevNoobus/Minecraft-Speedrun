# does not cover SSH

apt-get -V -y install firefox hardinfo chkrootkit iptables portsentry lynis ufw gufw sysv-rc-conf nessus clamav

apt-get -V -y install --reinstall coreutils
apt-get update
apt-get upgrade
apt-get dist-upgrade

apt-get install -y apparmor
systemctl enable apparmor
systemctl start apparmor

nano /etc/apt/sources.list #check for malicious sources
nano /etc/resolv.conf #make sure if safe, use 8.8.8.8 for name server
nano /etc/hosts #make sure is not redirecting
nano /etc/rc.local #should be empty except for 'exit 0'
nano /etc/sysctl.conf #change net.ipv4.tcp_syncookies entry from 0 to 1
nano /etc/lightdm/lightdm.conf #allow_guest=false, remove autologin allow-guest=false greeter0hide-users=true greeter-show-manual-login=true autologin-user=none
nano /etc/login.defs #FAILLOG_ENAB YES, LOG_UNKFAIL_ENAB YES. SYSLOG_SU_ENAB YES, SYSLOG_SG_ENAB YES ,PASS_MAX_DAYS 	90, PASS_MIN_DAYS 	10, PASS_WARN_AGE 7

nano /etc/ssh/sshd_config #Look for PermitRootLogin and set to no
    
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

sudo apt remove ophcrack JTR Hydra Nginx Samba Bind9





echo "PermitRootLogin no"
echo "ChallengeResponseAuthentication no"
echo "PasswordAuthentication no"
echo "UsePAM no"
echo "PermitEmptyPasswords no"

apt-get install bum

sudo apt-get install fail2ban
sudo systemctl restart fail2ban.service

