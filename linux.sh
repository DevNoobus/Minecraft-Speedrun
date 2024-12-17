# ------------------------ Basic Commands  -------------------------- #

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


# ----------------------------- APParmor -------------------------------------

apparmor () {
    sudo $APT install -y apparmor-utils
    sudo aa-enforce /etc/apparmor.d/*
}


# -------------------- Service functions --------------------
service_ssh () {
    # Unique config file each time
    sudo cp /etc/ssh/sshd_config backup/services/sshd_config_`date +%s`.bak

    sudo ufw allow ssh 

    # sshd_config 
    echo "Protocol 2" | sudo tee /etc/ssh/sshd_config > /dev/null

    echo "PermitRootLogin no"      | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "LoginGraceTime 2m"       | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "X11Forwarding no"         | sudo tee -a /etc/ssh/sshd_config > /dev/null 
    echo "AllowTcpForwarding no"    | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "AllowAgentForwarding no"  | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "UsePAM yes"                   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PasswordAuthentication no"    | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "HostBasedAuthentication no"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    # echo "RhostsRSAAuthentication no"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PubkeyAuthentication yes"     | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "IgnoreRhosts yes"             | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "StrictModes yes"              | sudo tee -a /etc/ssh/sshd_config > /dev/null

    # echo "UsePrivilegeSeparation yes"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PrintLastLog no"              | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PermitUserEnvironment no"     | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "SyslogFacility AUTH"          | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "LogLevel VERBOSE" | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "MaxAuthTries 3"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "MaxStartups 2"    | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "ChallengeResponseAuthentication no"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "KerberosAuthentication no"            | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "GSSAPIAuthentication no"              | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "UseDNS no"        | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PermitTunnel no"  | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "ClientAliveInterval 300"  | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "ClientAliveCountMax 0"    | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "Banner /etc/issue.net" | sudo tee -a /etc/ssh/sshd_config > /dev/null

    # New welcome banner
    echo "Cyber Centurion" | sudo tee /etc/issue.net > /dev/null

    GOODSYNTAX=$(sudo sshd -t)
    if [[ ! -z $GOODSYNTAX ]]
    then
        echo "${RED}Sshd config has some faults, please check script or ${BOLD}/etc/ssh/sshd_config${RESET}"
        read -rp ""
    fi

    sudo service ssh restart
}

service_samba () {
    # Unique config file each time
    sudo cp /etc/samba/smb.conf backup/services/smb_conf_`date +%s`.bak

    sudo ufw allow samba

    # smb.conf 
    echo "restrict anonymous = 2"       | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "encrypt passwords = True"     | sudo tee -a /etc/samba/smb.conf > /dev/null # Idk which one it takes
    echo "encrypt passwords = yes"      | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "read only = Yes"              | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "ntlm auth = no"               | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "obey pam restrictions = yes"  | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "server signing = mandatory"   | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "smb encrypt = mandatory"      | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "min protocol = SMB2"          | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "protocol = SMB2"              | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "guest ok = no"                | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "max log size = 24"            | sudo tee -a /etc/samba/smb.conf > /dev/null


    echo "${YELLOW}Please read the samba file ${BOLD}/etc/samba/smb.conf${RESET}${YELLOW} as well and check its contents${RESET}"

    sudo service smbd restart 
}

service_vsftpd () {
    # Unique config file each time
    local config_file="/etc/vsftpd.conf"
    if [[ ! -f $config_file ]]
    then 
        config_file="/etc/vsftpd/vsftpd.conf"
    fi 

    sudo cp $config_file backup/services/vsftpd_conf_`date +%s`.bak

    sudo ufw allow ftp 
    sudo ufw allow 20

    # vsftpd.conf

    # Jail users to home directory (user will need a home dir to exist)
    echo "chroot_local_user=YES"                        | sudo tee $config_file > /dev/null
    echo "chroot_list_enable=YES"                       | sudo tee -a $config_file > /dev/null
    echo "chroot_list_file=/etc/vsftpd.chroot_list"     | sudo tee -a $config_file > /dev/null
    echo "allow_writeable_chroot=YES"                   | sudo tee -a $config_file > /dev/null # Only enable if you want files to be editable

    # Allow or deny users
    echo "userlist_enable=YES"                  | sudo tee -a $config_file > /dev/null
    echo "userlist_file=/etc/vsftpd.userlist"   | sudo tee -a $config_file > /dev/null
    echo "userlist_deny=NO"                     | sudo tee -a $config_file > /dev/null

    # General config
    echo "anonymous_enable=NO"          | sudo tee -a $config_file > /dev/null # disable  anonymous login
    echo "local_enable=YES"             | sudo tee -a $config_file > /dev/null # permit local logins
    echo "write_enable=YES"             | sudo tee -a $config_file > /dev/null # enable FTP commands which change the filesystem
    echo "local_umask=022"              | sudo tee -a $config_file > /dev/null # value of umask for file creation for local users
    echo "dirmessage_enable=YES"        | sudo tee -a $config_file > /dev/null # enable showing of messages when users first enter a new directory
    echo "xferlog_enable=YES"           | sudo tee -a $config_file > /dev/null # a log file will be maintained detailing uploads and downloads
    echo "connect_from_port_20=YES"     | sudo tee -a $config_file > /dev/null # use port 20 (ftp-data) on the server machine for PORT style connections
    echo "xferlog_std_format=YES"       | sudo tee -a $config_file > /dev/null # keep standard log file format
    echo "listen=NO"                    | sudo tee -a $config_file > /dev/null # prevent vsftpd from running in standalone mode
    echo "listen_ipv6=YES"              | sudo tee -a $config_file > /dev/null # vsftpd will listen on an IPv6 socket instead of an IPv4 one
    echo "pam_service_name=vsftpd"      | sudo tee -a $config_file > /dev/null # name of the PAM service vsftpd will use
    echo "userlist_enable=YES"          | sudo tee -a $config_file > /dev/null # enable vsftpd to load a list of usernames
    echo "tcp_wrappers=YES"             | sudo tee -a $config_file > /dev/null # turn on tcp wrappers

    echo "ascii_upload_enable=NO"   | sudo tee -a $config_file > /dev/null 
    echo "ascii_download_enable=NO" | sudo tee -a $config_file > /dev/null 

    sudo service vsftpd restart 
}

service_pureftpd () {

    sudo cp /etc/pure-ftpd/pure-ftpd.conf backup/services/pure-ftpd_conf_`date +%s`.bak
    # Unique config file each time
    sudo ufw allow ftp 
    sudo ufw allow 20

    # pure-ftpd.conf

    echo "ChrootEveryone yes"           | sudo tee /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "NoAnonymous yes"              | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AnonymousOnly no"             | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AnonymousCanCreateDirs no"    | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AnonymousCantUpload yes"      | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AllowUserFXP no"              | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AllowAnonymousFXP no"         | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "DisplayDotFiles yes"          | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "ProhibitDotFilesWrite yes"    | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "ProhibitDotFilesRead no"      | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "DontResolve yes"              | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "VerboseLog yes"               | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "SyslogFacility ftp"           | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "PAMAuthenticate yes"          | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "UnixAuthenticate no"          | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "MaxClientsNumber 50"          | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "LimitRecursion 500 8"         | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "MaxClientsPerIp 3"            | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "MaxIdleTime 10"               | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "MaxLoad 4"                    | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "IPV4Only yes"                 | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "TLS 2"                        | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "Umask 133:022"                | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "Daemonize yes"                | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "NoChmod yes"                  | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    # echo "KeepAllFiles yes"             | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "CreateHomeDir yes"            | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AutoRename yes"               | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AntiWarez yes"                | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "CustomerProof yes"            | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    sudo service pure-ftpd restart 
}

service_proftpd () {
    # Unique config file each time
    sudo cp /etc/proftpd/proftpd.conf backup/services/proftpd_conf_`date +%s`.bak

    sudo ufw allow ftp 
    sudo ufw allow 20

    # proftpd.conf
    echo "Deny Filter \\*.*/"           | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "DelayEngine on"               | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "UseLastLog on"                | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "ServerIdent off"              | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "IdentLookups off"             | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "TLSEngine on"                 | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "TLSProtocol SSLv23"           | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "TLSRequired on"               | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "UseReverseDNS on"             | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "UseIPv6 off"                  | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo 'AllowFilter "^[a-zA-Z0-9 ,]*$"'| sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "DeferWelcome on"              | sudo tee -a /etc/protpd/proftpd.conf > /dev/null

    sudo service proftpd restart 
}

service_apache2 () {
    # Unique config file each time
    sudo cp /etc/apache2/apache2.conf backup/services/apache2_conf_`date +%s`.bak
    sudo cp /etc/apache2/conf-available/security.conf backup/services/apache2_security_conf_`date +%s`.bak

    sudo ufw allow apache
    sudo ufw allow https 
    sudo ufw allow http

    # Mod security  & enabling/disabling modules
    sudo $APT install libapache2-mod-security2 -y

    sudo a2enmod userdir
    sudo a2enmod headers
    sudo a2enmod rewrite
    sudo a2dismod imap
    sudo a2dismod include
    sudo a2dismod info
    sudo a2dismod userdir
    echo "Yes, do as I say!" | sudo a2dismod autoindex

    # Ask to remove default index.html
    local answer=""
    echo -n "${CYAN}Remove default index.html [${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
    read -rp "" answer
    case $answer in 
        y|Y)
            echo "" | sudo tee /var/www/html/index.html
            ;;
        n|N)
            ;; # Do nothing
    esac

    # apache.conf
    echo "HostnameLookups Off"              | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "LogLevel warn"                    | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "ServerTokens Prod"                | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "ServerSignature Off"              | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "Options all -Indexes"             | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "Header unset ETag"                | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "Header always unset X-Powered-By" | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "FileETag None"                    | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "TraceEnable off"                  | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "Timeout 60"                       | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    
    echo "RewriteEngine On"                         | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo 'RewriteCond %{THE_REQUEST} !HTTP/1\.1$'   | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo 'RewriteRule .* - [F]'                     | sudo tee -a /etc/apache2/apache2.conf > /dev/null

    echo '<IfModule mod_headers.c>'                         | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo '    Header set X-XSS-Protection 1;'               | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo '</IfModule>'                                      | sudo tee -a /etc/apache2/apache2.conf > /dev/null

    # Secure /
    echo "<Directory />"            | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Options -Indexes"     | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    AllowOverride None"   | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Order Deny,Allow"     | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Options None"         | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Deny from all"        | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "</Directory>"             | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    
    # Secure /var/www/html
    echo "<Directory /var/www/html>"    | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Options -Indexes"         | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "</Directory>"                 | sudo tee -a /etc/apache2/apache2.conf > /dev/null

    # security.conf
    # Enable HTTPOnly and Secure Flags
    echo 'Header edit Set-Cookie ^(.*)\$ \$1;HttpOnly;Secure'                                   | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # Clickjacking Attack Protection
    echo 'Header always append X-Frame-Options SAMEORIGIN'                                      | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # XSS Protection
    echo 'Header set X-XSS-Protection "1; mode=block"'                                          | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # Enforce secure connections to the server
    echo 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'    | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null  

    # MIME sniffing Protection
    echo 'Header set X-Content-Type-Options: "nosniff"'                                         | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # Prevent Cross-site scripting and injections
    echo 'Header set Content-Security-Policy "default-src '"'self'"';"'                         | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

	# Secure root directory
    echo "<Directory />"            | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Options -Indexes"       | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  AllowOverride None"     | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Order Deny,Allow"       | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Deny from all"          | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "</Directory>"             | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # Secure html directory
    echo "<Directory /var/www/html>"        | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Options -Indexes -Includes"     | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  AllowOverride None"             | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Order Allow,Deny"               | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Allow from All"                 | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "</Directory>"                     | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # ssl.conf
    # TLS only
    sudo sed -i "s/SSLProtocol.*/SSLProtocol –ALL +TLSv1 +TLSv1.1 +TLSv1.2/" /etc/apache2/mods-available/ssl.conf
    # Stronger cipher suite
    sudo sed -i "s/SSLCipherSuite.*/SSLCipherSuite HIGH:\!MEDIUM:\!aNULL:\!MD5:\!RC4/" /etc/apache2/mods-available/ssl.conf

    sudo chown -R root:root /etc/apache2
    sudo chown -R root:root /etc/apache 2> /dev/null

    sudo service apache2 restart 
}

service_php () {
    local PHPCONFIG=/etc/php5/apache2/php.ini
    if [[ ! -f $PHPCONFIG ]]
    then 
        echo "${RED}Php.ini does not exist at ${PHPCONFIG}${RESET}"
        echo -n "${YELLOW}Please input the new location: ${RESET}"
        read -rp "" PHPCONFIG 
        if [[ ! -f $PHPCONFIG ]]
        then
            echo "${RED}${BOLD}The file you have entered does not exist, skipping php ... ${RESET}"
            return 1
        fi
    fi

    # Unique config file each time
    sudo cp $PHPCONFIG backup/services/php_ini_`date +%s`.bak

    # Safe mode
    echo 'sql.safe_mode = On'   | sudo tee -a $PHPCONFIG
    echo 'safe_mode = On'       | sudo tee -a $PHPCONFIG
    echo 'safe_mode_gid = On'   | sudo tee -a $PHPCONFIG

    # Disable Global variables
    echo 'register_globals = Off' | sudo tee -a $PHPCONFIG

    # Disable tracking, HTML, and display errors
    sudo sed -i "s/^;\?track_errors.*/track_errors = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?html_errors.*/html_errors = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?display_errors.*/display_errors = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?expose_php.*/expose_php = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?mail\.add_x_header.*/mail\.add_x_header = Off/" $PHPCONFIG

    # Disable Remote File Includes
    sudo sed -i "s/^;\?allow_url_fopen.*/allow_url_fopen = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?allow_url_include.*/allow_url_include = Off/" $PHPCONFIG

    # Restrict File Uploads
    sudo sed -i "s/^;\?file_uploads.*/file_uploads = Off/" $PHPCONFIG

    # Control POST/Upload size
    sudo sed -i "s/^;\?post_max_size.*/post_max_size = 1K/" $PHPCONFIG
    sudo sed -i "s/^;\?upload_max_filesize.*/upload_max_filesize = 2M/" $PHPCONFIG

    # Protect sessions
    sudo sed -i "s/^;\?session\.cookie_httponly.*/session\.cookie_httponly = 1/" $PHPCONFIG

    # General
    echo "magic_quotes_gpc = Off" | sudo tee -a $PHPCONFIG
    sudo sed -i "s/^;\?session\.use_strict_mode.*/session\.use_strict_mode = On/" $PHPCONFIG

    # sudo sed -i 
    sudo sed -i "s/^;\?disable_functions.*/disable_functions = php_uname, getmyuid, getmypid, passthru, leak, listen, diskfreespace, tmpfile, link, ignore_user_abord, shell_exec, dl, set_time_limit, exec, system, highlight_file, source, show_source, fpaththru, virtual, posix_ctermid, posix_getcwd, posix_getegid, posix_geteuid, posix_getgid, posix_getgrgid, posix_getgrnam, posix_getgroups, posix_getlogin, posix_getpgid, posix_getpgrp, posix_getpid, posix, _getppid, posix_getpwnam, posix_getpwuid, posix_getrlimit, posix_getsid, posix_getuid, posix_isatty, posix_kill, posix_mkfifo, posix_setegid, posix_seteuid, posix_setgid, posix_setpgid, posix_setsid, posix_setuid, posix_times, posix_ttyname, posix_uname, proc_open, proc_close, proc_get_status, proc_nice, proc_terminate, phpinfo/" $PHPCONFIG
    # disable_functions = exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec 

    sudo sed -i "s/^;\?max_execution_time.*/max_execution_time = 30/" $PHPCONFIG
    sudo sed -i "s/^;\?max_input_time.*/max_input_time = 30/" $PHPCONFIG
    sudo sed -i "s/^;\?memory_limit.*/memory_limit = 40M/" $PHPCONFIG
    # open_basedir = "/home/user/public_html" # -> correct html base dir 


    echo "${YELLOW}Checkout the PHP section in the guide, install suhosin${RESET}"
    sudo service apache2 restart
}

service_nginx () {
    # Unique config file each time
    sudo cp /etc/nginx/nginx.conf backup/services/nginx_conf_`date +%s`.bak
    sudo cp /etc/nginx/sites-available/default backup/services/nginx_default_`date +%s`.bak

    sudo ufw allow 'Nginx Full'
    sudo ufw allow https 
    sudo ufw allow http

    # Ask to remove default index.html
    local answer=""
    echo -n "${CYAN}Remove default index.html [${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
    read -rp "" answer
    case $answer in 
        y|Y)
            echo "" | sudo tee /var/www/html/index.html
            ;;
        n|N)
            ;; # Do nothing
    esac

    # nginx.conf
    ETAGEXISTS=$(grep -i etag /etc/nginx/nginx.conf)

    if [[ -z $ETAGEXISTS ]]
    then
        sudo sed -ie "s/#\?\\s*server_tokens.*/server_tokens off;\n\tetag off;/g" /etc/nginx/nginx.conf
    else
        sudo sed -ie "s/#\?\\s*server_tokens.*/server_tokens off;/g" /etc/nginx/nginx.conf
        sudo sed -ie "s/#\?\\s*etag.*/etag off;/g" /etc/nginx/nginx.conf
    fi

    # Use strong cipher suites
    sudo sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;/" /etc/nginx/nginx.conf

    # Set ssl session timeout
    sudo sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf

    # Set ssl session cache
    sudo sed -i "s/ssl_session_timeout 5m;/ssl_session_cache shared:SSL:10m;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf

    # sites-available/default
    # Enable HttpOnly and Secure flags
    sudo sed -i "s|^\s*try_files \\\$uri \\\$uri/ =404;|try_files \\\$uri \\\$uri/ =404;\nproxy_cookie_path / \"/; secure; HttpOnly\";|" /etc/nginx/sites-available/default

    # Clickjacking Attack Protection
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Frame-Options DENY;|" /etc/nginx/sites-available/default

    # XSS Protection
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-XSS-Protection \"1; mode=block\";|" /etc/nginx/sites-available/default

    # Enforce secure connections to the server
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubdomains;\";|" /etc/nginx/sites-available/default

    # MIME sniffing Protection
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Content-Type-Options nosniff;|" /etc/nginx/sites-available/default

    # Prevent Cross-site scripting and injections
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Content-Security-Policy \"default-src 'self';\";|" /etc/nginx/sites-available/default

    # Set X-Robots-Tag
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Robots-Tag none;|" /etc/nginx/sites-available/default

    sudo service nginx restart 
}


service_mysql () {
    # Unique config file each time
    sudo cp $PHPCONFIG backup/services/php_ini_`date +%s`.bak

    sudo ufw allow mysql 

    echo "${}[*] Setup mysql by running 'sudo mysql_secure_installation' ${RESET}"
    read -rp "Press <enter> when you are done" 

    #Disables LOCAL INFILE
    echo "local-infile=0" | sudo tee -a /etc/mysql/my.cnf

    #Lowers database privileges
    echo "skip-show-database" | sudo tee -a /etc/mysql/my.cnf

    # Disable remote access
    echo "bind-address=127.0.0.1" | sudo tee -a /etc/mysql/my.cnf
    sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf

    #Disables symbolic links
    echo "symbolic-links=0" | sudo tee -a /etc/mysql/my.cnf

    #Sets password expiration
    echo "default_password_lifetime = 90" | sudo tee -a /etc/mysql/my.cnf

    #Sets root account password
    echo "[mysqladmin]" | sudo tee -a /etc/mysql/my.cnf
    echo "user = root" | sudo tee -a /etc/mysql/my.cnf
    echo "password = CyberPatriot1!" | sudo tee -a /etc/mysql/my.cnf

    #Sets packet restrictions
    echo "key_buffer_size         = 16M" | sudo tee -a /etc/mysql/my.cnf
    echo "max_allowed_packet      = 16M" | sudo tee -a /etc/mysql/my.cnf

    sudo service mysql restart
}


# ----------------------------- malware removal ----------------------------------------
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
# --------------------------------------------------- disabling guests -----------------------------------
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

# ----------------------------------------------- user policy for hardening -----------------------------------
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

#------------------------------------ web browser config -----------------------
firefox_config () {
    echo 'pref("general.config.filename", "mozilla.cfg");' | sudo tee -a /usr/lib/firefox/defaults/pref/local-settings.js > /dev/null

    local config='lockPref("browser.safebrowsing.downloads.enabled", true);\n
    lockPref("dom.disable_open_during_load", true);\n
    lockPref("xpinstall.whitelist.required", true);\n
    lockPref("xpinstall.signatures.required", true);\n
    lockPref("app.update.enabled", true);\n
    lockPref("app.update.auto", true);\n
    lockPref("privacy.donottrackheader.enabled", true);\n
    lockPref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", true);\n
    lockPref("browser.safebrowsing.downloads.remote.block_uncommon", true);\n
    lockPref("browser.safebrowsing.malware.enabled", true);\n
    lockPref("browser.safebrowsing.phishing.enabled", true);\n'
    echo -e $config | sed "s/^ //g" | sudo tee -a /usr/lib/firefox/mozilla.cfg > /dev/null
}

# ---------------------- monitors ports --------------------------

monitor_ports () { 
    # Pipes open tcp and udp ports into a less window
    sudo netstat -peltu | column -t > backup/networking/open_ports.log

    sudo $APT install nmap -y
    sudo nmap -oN backup/networking/nmap.log -p- -v localhost 
    sudo $APT purge nmap -y
}

# -------------------- systctl config --------------------------
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


# --------- disabling control alt delete ---------------------------
disable_ctrl_alt_del () {
    echo 'exec shutdown -r now "Control-Alt-Delete pressed"' | sudo tee -a /etc/init/control-alt-delete.conf
    
    sudo systemctl mask ctrl-alt-del.target
    sudo systemctl daemon-reload
}
#--------------- file permission ------------------------------------
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




#------------------------------ password policies ----------------------------------
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


# --------------------------policies -------------------------------
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

# ---- ----------------------------app cleanup-------------------------------------

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
#-------------------------------------- end commands ------------------------------------
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
delete_media () {
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
apparmor
file_perms

firewall_setup
password_policies
account_policies
login_policies
enable_autoupdate
fix_sources_list

update
sudo systemctl restart sshd

