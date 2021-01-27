#!/bin/bash
# curl -O <hidden>
RED='\033[0;31m'
CYAN='\033[1;36m'
GREEN='\033[1;32m'
NC='\033[0m' # No Color

pause() {
  # pause shouldn't change the recent return code but it would, hence capture it
  declare r=$?
  # also save the current terminal line settings (we work with tty explicitely
  # because stdin and stdout could be redirected)
  declare s=$(stty -gF "/dev/tty")
  # set default terminal characteristics
  stty sane -F "/dev/tty"
  # disable sending the terminal stop signal via Ctrl+Z to avoid freezing
  stty susp undef -F "/dev/tty"
  # make c a variable with local scope before we use it along with command read
  declare c
  # discard pending chars from tty (if any)
  while read -rst 0 c; do read -rsn 1 c; done < "/dev/tty"
  # option -q will disable the prompt and line wrapping
  if [ "${1}" = "-q" ]; then
    # wait for input, read 1 char in raw mode without printing it
    read -rsn 1 c < "/dev/tty"
  else
    # prompt the user
    echo -ne "${1:-Press any key to continue . . . }" > "/dev/tty"
    # wait for input, read 1 char in raw mode without printing it
    read -rsn 1 c < "/dev/tty"
    # wrap the line
    echo > "/dev/tty"
  fi
  # discard remnants (if any) as caused by cursor keys or other extended keys
  while read -rst 0 c; do read -rsn 1 c; done < "/dev/tty"
  # restore previous terminal line settings
  stty $s -F "/dev/tty"
  # return the cached value
  return $r
}

help_setup () {
  echo -e "  ${CYAN}Help${NC}
  --install            Installs all Programs
  --post-reboot        Check if everything works after reboot
  --update             Update System
  --essentials         Install Essential Programs
  --code-server        Install Code-Server (use with caddy, oauth2-proxy)
  --caddy              Installs Caddyserver (needs oauth2-proxy)
  --oauth2-proxy       Installs OAuth2-Proxy (needs caddy)
  --cloudcmd           Install Cloudcmd (needs oauth2-proxy)
  --vpn                Install Wireguard VPN Server
  --upgrades           Installs unattended-upgrades
  --fail2ban           Installs fail2ban
  --ufw                Configures UFW Firewall
  --hardening          Makes Server more secure
  --details            Show IPv4 Adress and DNS Records
  --cleanup            Removes Leftovers and reboots
  Copyright 2020 @ kaaaxcreators
  Licensed under GPL-3.0"
}

post_reboot() {
  systemctl is-active --quiet code-server@code-server && echo -e "${GREEN}Code-Server is running${NC}" || echo -e "${RED}WARNING!! Code-Server IS NOT RUNNING${NC}"
  systemctl is-active --quiet caddy && echo -e "${GREEN}Caddy is running${NC}" || echo -e "${RED}WARNING!! Caddy IS NOT RUNNING${NC}"
  systemctl is-active --quiet code-proxy && echo -e "${GREEN}Code Server Proxy is running${NC}" || echo -e "${RED}WARNING!! Code Server Proxy IS NOT RUNNING${NC}"
  systemctl is-active --quiet cloudcmd-proxy && echo -e "${GREEN}CloudCMD Proxy is running${NC}" || echo -e "${RED}WARNING!! CloudCMD Proxy IS NOT RUNNING${NC}"
  systemctl is-active --quiet cloudcmd && echo -e "${GREEN}CloudCMD is running${NC}" || echo -e "${RED}WARNING!! CloudCMD IS NOT RUNNING${NC}"
  systemctl is-active --quiet fail2ban && echo -e "${GREEN}fail2ban is running${NC}" || echo -e "${RED}WARNING!! fail2ban IS NOT RUNNING${NC}"
  sudo ufw status | grep -qw active && echo -e "${GREEN}UFW Firewall is running${NC}" || echo -e "${RED}WARNING!! UFW Firewall IS NOT RUNNING${NC}"
  echo "Access the Code-Server at https://code.kaaaxcreators.de"
  echo "Access the File-Server at https://file.kaaaxcreators.de"
  echo "Generate QR-Code for Wireguard with \"pivpn -qr 1\""
  echo "Default Sessionfile for Wireguard is \"/home/openvpn/configs/android.conf\""
  echo "Sessionfiles for Wireguard are located at \"/home/openvpn/configs/<name>.conf\""
}

install () {
  prepare
  update
  essentials
  code_server
  caddy
  oauth2_proxy
  cloudcmd
  vpn
  fail2ban
  ufw_init
  hardening
  details
  cleanup
}

prepare() {
  cd ~
  if ! [[ $EUID -eq 0 ]]; then
    echo -e "${RED}You MUST be root${NC}"
    exit 1
  fi
  echo -e "${BLUE}Requirements${NC}"
  echo "------------"
  echo "1. SSH Key in ~/.ssh/authorized_keys"
  echo "2. Logged in as Root"
  echo "3. Systemctl Support"
  echo "4. Full IPv4 Support"
  read -n 1 -p "All Supported? [y/n]" req
  echo ""
  if [ "${req}" = "n" ]; then
    exit 0
  fi
  echo -e "${BLUE}Password${NC}"
  echo "--------"
  echo "1. code-server password"
  echo "2. openvpn password"
  echo "3. bernd password"
  echo "4. root password"
  read codeserverpw openvpnpw berndpw rootpw
  echo ""
  echo -e "Code-Server: ${codeserverpw}"
  echo -e "OpenVPN: ${openvpnpw}"
  echo -e "bernd: ${berndpw}"
  echo -e "root: ${rootpw}"
  read -n 1 -p "Confirm? [y/n]" confirm
  echo
  if [ "${confirm}" = "n" ]; then
    exit 0
  fi
}

update() {
  echo ""
  echo -e "${BLUE}Updating System${NC}"
  echo "---------------"
  pause
  apt update
  apt upgrade -y
  apt dist-upgrade -y
  apt autoclean -y
  apt autoremove -y
}

essentials() {
  echo -e "${BLUE}Installing Essentials${NC}"
  echo "---------------------"
  pause
  apt install nano sudo screen zip unzip tar curl wget debian-keyring debian-archive-keyring apt-transport-https make build-essential -y
}

code_server () {
  echo -e "${BLUE}Installing Code-Server${NC}"
  echo ------------------------
  pause
  adduser --quiet --disabled-password --shell /bin/bash --home /home/code-server --gecos "Code-Server" code-server
  echo -e "code-server:${codeserverpw}" | chpasswd
  usermod -a -G sudo code-server
  curl -fsSL https://code-server.dev/install.sh | sh
  systemctl enable --now code-server@code-server
  echo "Waiting for code-server to start..."
  sleep 5
  systemctl is-active --quiet code-server@code-server && echo -e "${GREEN}Code-Server is running${NC}" || echo -e "${RED}WARNING!! Code-Server IS NOT RUNNING${NC}"
  echo -e "bind-addr: 127.0.0.1:8080\nauth: none\npassword: 3591103b81d5e890d21596f5\ncert: false" > /home/code-server/.config/code-server/config.yaml
  systemctl restart code-server@code-server
}

caddy () {
  echo -e "${BLUE}Installing Caddy Server${NC}"
  echo "-----------------------"
  pause
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/cfg/gpg/gpg.155B6D79CA56EA34.key' | sudo apt-key add -
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/cfg/setup/config.deb.txt?distro=debian&version=any-version' | sudo tee -a /etc/apt/sources.list.d/caddy-stable.list
  apt update
  apt install caddy
  echo -e "code.kaaaxcreators.de { \n	reverse_proxy 127.0.0.1:4180 \n} \nfile.kaaaxcreators.de { \n	reverse_proxy 127.0.0.1:4181  \n}" > /etc/caddy/Caddyfile
  sudo systemctl reload caddy
  systemctl is-active --quiet caddy && echo -e "${GREEN}Caddy is running${NC}" || echo -e "${RED}WARNING!! Caddy IS NOT RUNNING${NC}"
}

oauth2_proxy() {
  echo -e "${BLUE}Installing OAuth2_Proxy${NC}"
  echo "-----------------------"
  pause
  curl -fLO https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v6.1.1/oauth2-proxy-v6.1.1.linux-amd64.tar.gz
  tar -xf oauth2-proxy-v6.1.1.linux-amd64.tar.gz
  mkdir /opt/oauth2-proxy
  mv oauth2-proxy-v6.1.1.linux-amd64/oauth2-proxy /opt/oauth2-proxy
  rm -r oauth2-proxy-v6.1.1.linux-amd64
  rm -r oauth2-proxy-v6.1.1.linux-amd64.tar.gz
  echo -e "${BLUE}Installing Code Server Proxy${NC}"
  echo "----------------------------"
  echo -e "# Systemd service file for oauth2_proxy daemon\n\n[Unit]\nDescription=oauth2_proxy daemon service for code-server\nAfter=syslog.target network.target\n\n[Service]\nExecStart=/opt/oauth2-proxy/oauth2-proxy --email-domain=*  --github-org="kaaaxcreators"  --http-address=":4180" --upstream=http://127.0.0.1:8080/ --cookie-secret=bLK#|Z<hf9.FfHcUaCtz{W3HH()=O@IA  --cookie-secure=true --provider="github" --reverse-proxy=true --client-id=<hidden> --client-secret=<hidden>\nExecReload=/bin/kill -HUP $MAINPID\n\nKillMode=process\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/code-proxy.service
  sudo systemctl daemon-reload
  systemctl enable --now code-proxy.service
  systemctl is-active --quiet code-proxy && echo -e "${GREEN}Code Server Proxy is running${NC}" || echo -e "${RED}WARNING!! Code Server Proxy IS NOT RUNNING${NC}"
  echo -e "${BLUE}Installing CloudCMD Proxy${NC}"
  echo "-------------------------"
  echo -e "# Systemd service file for oauth2_proxy daemon\n\n[Unit]\nDescription=oauth2_proxy daemon service for cloudcmd\nAfter=syslog.target network.target\n\n[Service]\nExecStart=/opt/oauth2-proxy/oauth2-proxy --email-domain=*  --github-org="kaaaxcreators"  --http-address=":4181" --upstream=http://127.0.0.1:8000/ --cookie-secret=aLK#|Z<hf9.FfHcUaCtz{W3HH()=O@IA  --cookie-secure=true --provider="github" --reverse-proxy=true --client-id=<hidden> --client-secret=<hidden>\nExecReload=/bin/kill -HUP $MAINPID\n\nKillMode=process\nRestart=always\n\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/cloudcmd-proxy.service
  sudo systemctl daemon-reload
  systemctl enable --now cloudcmd-proxy.service
  systemctl is-active --quiet cloudcmd-proxy && echo -e "${GREEN}CloudCMD Proxy is running${NC}" || echo -e "${RED}WARNING!! CloudCMD Proxy IS NOT RUNNING${NC}"
}

cloudcmd () {
  echo -e "${BLUE}Installing CloudCMD${NC}"
  echo "-------------------"
  pause
  cd ~
  curl -sL https://deb.nodesource.com/setup_14.x -o nodesource_setup.sh
  bash nodesource_setup.sh
  apt install nodejs -y
  npm i cloudcmd -g
  npm -g config set user root
  npm i gritty -g
  echo -e "[Unit]\nDescription=Cloud Commander\nAfter=network.target\n\n[Service]\nWorkingDirectory=/usr/lib/node_modules/cloudcmd/bin/\nExecStart=/usr/bin/node cloudcmd.mjs --no-contact --no-open --no-auth --terminal --terminal-path /usr/lib/node_modules/gritty\nRestart=on-failure\n\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/cloudcmd.service
  sudo systemctl daemon-reload
  systemctl enable --now cloudcmd.service
  systemctl is-active --quiet cloudcmd && echo -e "${GREEN}CloudCMD is running${NC}" || echo -e "${RED}WARNING!! CloudCMD IS NOT RUNNING${NC}"
}

vpn () {
  echo -e "${BLUE}Installing VPN${NC}"
  echo "--------------"
  pause
  adduser --quiet --disabled-password --shell /bin/bash --home /home/openvpn --gecos "openvpn" openvpn
  echo -e "openvpn:${openvpnpw}" | chpasswd
  curl -L https://install.pivpn.io | bash
  pivpn add -n android
}

unattended_upgrades () {
  echo -e "${BLUE}Installing unattended-upgrades${NC}" # Can be installed with PiVPN
  echo "------------------------------"
  pause
  sudo apt-get install unattended-upgrades
}

fail2ban () {
  echo -e "${BLUE}Installing fail2ban${NC}"
  echo "-------------------"
  pause
  apt-get install fail2ban -y
  cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
  systemctl restart fail2ban
  echo "Waiting for fail2ban to start..."
  sleep 5
  systemctl is-active --quiet fail2ban && echo -e "${GREEN}fail2ban is running${NC}" || echo -e "${RED}WARNING!! fail2ban IS NOT RUNNING${NC}"
  JAILS=`fail2ban-client status | grep "Jail list" | sed -E 's/^[^:]+:[ \t]+//' | sed 's/,//g'`
  for JAIL in $JAILS
  do
    fail2ban-client status $JAIL
  done
}

ufw_init () {
  echo -e "${BLUE}UFW Firewall Setup${NC}"
  echo "------------------"
  pause
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow ssh
  sudo ufw allow 51820
  sudo ufw allow http
  sudo ufw allow https
  sudo ufw --force enable
  echo "Open Ports (IPv4 & IPv6)"
  echo "[ 1] 22/tcp SSH"
  echo "[ 2] 51820 Wireguard VPN"
  echo "[ 3] 80/tcp HTTP"
  echo "[ 4] 443/tcp HTTPS"
}

hardening() {
  echo -e "${BLUE}Hardening System${NC}"
  echo "----------------"
  pause
  cp /etc/ssh/sshd_config /root/.ssh/sshd_config.bak
  sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
  echo "SSH Root Login disabled! Creating User Account"
  adduser --quiet --disabled-password --shell /bin/bash --home /home/bernd --gecos "Bernd" bernd
  echo -e "bernd:${berndpw}" | chpasswd
  usermod -a -G sudo bernd
  echo "Copying SSH Key"
  mkdir /home/bernd/.ssh
  chown bernd.bernd /home/bernd/.ssh
  chmod 700 ~/.ssh
  touch /home/bernd/.ssh/authorized_keys
  chown bernd.bernd /home/bernd/.ssh/authorized_keys
  chmod 600 /home/bernd/.ssh/authorized_keys
  cat ~/.ssh/authorized_keys >> /home/bernd/.ssh/authorized_keys
  echo "Copying Script for Post-Reboot"
  cp setup.sh /home/bernd/setup.sh
  chmod +x /home/bernd/setup.sh
  chown bernd.bernd /home/bernd/setup.sh
  echo "Changing Rootpassword for switching User"
  echo "root:${rootpw}" | chpasswd
  sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
  sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
  sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
  sudo service sshd reload
}

details () {
  echo -e "${BLUE}Public IP${NC}"
  echo "---------"
  ip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
  echo -e "A code.kaaaxcreators.de ${ip}"
  echo -e "A file.kaaaxcreators.de ${ip}"
  echo "User Data"
  echo "---------"
  echo -e "bernd: ${berndpw} sudo"
  echo -e "openvpn: ${openvpnpw}"
  echo -e "code-server: ${codeserverpw} sudo"
  echo -e "root: ${rootpw} root"
}

cleanup () {
  echo "Cleaning"
  echo "--------"
  apt autoclean -y
  apt autoremove -y
  echo -e "${CYAN}Login with bernd and your private key${NC}"
  echo -e "Run${CYAN}\"./setup.sh --post-reboot\"${NC} after reboot"
  pause "Press any key to reboot..."
  reboot
}

case "$1" in
  --install)   install;;
  --post-reboot)   post_reboot;;
  --update)   update;;
  --essentials)   essentials;;
  --code-server)   code_server;;
  --caddy)   caddy;;
  --oauth2_proxy)   oauth2_proxy;;
  --cloudcmd)   cloudcmd;;
  --vpn)   vpn;;
  --upgrades)   unattended_upgrades;;
  --fail2ban)   fail2ban;;
  --ufw)   ufw_init;;
  --hardening)   hardening;;
  --details)   details;;
  --cleanup)   details;;
  "")   help_setup;;
esac