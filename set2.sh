#!/bin/bash
#
#  Linux Security Audit Dashboard  –  same logic, refreshed look
#

# ───────────────────────── COLOUR PALETTE ─────────────────────────
HDR='\033[38;5;111m'     # Sky-blue section headers
ACC='\033[38;5;141m'     # Purple accents / banners
OK='\033[38;5;82m'       # Lime success
WARN='\033[38;5;214m'    # Amber warning
ERR='\033[38;5;196m'     # Lava-red error
TXT='\033[0;37m'         # Light-grey text
NC='\033[0m'             # Reset

# ───────────────────────── BANNER ─────────────────────────
banner() {
  echo -e "${ACC}"
  printf '╔════════════════════════════════════════════════════════════╗\n'
  printf '║%*s║\n' 58 " "
  printf '║%*sLinux Security Audit Dashboard%*s║\n' 15 " " 14 " "
  printf '╚════════════════════════════════════════════════════════════╝\n'
  echo -e "${NC}"
}

# ───────────────────────── SECTION MACRO ─────────────────────────
section() {  # section "TITLE"
  echo -e "${HDR}\n───· $1 ·────────────────────────────────────────────${NC}"
}

# ───────────────────────── AUDIT FUNCTIONS ─────────────────────────
user_and_group_audit() {
  section "USER & GROUP AUDIT"
  echo -e "${OK}[1] Human Users (UID ≥ 1000 with valid shell):${NC}"
  awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)/ { print "  • " $1 }' /etc/passwd
  echo
  echo -e "${OK}[2] Groups (GID ≥ 1000 and not nogroup):${NC}"
  awk -F: '$3 >= 1000 && $1 != "nogroup" { print "  • " $1 }' /etc/group
  echo
  echo -e "${WARN}[3] Non-root UID 0 Users:${NC}"
  awk -F: '($3 == 0 && $1 != "root"){print "  ⚠  "$1}' /etc/passwd
  echo
  echo -e "${WARN}[4] Users Without Passwords:${NC}"
  sudo awk -F: '
    NR==FNR && $3 >= 1000 && $7 !~ /(nologin|false)/{users[$1]=$7;next}
    FNR!=NR && ($1 in users) && ($2==""||$2~/^\*|^!/){
        printf "  ⚠  %s (shell: %s) has NO password\n",$1,users[$1]
    }' /etc/passwd /etc/shadow
}

perm_check() {
  section "FILE & DIRECTORY PERMISSIONS"
  echo -e "${OK}[1] World-writable Files:${NC}"
  find / -xdev -type f -perm -0002 -exec echo "  ✖  {}" \; 2>/dev/null
  echo -e "${OK}[2] World-writable Directories:${NC}"
  find / -xdev -type d -perm -0002 -exec echo "  ✖  {}" \; 2>/dev/null

  echo -e "${OK}[3] .ssh Permissions (human users):${NC}"
  awk -F: '$3>=1000 && $7!~/(false|nologin)/{print $1,$6}' /etc/passwd |
  while read user home; do
    ssh_dir="$home/.ssh"; echo -e "\n  $user:"
    if [ -d "$ssh_dir" ]; then
      dir_perm=$(stat -c "%a" "$ssh_dir")
      [ "$dir_perm" -ne 700 ] && \
        echo -e "    ${ERR}✖ .ssh dir perm $dir_perm (should be 700)${NC}" || \
        echo -e "    ${OK}✔ dir perm $dir_perm${NC}"
      for f in authorized_keys id_rsa id_rsa.pub; do
        fp="$ssh_dir/$f"; [ ! -e "$fp" ] && \
          echo -e "    ${WARN}⚠ $f missing${NC}" && continue
        p=$(stat -c "%a" "$fp")
        exp=600; [[ $f == *.pub ]] && exp=644
        [ "$p" -ne "$exp" ] && \
          echo -e "    ${ERR}✖ $f perm $p (should $exp)${NC}" || \
          echo -e "    ${OK}✔ $f perm $p${NC}"
      done
    else
      echo -e "    ${ERR}✖ .ssh dir not found${NC}"
    fi
  done

  echo -e "${OK}[4] SUID / SGID Executables:${NC}"
  echo "    — SUID —"
  find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null
  echo -e "\n    — SGID —"
  find / -perm -2000 -type f -exec ls -l {} \; 2>/dev/null
}

service_audit() {
  section "SERVICE AUDIT"
  AUTHORIZED_SERVICES=("sshd" "cron" "rsyslog" "networking" "firewalld" "iptables")
  CRITICAL_SERVICES=("sshd" "iptables" "firewalld")
  echo -e "${OK}[1] Running services:${NC}"
  RUNNING_SERVICES=($(systemctl list-units --type=service --state=running 2>/dev/null |
                     awk '{print $1}' | sed 's/\.service//' ))
  printf '  • %s\n' "${RUNNING_SERVICES[@]}"
  echo
  echo -e "${WARN}[2] Unexpected services:${NC}"
  for svc in "${RUNNING_SERVICES[@]}"; do
    [[ " ${AUTHORIZED_SERVICES[*]} " =~ " $svc " ]] || echo -e "  ${ERR}✖ $svc${NC}"
  done
  echo
  echo -e "${OK}[3] Critical services:${NC}"
  for crit in "${CRITICAL_SERVICES[@]}"; do
    systemctl is-active --quiet "$crit" && \
      echo -e "  ${OK}✔ $crit running${NC}" || \
      echo -e "  ${ERR}✖ $crit NOT running${NC}"
  done
  echo
  echo -e "${OK}[4] SSH Config:${NC}"
  SSHD_CONFIG="/etc/ssh/sshd_config"
  if [ -f "$SSHD_CONFIG" ]; then
    grep -E "^Port|^PermitRootLogin|^PasswordAuthentication" "$SSHD_CONFIG"
    SSH_PORT=$(grep "^Port" "$SSHD_CONFIG" | awk '{print $2}')
    [ -z "$SSH_PORT" ] && SSH_PORT=22
    if ss -tuln 2>/dev/null | grep -q ":$SSH_PORT"; then
      echo -e "  ${OK}✔ SSH listening on $SSH_PORT${NC}"
    else
      echo -e "  ${ERR}✖ SSH not listening on $SSH_PORT${NC}"
    fi
  else
    echo -e "  ${ERR}✖ SSH config not found${NC}"
  fi
  echo
  echo -e "${OK}[5] All listening ports:${NC}"
  ss -tuln
  echo
  echo -e "${WARN}[6] Unusual open ports:${NC}"
  LISTEN_PORTS=$(ss -tuln 2>/dev/null | awk '/LISTEN/ {split($5,a,":"); print a[length(a)]}' | sort -n | uniq)
  STANDARD_PORTS=(22 53 80 123 443 25 110 143 587 993 995)
  for port in $LISTEN_PORTS; do
    [[ " ${STANDARD_PORTS[*]} " =~ " $port " ]] || \
      echo -e "  ${WARN}⚠ Port $port${NC}"
  done
}

firewall_audit() {
  section "FIREWALL STATUS"
  if systemctl is-active --quiet firewalld; then
    echo -e "${OK}✔ firewalld active${NC}"
    firewall-cmd --list-all
  elif systemctl is-active --quiet ufw; then
    echo -e "${OK}✔ ufw active${NC}"
    ufw status verbose
  elif command -v iptables &>/dev/null && iptables -L -n | grep -q ACCEPT; then
    echo -e "${OK}✔ iptables active${NC}"
    iptables -L -n -v
  else
    echo -e "${ERR}✖ No firewall active${NC}"
  fi
  echo -e "\n${HDR}───· OPEN PORTS & SERVICES ·────────────────────────────${NC}"
  if command -v ss &>/dev/null; then
    ss -tulnp
  elif command -v netstat &>/dev/null; then
    netstat -tulnp
  else
    echo -e "${ERR}✖ Neither ss nor netstat available${NC}"
  fi
  echo -e "\n${HDR}───· SSH STATUS ·────────────────────────────${NC}"
  if systemctl is-active --quiet sshd; then
    echo -e "${OK}✔ SSH active${NC}"
    sshd -T | grep -Ei 'port|permitrootlogin|passwordauthentication'
  else
    echo -e "${ERR}✖ SSH not running${NC}"
  fi
  echo -e "\n${HDR}───· IP FORWARDING ·─────────────────────────${NC}"
  ip_forward=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
  [ "$ip_forward" -eq 1 ] && \
    echo -e "${ERR}✖ IP forwarding ENABLED${NC}" || \
    echo -e "${OK}✔ IP forwarding disabled${NC}"
}

network_audit() {
  section "NETWORK OVERVIEW"
  public_ip=$(curl -s ifconfig.me)
  echo -e "${TXT}Public IP: $public_ip${NC}"
  for ip in $(hostname -I); do echo -e "  Private: $ip"; done
  echo -e "\n${HDR}───· SSH PORT EXPOSURE ·────────────────────────${NC}"
  echo -e "${TXT}Ports/interfaces where SSH is listening:${NC}"
  ss -tnlp | grep ':22 ' | while read -r line; do
    ip=$(echo "$line" | awk '{print $4}' | cut -d':' -f1)
    if [[ "$ip" == "0.0.0.0" || "$ip" == "::" ]]; then
      echo -e "  ${ERR}⚠ SSH on all interfaces${NC}"
    elif [[ "$ip" =~ ^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
      echo -e "  ${OK}✔ Private IP $ip${NC}"
    else
      echo -e "  ${WARN}⚠ SSH on public IP $ip${NC}"
    fi
  done
}

update_audit() {
  section "SECURITY UPDATES & PATCHING"
  echo -e "\n${TXT}Checking connectivity...${NC}"
  ping -c 2 archive.ubuntu.com >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo -e "${ERR}✖ Cannot reach archive.ubuntu.com${NC}"
    return
  fi
  echo -e "\n${TXT}Updating package lists...${NC}"
  sudo apt update -qq
  echo -e "\n${TXT}Available security updates:${NC}"
  sudo apt list --upgradable 2>/dev/null | grep -i security || echo "  None"
  echo -e "\n${TXT}Ensure automatic security updates enabled:${NC}"
  AUTO="/etc/apt/apt.conf.d/20auto-upgrades"
  if [ -f "$AUTO" ]; then
    echo "  Found $AUTO:"
    cat "$AUTO"
  else
    echo "  Creating $AUTO"
    sudo bash -c "cat > $AUTO" <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  fi
  echo -e "\n${TXT}Installing unattended-upgrades if needed...${NC}"
  dpkg -l | grep -q unattended-upgrades || sudo apt install -y unattended-upgrades
  echo -e "\n${OK}✔ Update audit complete${NC}"
}

log_audit() {
  section "LOG MONITORING"
  LOG="/var/log/auth.log"
  [ ! -f "$LOG" ] && echo -e "${ERR}✖ $LOG not found${NC}" && return
  echo -e "${TXT}Recent failed SSH logins:${NC}"
  grep "Failed password" "$LOG" | tail -n 10
  echo
  echo -e "${TXT}Suspicious IPs (failed logins count):${NC}"
  grep "Failed password" "$LOG" | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head
  echo
  echo -e "${TXT}Root login attempts:${NC}"
  grep "sshd" "$LOG" | grep "root"
  echo -e "\n${OK}✔ Log audit complete${NC}"
}

# ───────────────────────── HARDENING FUNCTIONS ─────────────────────────
harden_ssh() {
  section "SSH HARDENING"
  echo "Checking for OpenSSH server..."
  if ! command -v sshd >/dev/null 2>&1; then
    echo "  Installing openssh-server..."
    sudo apt update && sudo apt install -y openssh-server
  fi
  mkdir -p ~/.ssh && chmod 700 ~/.ssh
  KEY=~/.ssh/id_rsa
  [ -f "$KEY" ] || ssh-keygen -t rsa -b 4096 -N "" -f "$KEY"
  cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
  SSHD_CONFIG="/etc/ssh/sshd_config"
  [ ! -f "$SSHD_CONFIG.bak" ] && sudo cp "$SSHD_CONFIG" "$SSHD_CONFIG.bak"
  sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
  sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
  sudo sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"
  sudo sed -i 's/^#UsePAM.*/UsePAM no/' "$SSHD_CONFIG"
  sudo systemctl restart ssh
  echo -e "${OK}✔ SSH hardened${NC}"
}

harden_ipv6() {
  section "DISABLE IPV6 & SAFESQUID"
  SYSCTL="/etc/sysctl.conf"
  grep -q "disable_ipv6" "$SYSCTL" || cat <<EOF | sudo tee -a "$SYSCTL"
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  sudo sysctl -p >/dev/null
  GRUB="/etc/default/grub"
  grep -q "ipv6.disable=1" "$GRUB" || \
    sudo sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="ipv6.disable=1 /' "$GRUB" && sudo update-grub >/dev/null
  SAFE_CONF="/opt/safesquid/safesquid.conf"
  [ -f "$SAFE_CONF" ] && sudo sed -i 's/^bind_address=.*/bind_address=0.0.0.0/' "$SAFE_CONF" && sudo systemctl restart safesquid
  echo -e "${OK}✔ IPv6 disabled (reboot may be required)${NC}"
}

harden_grub() {
  section "SECURE GRUB BOOTLOADER"
  read -s -p "Enter GRUB admin password: " grub_pass; echo
  read -s -p "Confirm password: " grub_pass2; echo
  [ "$grub_pass" != "$grub_pass2" ] && echo -e "${ERR}✖ Passwords differ${NC}" && return
  hash=$(echo -e "$grub_pass\n$grub_pass" | grub-mkpasswd-pbkdf2 2>/dev/null | awk '/PBKDF2/{print $7}')
  grub_custom="/etc/grub.d/40_custom"
  [ ! -f "$grub_custom.bak" ] && sudo cp "$grub_custom" "$grub_custom.bak"
  grep -q "set superusers" "$grub_custom" || cat <<EOF | sudo tee -a "$grub_custom" >/dev/null
set superusers="admin"
password_pbkdf2 admin $hash
EOF
  sudo update-grub && echo -e "${OK}✔ GRUB secured${NC}"
}

harden_firewall() {
  section "IPTABLES HARDENING"
  sudo iptables -F && sudo iptables -X && sudo iptables -t nat -F && sudo iptables -t nat -X
  sudo iptables -P INPUT DROP && sudo iptables -P FORWARD DROP && sudo iptables -P OUTPUT ACCEPT
  sudo iptables -A INPUT -i lo -j ACCEPT
  sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  sudo iptables -L -v
  if command -v iptables-save >/dev/null && [ -d /etc/iptables ]; then
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null
  else
    echo -e "${WARN}Install iptables-persistent for rule persistence${NC}"
  fi
  echo -e "${OK}✔ Firewall configured${NC}"
}

harden_updates() {
  section "ENABLE AUTO SECURITY UPDATES"
  sudo apt update -y && sudo apt install -y unattended-upgrades apt-listchanges
  sudo bash -c 'cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF'
  sudo sed -i 's|//\s*"${distro_id}:${distro_codename}-security";|"${distro_id}:${distro_codename}-security";|' /etc/apt/apt.conf.d/50unattended-upgrades
  sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies.*|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
  sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot.*|Unattended-Upgrade::Automatic-Reboot "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
  sudo unattended-upgrade --dry-run --debug
  echo -e "${OK}✔ Auto-updates enabled${NC}"
}

hardening_menu() {
  while true; do
    echo -e "${ACC}"
    echo "╔═════════ HARDENING MENU ═════════╗"
    echo "║ 1) SSH & Root          4) Firewall║"
    echo "║ 2) Disable IPv6        5) Updates ║"
    echo "║ 3) Secure GRUB         6) ALL     ║"
    echo "║ 0) Exit                          ║"
    echo "╚══════════════════════════════════╝"
    echo -ne "${NC}Select: "; read -r c
    case $c in
      1) harden_ssh;;
      2) harden_ipv6;;
      3) harden_grub;;
      4) harden_firewall;;
      5) harden_updates;;
      6) harden_ssh; harden_ipv6; harden_grub; harden_firewall; harden_updates;;
      0|q|Q) break;;
      *) echo -e "${WARN}Invalid choice${NC}";;
    esac
  done
}

# ───────────────────────── HELP / MAIN ─────────────────────────
show_help() {
  cat <<EOF
Usage: $0 [--useraudit] [--permcheck] [--serviceaudit] [--firewallaudit]
          [--networkaudit] [--updateaudit] [--logaudit] [--hardening] [--all]
EOF
}

main() {
  banner
  [ $# -eq 0 ] && show_help && exit 1
  for sw in "$@"; do
    case $sw in
      --useraudit)     user_and_group_audit ;;
      --permcheck)     perm_check ;;
      --serviceaudit)  service_audit ;;
      --firewallaudit) firewall_audit ;;
      --networkaudit)  network_audit ;;
      --updateaudit)   update_audit ;;
      --logaudit)      log_audit ;;
      --hardening)     hardening_menu ;;
      --all)           user_and_group_audit; perm_check; service_audit; firewall_audit;\
                       network_audit; update_audit; log_audit ;;
      --help|-h)       show_help ;;
      *) echo -e "${ERR}Unknown option: $sw${NC}"; show_help; exit 1 ;;
    esac
  done
}

main "$@"
