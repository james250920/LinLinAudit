#!/usr/bin/env bash
#
# LinLinAudit — colector de evidencia READ-ONLY para servidores Linux.
#
# Reglas de diseño (ver README.md §2 y §29):
#   - No modifica configuración, no instala paquetes, no reinicia servicios.
#   - No refresca metadatos de gestores de paquetes (usa solo caché local).
#   - No lee contenido de /etc/shadow (solo estado: EMPTY / LOCKED / SET).
#   - No vuelca variables de entorno de contenedores (solo nombres).
#   - Redacta patrones de secretos en toda la salida.
#   - Cada archivo de evidencia registra comando, fecha, privilegio y exit code.
#
# Única escritura: el directorio de salida (modo 700) y, con --archive, su .tar.gz.

set -u
set -o pipefail

VERSION="1.0.1"
ALL_MODULES="inventory system users ssh network firewall services packages filesystem logs auditd mac scheduled containers kubernetes webapps backups secrets integrity capacity virtualization"

OUT=""
MODULES="$ALL_MODULES"
USE_SUDO="auto"
TIMEOUT=120
LONG_TIMEOUT=900
ARCHIVE=0
QUICK=0
SINCE="7 days ago"

log() { printf '[linlinaudit] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit 2; }

usage() {
    cat >&2 <<EOF
LinLinAudit collector v$VERSION — recolección de evidencia read-only

Uso: $0 [opciones]

  -o, --output DIR       Directorio de salida (por defecto ./audit-<host>-<fecha>)
  -m, --modules LISTA    Módulos separados por coma (por defecto: todos)
      --list-modules     Muestra los módulos disponibles
      --no-sudo          No intentar 'sudo -n' aunque esté disponible
      --quick            Omite escaneos pesados (SUID/SGID/world-writable, rpm -Va, debsums)
      --since TEXTO      Ventana de logs para journalctl (por defecto: "$SINCE")
      --timeout SEG      Timeout por comando (por defecto: $TIMEOUT)
      --archive          Genera además <salida>.tar.gz
      --redact           Filtro: lee stdin y escribe stdout con secretos redactados
  -V, --version          Muestra la versión
  -h, --help             Muestra esta ayuda

Módulos: $ALL_MODULES
EOF
}

# --------------------------------------------------------------------------
# Redacción de secretos
# --------------------------------------------------------------------------
redact() {
    sed -E \
        -e '/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/c\<REDACTED PRIVATE KEY>' \
        -e 's/([A-Za-z0-9_.-]*([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss][Ww][Dd]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]|[Aa][Cc][Cc][Ee][Ss][Ss][_-]?[Kk][Ee][Yy]|[Pp][Rr][Ii][Vv][Aa][Tt][Ee][_-]?[Kk][Ee][Yy]|[Cc][Rr][Ee][Dd][Ee][Nn][Tt][Ii][Aa][Ll][Ss]?)[A-Za-z0-9_.-]*)(["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?)[^"'"'"'[:space:],;]+/\1\3<REDACTED>/g' \
        -e 's/(^|[[:space:]])((requirepass|masterauth)[[:space:]]+)[^[:space:]]+/\1\2<REDACTED>/g' \
        -e 's/([Bb]earer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1<REDACTED>/g' \
        -e 's#([a-zA-Z][a-zA-Z0-9+.-]*://[^/:@[:space:]]+):[^@/[:space:]]+@#\1:<REDACTED>@#g'
}

# --------------------------------------------------------------------------
# Argumentos
# --------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -o|--output)   [ $# -ge 2 ] || die "falta valor para $1"; OUT="$2"; shift 2 ;;
        -m|--modules)  [ $# -ge 2 ] || die "falta valor para $1"; MODULES="${2//,/ }"; shift 2 ;;
        --list-modules) printf '%s\n' $ALL_MODULES; exit 0 ;;
        --no-sudo)     USE_SUDO="no"; shift ;;
        --quick)       QUICK=1; shift ;;
        --since)       [ $# -ge 2 ] || die "falta valor para $1"; SINCE="$2"; shift 2 ;;
        --timeout)     [ $# -ge 2 ] || die "falta valor para $1"; TIMEOUT="$2"; shift 2 ;;
        --archive)     ARCHIVE=1; shift ;;
        --redact)      redact; exit $? ;;
        -V|--version)  echo "$VERSION"; exit 0 ;;
        -h|--help)     usage; exit 0 ;;
        *)             usage; die "opción desconocida: $1" ;;
    esac
done

for m in $MODULES; do
    case " $ALL_MODULES " in
        *" $m "*) ;;
        *) die "módulo desconocido: $m (usa --list-modules)" ;;
    esac
done

case "$TIMEOUT" in ''|*[!0-9]*) die "--timeout debe ser un entero" ;; esac

# --------------------------------------------------------------------------
# Entorno
# --------------------------------------------------------------------------
HOST="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname)"
TS="$(date +%Y%m%d-%H%M%S)"
[ -n "$OUT" ] || OUT="./audit-${HOST}-${TS}"

umask 077
[ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ] && die "el directorio de salida ya existe y no está vacío: $OUT"
mkdir -p "$OUT" || die "no se pudo crear $OUT"
chmod 700 "$OUT"

SUDO=""
if [ "$(id -u)" -eq 0 ]; then
    PRIV="root"
elif [ "$USE_SUDO" != "no" ] && command -v sudo >/dev/null 2>&1 && sudo -n true </dev/null 2>/dev/null; then
    SUDO="sudo -n"
    PRIV="sudo"
else
    PRIV="user"
fi
export SUDO SINCE
export LC_ALL=C

have() { command -v "$1" >/dev/null 2>&1; }

# lla_reach <ruta>: "yes" si cualquier usuario puede atravesar todos los directorios padre
# (o+x); un archivo 644 dentro de un home 700 no es legible por otros.
lla_reach() {
    local d
    d=$(dirname "$1")
    while [ "$d" != "/" ] && [ "$d" != "." ]; do
        case "$($SUDO stat -c %A "$d" 2>/dev/null)" in
            ?????????[xt]) ;;
            *) echo no; return ;;
        esac
        d=$(dirname "$d")
    done
    echo yes
}
export -f lla_reach
TIMEOUT_BIN=""
have timeout && TIMEOUT_BIN="timeout"

LIMITS="$OUT/limitations.txt"
: > "$LIMITS"
printf 'module\tfile\texit\tcommand\n' > "$OUT/commands.tsv"

# run_t <timeout> <module> <name> <command>
run_t() {
    local t="$1" mod="$2" name="$3" cmd="$4"
    local dir="$OUT/$mod" f rc
    mkdir -p "$dir"
    f="$dir/$name.txt"
    {
        printf '##LLA command: %s\n' "$cmd"
        printf '##LLA date: %s\n' "$(date -Is)"
        printf '##LLA privilege: %s\n' "$PRIV"
    } > "$f"
    if [ -n "$TIMEOUT_BIN" ]; then
        timeout -k 5 "$t" bash -c "$cmd" </dev/null 2>&1 | redact >> "$f"
    else
        bash -c "$cmd" </dev/null 2>&1 | redact >> "$f"
    fi
    rc=${PIPESTATUS[0]}
    printf '##LLA exit: %s\n' "$rc" >> "$f"
    printf '%s\t%s\t%s\t%s\n' "$mod" "$name" "$rc" "$cmd" >> "$OUT/commands.tsv"
    if [ "$rc" = "124" ] || [ "$rc" = "137" ]; then
        printf 'TIMEOUT\t%s/%s\t%ss\n' "$mod" "$name" "$t" >> "$LIMITS"
    fi
    if grep -qiE 'permission denied|operation not permitted|must be (run as )?root|a password is required|you must be root|access denied|are you root|requires root' "$f"; then
        printf 'PERMISSION\t%s/%s\tposible salida incompleta por falta de privilegios\n' "$mod" "$name" >> "$LIMITS"
    fi
    return 0
}

run() { run_t "$TIMEOUT" "$@"; }

# runif <tool> <module> <name> <command>  — registra la herramienta ausente en vez de ejecutar
runif() {
    local tool="$1"; shift
    if have "$tool"; then
        run "$@"
    else
        mkdir -p "$OUT/$1"
        {
            printf '##LLA command: %s\n' "$3"
            printf '##LLA skipped: tool not found: %s\n' "$tool"
        } > "$OUT/$1/$2.txt"
        printf 'MISSING_TOOL\t%s/%s\t%s\n' "$1" "$2" "$tool" >> "$LIMITS"
    fi
}

skip_quick() {
    mkdir -p "$OUT/$1"
    printf '##LLA skipped: --quick\n' > "$OUT/$1/$2.txt"
    printf 'QUICK_SKIP\t%s/%s\tomitido por --quick\n' "$1" "$2" >> "$LIMITS"
}

# --------------------------------------------------------------------------
# Módulos
# --------------------------------------------------------------------------
mod_inventory() {
    local m=inventory
    runif hostnamectl $m hostnamectl 'hostnamectl'
    run $m uname 'uname -a'
    run $m os-release 'cat /etc/os-release'
    run $m uptime 'uptime'
    run $m who 'who'
    run $m w 'w'
    runif last $m last 'last -n 20 -F 2>/dev/null || last -n 20'
    run $m init 'ps -p 1 -o comm='
    runif systemd-detect-virt $m virt 'systemd-detect-virt'
    run $m dmi 'for k in system-manufacturer system-product-name bios-version; do printf "%s: " "$k"; $SUDO dmidecode -s "$k" 2>/dev/null || cat /sys/class/dmi/id/${k//-/_} 2>/dev/null || echo "?"; done'
    runif lscpu $m cpu 'lscpu; echo; echo "nproc: $(nproc)"'
    run $m memory 'free -h; echo; cat /proc/meminfo'
    runif lsblk $m storage 'lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS,UUID 2>/dev/null || lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID; echo; df -hT; echo; findmnt'
    runif lspci $m pci 'lspci'
    runif lsusb $m usb 'lsusb'
    runif timedatectl $m time 'timedatectl'
}

mod_system() {
    local m=system
    run $m sysctl-security 'for k in kernel.randomize_va_space kernel.kptr_restrict kernel.dmesg_restrict kernel.yama.ptrace_scope kernel.unprivileged_bpf_disabled kernel.unprivileged_userns_clone kernel.sysrq fs.suid_dumpable fs.protected_symlinks fs.protected_hardlinks fs.protected_fifos fs.protected_regular net.core.bpf_jit_harden net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv6.conf.all.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.conf.all.accept_source_route net.ipv6.conf.all.accept_source_route net.ipv4.conf.all.rp_filter net.ipv4.conf.all.log_martians net.ipv4.tcp_syncookies net.ipv4.icmp_echo_ignore_broadcasts net.ipv6.conf.all.disable_ipv6; do sysctl "$k" 2>/dev/null || echo "$k = <n/a>"; done'
    run $m cmdline 'cat /proc/cmdline'
    runif lsmod $m modules 'lsmod'
    runif mokutil $m secureboot 'mokutil --sb-state'
    run $m login-defs 'grep -E "^[[:space:]]*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK|ENCRYPT_METHOD|SHA_CRYPT_MIN_ROUNDS|YESCRYPT_COST_FACTOR)" /etc/login.defs'
    run $m pam-password 'grep -RhE "^[[:space:]]*[^#].*(pam_pwquality|pam_cracklib|pam_faillock|pam_tally2|pam_unix)" /etc/pam.d 2>/dev/null | sort -u; echo; grep -hE "^[[:space:]]*[^#]" /etc/security/pwquality.conf /etc/security/faillock.conf 2>/dev/null'
    run $m limits-core 'grep -RhE "^[[:space:]]*[^#].*core" /etc/security/limits.conf /etc/security/limits.d 2>/dev/null; echo "ulimit -c: $(ulimit -c)"; cat /proc/sys/kernel/core_pattern'
    run $m ctrl-alt-del 'systemctl is-enabled ctrl-alt-del.target 2>&1; systemctl get-default 2>&1'
}

mod_users() {
    local m=users
    run $m passwd 'getent passwd'
    run $m group 'getent group'
    run $m human-users "awk -F: '\$3 >= 1000 && \$1 != \"nobody\" {print}' /etc/passwd"
    run $m uid0 "awk -F: '\$3 == 0 {print}' /etc/passwd"
    run $m shells 'cat /etc/shells'
    run $m interactive-shells "awk -F: '\$7 !~ /(nologin|false|sync|shutdown|halt)\$/ {print \$1 \":\" \$3 \":\" \$7}' /etc/passwd"
    run $m admin-groups 'for g in sudo wheel admin adm docker lxd libvirt disk shadow; do getent group "$g"; done'
    run $m sudo-l 'sudo -n -l 2>&1'
    run $m sudoers-rules "\$SUDO grep -RInE '^[[:space:]]*[^#[:space:]].*(ALL|NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d"
    run $m sudoers-files '$SUDO ls -la /etc/sudoers /etc/sudoers.d'
    # Solo estado de la contraseña, NUNCA el hash.
    run $m shadow-status "\$SUDO awk -F: '{ s=\"SET\"; if (\$2==\"\") s=\"EMPTY\"; else if (\$2 ~ /^[!*]/) s=\"LOCKED\"; print \$1, s, \"lastchg=\"\$3, \"max=\"\$5, \"expire=\"\$8 }' /etc/shadow"
    run $m lastlog 'if command -v lastlog2 >/dev/null; then lastlog2; elif command -v lastlog >/dev/null; then lastlog; else echo "lastlog no disponible"; fi'
    run $m home-perms 'ls -ld /root /home/* 2>&1'
}

mod_ssh() {
    local m=ssh
    runif sshd $m sshd-effective '$SUDO sshd -T'
    run $m sshd-config "\$SUDO grep -RInE '^[[:space:]]*(Port|ListenAddress|PermitRootLogin|PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|AllowTcpForwarding|AllowAgentForwarding|AllowUsers|AllowGroups|DenyUsers|DenyGroups|MaxAuthTries|LoginGraceTime|ClientAliveInterval|UsePAM|AuthenticationMethods|Ciphers|MACs|KexAlgorithms|Include|Match)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d"
    run $m config-perms '$SUDO ls -la /etc/ssh /etc/ssh/sshd_config.d'
    run $m host-keys 'for f in /etc/ssh/ssh_host_*_key.pub; do [ -f "$f" ] && ssh-keygen -lf "$f"; done'
    run $m authorized-keys '$SUDO find /home /root -maxdepth 3 -name "authorized_keys*" -type f -printf "%m %u:%g %TY-%Tm-%Td %p\n"'
    # Tipo, tamaño y comentario de cada clave autorizada (sin el material de clave)
    run $m authorized-keys-fp '$SUDO find /home /root -maxdepth 3 -name "authorized_keys*" -type f 2>/dev/null | while read -r f; do echo "== $f"; $SUDO ssh-keygen -lf "$f" 2>&1; done'
    runif ssh $m version 'ssh -V'
}

mod_network() {
    local m=network
    run $m addr-brief 'ip -br addr'
    run $m addr 'ip addr'
    run $m link 'ip -br link'
    run $m route 'ip route; echo; ip -6 route'
    run $m dns 'resolvectl status 2>/dev/null || cat /etc/resolv.conf'
    run $m hosts 'cat /etc/hosts; echo; cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null | grep -v "^#"'
    runif ss $m listening '$SUDO ss -tulpnH 2>/dev/null || $SUDO ss -tulpn'
    runif ss $m listening-tcp '$SUDO ss -lntp'
    runif ss $m listening-udp '$SUDO ss -lnup'
    runif ss $m connections '$SUDO ss -tunap'
    runif ip $m neighbors 'ip neigh'
}

mod_firewall() {
    local m=firewall
    run $m status 'for s in ufw firewalld nftables iptables ip6tables netfilter-persistent; do printf "%s: " "$s"; systemctl is-active "$s" 2>/dev/null || true; done'
    runif ufw $m ufw '$SUDO ufw status verbose'
    runif nft $m nftables '$SUDO nft list ruleset'
    runif iptables $m iptables '$SUDO iptables -S; echo; $SUDO iptables -L -n -v; echo; $SUDO iptables -t nat -S'
    runif ip6tables $m ip6tables '$SUDO ip6tables -S; echo; $SUDO ip6tables -L -n -v'
    runif firewall-cmd $m firewalld '$SUDO firewall-cmd --state; $SUDO firewall-cmd --get-active-zones; $SUDO firewall-cmd --list-all'
    runif fail2ban-client $m fail2ban '$SUDO fail2ban-client status'
}

mod_services() {
    local m=services
    runif systemctl $m running 'systemctl list-units --type=service --state=running --no-pager --no-legend'
    runif systemctl $m unit-files 'systemctl list-unit-files --type=service --no-pager --no-legend'
    runif systemctl $m failed 'systemctl --failed --no-pager --no-legend'
    runif systemctl $m sockets 'systemctl list-sockets --no-pager'
    run $m ps-cpu 'ps aux --sort=-%cpu | head -30'
    run $m ps-mem 'ps aux --sort=-%mem | head -30'
    run $m ps-all 'ps -eo user,pid,ppid,lstart,comm,args --sort=user'
    run $m suspicious-exe '$SUDO sh -c "ls -l /proc/[0-9]*/exe 2>/dev/null" | grep -E "(/tmp/|/var/tmp/|/dev/shm/|\(deleted\))" || echo "ninguno"'
    runif systemd-analyze $m systemd-security 'systemd-analyze security --no-pager'
}

mod_packages() {
    local m=packages
    if have dpkg; then
        run $m dpkg-list 'dpkg -l'
        run $m apt-upgradable 'apt list --upgradable 2>/dev/null'
        run $m apt-security 'apt list --upgradable 2>/dev/null | grep -i -- "-security" || echo "ninguno"'
        run $m apt-sources 'grep -RhvE "^[[:space:]]*(#|$)" /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null'
        run $m apt-cache-age 'ls -la --time-style=full-iso /var/lib/apt/lists/ | head -5; stat -c "%y %n" /var/lib/apt/periodic/update-success-stamp 2>/dev/null'
        run $m apt-auto 'systemctl is-enabled unattended-upgrades 2>&1; cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null'
        run $m apt-history 'grep -hE "^(Start-Date|Commandline)" /var/log/apt/history.log 2>/dev/null | tail -40'
        run $m manual 'apt-mark showmanual 2>/dev/null'
    fi
    if have rpm; then
        run $m rpm-list 'rpm -qa --qf "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\t%{VENDOR}\n" | sort'
        run $m rpm-last 'rpm -qa --last | head -40'
        run $m repos 'grep -HE "^[[:space:]]*(\[|name|baseurl|metalink|mirrorlist|enabled|gpgcheck)" /etc/yum.repos.d/*.repo 2>/dev/null'
    fi
    if have dnf; then
        # --cacheonly: no descarga metadatos (read-only). El resultado depende de la antigüedad de la caché.
        run $m dnf-check-update 'dnf -q --cacheonly check-update; rc=$?; echo "rc=$rc"; exit $rc'
        run $m dnf-security 'dnf -q --cacheonly updateinfo list --security 2>&1'
        run $m dnf-auto 'systemctl is-enabled dnf-automatic.timer dnf5-automatic.timer 2>&1'
        run $m needs-restarting 'if command -v needs-restarting >/dev/null; then $SUDO needs-restarting -r 2>&1; else $SUDO dnf -q --cacheonly needs-restarting -r 2>&1; fi; echo "rc=$?"'
    elif have yum; then
        run $m yum-check-update 'yum -q -C check-update; rc=$?; echo "rc=$rc"; exit $rc'
    fi
    if have pacman; then
        run $m pacman-upgradable 'pacman -Qu'
        run $m pacman-list 'pacman -Q'
        run $m pacman-foreign 'pacman -Qm'
    fi
    if have zypper; then
        run $m zypper-updates 'zypper --no-refresh --non-interactive list-updates'
        run $m zypper-patches 'zypper --no-refresh --non-interactive list-patches --category security'
    fi
    if have apk; then
        run $m apk-upgradable 'apk version -l "<"'
        run $m apk-list 'apk info -v'
    fi
    runif snap $m snap 'snap list'
    runif flatpak $m flatpak 'flatpak list'
    run $m reboot-required 'if [ -f /var/run/reboot-required ]; then echo "REBOOT_REQUIRED"; cat /var/run/reboot-required.pkgs 2>/dev/null; else echo "no-flag"; fi; echo "running_kernel=$(uname -r)"; ls -1 /boot/vmlinuz-* 2>/dev/null'
}

mod_filesystem() {
    local m=filesystem
    run $m findmnt 'findmnt'
    run $m fstab 'cat /etc/fstab'
    run $m tmp-mounts 'for p in /tmp /var/tmp /dev/shm /home /var /var/log; do printf "%s\t" "$p"; findmnt -no SOURCE,FSTYPE,OPTIONS "$p" 2>/dev/null || echo "(no es punto de montaje)"; done'
    run $m critical-perms 'for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config /etc/crontab /boot/grub/grub.cfg /boot/grub2/grub.cfg; do [ -e "$f" ] && stat -c "%a %U:%G %n" "$f"; done'
    if [ "$QUICK" -eq 1 ]; then
        skip_quick $m suid; skip_quick $m sgid; skip_quick $m world-writable-files
        skip_quick $m world-writable-dirs; skip_quick $m unowned
    else
        run_t "$LONG_TIMEOUT" $m suid '$SUDO find / -xdev -type f -perm -4000 -printf "%m %u:%g %p\n"'
        run_t "$LONG_TIMEOUT" $m sgid '$SUDO find / -xdev -type f -perm -2000 -printf "%m %u:%g %p\n"'
        run_t "$LONG_TIMEOUT" $m world-writable-files '$SUDO find / -xdev -type f -perm -0002 -printf "%m %u:%g %p\n"'
        run_t "$LONG_TIMEOUT" $m world-writable-dirs '$SUDO find / -xdev -type d -perm -0002 -printf "%m %u:%g %p\n"'
        run_t "$LONG_TIMEOUT" $m unowned '$SUDO find / -xdev \( -nouser -o -nogroup \) -printf "%m %u:%g %p\n" | head -500'
    fi
    run $m sensitive-dirs 'ls -la /tmp /var/tmp /srv /opt /var/www 2>&1'
}

mod_logs() {
    local m=logs
    runif journalctl $m journal-usage 'journalctl --disk-usage'
    run $m journald-conf 'grep -hE "^[[:space:]]*[^#]" /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null; echo; ls -ld /var/log/journal 2>&1'
    runif journalctl $m journal-warnings '$SUDO journalctl -p warning..alert --since "$SINCE" --no-pager -q | tail -2000'
    runif journalctl $m journal-ssh '$SUDO journalctl -u ssh -u sshd --since "$SINCE" --no-pager -q | tail -3000'
    run $m auth-log '$SUDO sh -c "grep -hEi \"failed|invalid|accepted|sudo|su:|authentication failure\" /var/log/auth.log /var/log/secure 2>/dev/null" | tail -3000'
    run $m auth-failed-by-ip '{ $SUDO journalctl -u ssh -u sshd --since "$SINCE" --no-pager -q 2>/dev/null; $SUDO cat /var/log/auth.log /var/log/secure 2>/dev/null; } | grep -Eo "(Failed password|Invalid user|authentication failure).*from [0-9a-fA-F.:]+" | grep -Eo "from [0-9a-fA-F.:]+" | awk "{print \$2}" | sort | uniq -c | sort -rn | head -50'
    run $m auth-invalid-users '{ $SUDO journalctl -u ssh -u sshd --since "$SINCE" --no-pager -q 2>/dev/null; $SUDO cat /var/log/auth.log /var/log/secure 2>/dev/null; } | grep -Eo "Invalid user [^ ]+" | awk "{print \$3}" | sort | uniq -c | sort -rn | head -50'
    run $m auth-accepted '{ $SUDO journalctl -u ssh -u sshd --since "$SINCE" --no-pager -q 2>/dev/null; $SUDO cat /var/log/auth.log /var/log/secure 2>/dev/null; } | grep -E "Accepted (password|publickey|keyboard-interactive)" | tail -200'
    runif lastb $m lastb '$SUDO lastb -n 50'
    run $m syslog-daemons 'for s in rsyslog syslog-ng systemd-journald; do printf "%s: " "$s"; systemctl is-active "$s" 2>/dev/null || true; done'
    run $m remote-forwarding 'grep -RhnE "^[[:space:]]*[^#].*(@@?[A-Za-z0-9.-]+|omfwd|destination|ForwardToSyslog)" /etc/rsyslog.conf /etc/rsyslog.d /etc/syslog-ng /etc/systemd/journald.conf 2>/dev/null || echo "ninguno"'
    run $m logrotate 'grep -hvE "^[[:space:]]*(#|$)" /etc/logrotate.conf 2>/dev/null; ls -1 /etc/logrotate.d 2>/dev/null'
    run $m var-log '$SUDO ls -la /var/log'
}

mod_auditd() {
    local m=auditd
    run $m status 'systemctl is-active auditd 2>&1; systemctl is-enabled auditd 2>&1'
    runif auditctl $m auditctl-status '$SUDO auditctl -s'
    runif auditctl $m rules '$SUDO auditctl -l'
    run $m conf 'grep -hE "^[[:space:]]*[^#]" /etc/audit/auditd.conf 2>/dev/null'
    runif ausearch $m logins '$SUDO ausearch -m USER_LOGIN --start recent -i 2>&1 | tail -200'
    runif ausearch $m user-cmd '$SUDO ausearch -m USER_CMD --start recent -i 2>&1 | tail -200'
}

mod_mac() {
    local m=mac
    runif getenforce $m selinux-mode 'getenforce'
    runif sestatus $m sestatus 'sestatus'
    runif ausearch $m selinux-avc '$SUDO ausearch -m AVC --start recent 2>&1 | tail -100'
    runif aa-status $m apparmor '$SUDO aa-status'
    run $m apparmor-denied '$SUDO journalctl -k --since "$SINCE" --no-pager -q 2>/dev/null | grep -i "apparmor=\"DENIED\"" | tail -100 || echo "ninguno"'
}

mod_scheduled() {
    local m=scheduled
    run $m crontab-current 'crontab -l'
    run $m crontab-root '$SUDO crontab -u root -l'
    run $m etc-crontab 'cat /etc/crontab'
    run $m cron-dirs 'ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>&1'
    run $m cron-d-content 'for f in /etc/cron.d/*; do [ -f "$f" ] && { echo "== $f"; grep -vE "^[[:space:]]*(#|$)" "$f"; }; done'
    run $m user-crontabs 'for u in $(cut -d: -f1 /etc/passwd); do out=$($SUDO crontab -u "$u" -l 2>/dev/null) && printf "=== %s ===\n%s\n" "$u" "$out"; done; echo "(fin)"'
    run $m suspicious 'grep -RInE "(curl|wget|/tmp/|/dev/shm|base64 -d|nc -e|bash -i|python -c|\| *sh)" /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null; $SUDO grep -RInE "(curl|wget|/tmp/|/dev/shm|base64 -d|nc -e|bash -i|\| *sh)" /var/spool/cron 2>/dev/null; echo "(fin)"'
    runif systemctl $m timers 'systemctl list-timers --all --no-pager'
    runif atq $m at '$SUDO atq'
}

mod_containers() {
    local m=containers
    local fmt='{{.Name}} image={{.Config.Image}} user={{.Config.User}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}} pid={{.HostConfig.PidMode}} ipc={{.HostConfig.IpcMode}} readonly={{.HostConfig.ReadonlyRootfs}} memory={{.HostConfig.Memory}} nanocpus={{.HostConfig.NanoCpus}} restart={{.HostConfig.RestartPolicy.Name}} capadd={{json .HostConfig.CapAdd}} secopt={{json .HostConfig.SecurityOpt}} ports={{json .HostConfig.PortBindings}} mounts={{range .Mounts}}{{.Type}}:{{.Source}}->{{.Destination}}:rw={{.RW}};{{end}} env_names={{range .Config.Env}}{{index (split . "=") 0}},{{end}}'
    if have docker; then
        run $m docker-version '$SUDO docker version'
        run $m docker-info '$SUDO docker info'
        run $m docker-ps '$SUDO docker ps -a --no-trunc --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"'
        run $m docker-images '$SUDO docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}"'
        run $m docker-networks '$SUDO docker network ls'
        run $m docker-volumes '$SUDO docker volume ls'
        # Resumen de seguridad por contenedor. Nunca `docker inspect` completo: expondría secretos en Env.
        run $m docker-summary "ids=\$(\$SUDO docker ps -aq); [ -n \"\$ids\" ] && \$SUDO docker inspect --format '$fmt' \$ids || echo 'sin contenedores'"
        run $m docker-daemon 'cat /etc/docker/daemon.json 2>/dev/null; echo; ps -eo args | grep -E "[d]ockerd" ; systemctl cat docker.service 2>/dev/null | grep -E "^ExecStart"'
        run $m docker-socket 'ls -l /var/run/docker.sock /run/docker.sock 2>&1; getent group docker'
        run $m compose-files 'find /opt /srv /home /root -maxdepth 4 \( -name "docker-compose*.yml" -o -name "docker-compose*.yaml" -o -name "compose.yml" -o -name "compose.yaml" \) -printf "%m %u:%g %p\n" 2>/dev/null'
    else
        mkdir -p "$OUT/$m"; printf '##LLA skipped: tool not found: docker\n' > "$OUT/$m/docker-version.txt"
    fi
    if have podman; then
        run $m podman-ps 'podman ps -a; echo "--- rootful ---"; $SUDO podman ps -a'
        run $m podman-images 'podman images; echo "--- rootful ---"; $SUDO podman images'
        run $m podman-networks 'podman network ls; echo "--- rootful ---"; $SUDO podman network ls'
        run $m podman-volumes 'podman volume ls; echo "--- rootful ---"; $SUDO podman volume ls'
        run $m podman-summary 'for p in "" "$SUDO"; do ids=$($p podman ps -aq); [ -n "$ids" ] && $p podman inspect --format "{{.Name}} image={{.ImageName}} privileged={{.HostConfig.Privileged}} network={{.HostConfig.NetworkMode}} pid={{.HostConfig.PidMode}} user={{.Config.User}} mounts={{range .Mounts}}{{.Type}}:{{.Source}}->{{.Destination}};{{end}}" $ids; done; echo "(fin)"'
    fi
    if have lxc-ls; then run $m lxc '$SUDO lxc-ls -f'; fi
}

mod_kubernetes() {
    local m=kubernetes k=""
    if have kubectl; then k="kubectl"
    elif have k3s; then k="\$SUDO k3s kubectl"
    elif have microk8s; then k="\$SUDO microk8s kubectl"
    fi
    if [ -z "$k" ]; then
        mkdir -p "$OUT/$m"; printf '##LLA skipped: tool not found: kubectl\n' > "$OUT/$m/nodes.txt"
        return 0
    fi
    run $m nodes "$k get nodes -o wide"
    run $m pods "$k get pods -A -o wide"
    run $m services "$k get svc -A"
    run $m ingress "$k get ingress -A"
    run $m networkpolicies "$k get networkpolicies -A"
    run $m secrets-names "$k get secrets -A"
    run $m serviceaccounts "$k get serviceaccounts -A"
    run $m clusterrolebindings "$k get clusterrolebindings -o wide"
    run $m pod-security "$k get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} hostNetwork={.spec.hostNetwork} hostPID={.spec.hostPID} hostIPC={.spec.hostIPC} privileged={.spec.containers[*].securityContext.privileged} runAsUser={.spec.securityContext.runAsUser} hostPath={.spec.volumes[*].hostPath.path}{\"\\n\"}{end}'"
}

mod_webapps() {
    local m=webapps
    run $m detect 'systemctl list-units --type=service --no-pager --no-legend 2>/dev/null | grep -Ei "nginx|apache|httpd|caddy|traefik|haproxy|lighttpd|php-fpm|tomcat" || echo "ninguno"'
    runif nginx $m nginx '$SUDO nginx -T'
    run $m apache 'for c in apache2ctl apachectl httpd; do command -v "$c" >/dev/null && { $SUDO "$c" -S; $SUDO "$c" -M; break; }; done; echo "(fin)"'
    runif caddy $m caddy 'caddy version; cat /etc/caddy/Caddyfile 2>/dev/null'
    run $m certificates '$SUDO find /etc/letsencrypt/live /etc/ssl/private /etc/nginx /etc/apache2 /etc/httpd /etc/caddy /etc/traefik /opt /srv -maxdepth 4 -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.cer" \) ! -name "*key*" 2>/dev/null | while read -r f; do $SUDO openssl x509 -noout -subject -issuer -enddate -in "$f" >/dev/null 2>&1 || continue; echo "== $f"; $SUDO openssl x509 -noout -subject -issuer -enddate -in "$f" 2>&1; done; echo "(fin)"'
    run $m database-binds '$SUDO grep -RInE "^[[:space:]]*(bind-address|listen_addresses|bind |protected-mode|requirepass|net\.bindIp|bindIp:|network\.host|skip-networking)" /etc/mysql /etc/my.cnf /etc/my.cnf.d /etc/postgresql /var/lib/pgsql/data/postgresql.conf /etc/redis /etc/redis.conf /etc/mongod.conf /etc/elasticsearch 2>/dev/null || echo "ninguno"'
    run $m pg-hba '$SUDO sh -c "grep -hvE \"^[[:space:]]*(#|$)\" /etc/postgresql/*/main/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf 2>/dev/null" || echo "ninguno"'
}

mod_backups() {
    local m=backups
    run $m tools 'for t in restic borg borgmatic rsync rclone duplicity duplicati kopia proxmox-backup-client timeshift snapper sanoid syncoid bacula-fd urbackupclientctl; do command -v "$t" >/dev/null && echo "$t: $(command -v "$t")"; done; echo "(fin)"'
    run $m references 'grep -RInE "backup|restic|borg|rsync|rclone|duplicity|kopia|snapshot" /etc/systemd /etc/cron* 2>/dev/null; $SUDO grep -RInE "backup|restic|borg|rsync|rclone|duplicity|kopia" /var/spool/cron 2>/dev/null; echo "(fin)"'
    runif systemctl $m units 'systemctl list-units --all --no-pager --no-legend | grep -Ei "backup|restic|borg|rclone|kopia|snapshot|sanoid|timeshift" || echo "ninguno"'
    runif journalctl $m recent-runs '$SUDO journalctl --since "30 days ago" --no-pager -q 2>/dev/null | grep -Ei "(restic|borg|rclone|kopia|backup).*(finish|complete|success|error|fail)" | tail -100 || echo "ninguno"'
    runif zfs $m zfs-snapshots '$SUDO zfs list -t snapshot -o name,creation -s creation | tail -30'
    runif snapper $m snapper '$SUDO snapper list'
}

mod_secrets() {
    local m=secrets
    # Solo rutas y permisos — nunca el contenido.
    run $m pattern-files '$SUDO grep -rIliE --exclude=nsswitch.conf --exclude-dir=alternatives --exclude-dir=ssl --exclude-dir=pki --exclude-dir=selinux --exclude-dir=man --exclude-dir=node_modules --exclude-dir=.git --exclude="*.js" --exclude="*.map" --exclude="*.html" --exclude="*.css" --exclude="*.md" --exclude="*.template" --exclude="*.example" --exclude="*.sample" -e "(password|passwd|pwd|secret|secret[_-]?key|token|api[_-]?key|access[_-]?key|private[_-]?key)[\"'"'"']?[[:space:]]*=[[:space:]]*[\"'"'"']?[^[:space:]\"'"'"'\$<{]{4,}" -e "^[[:space:]]*[a-z_]*(password|secret|secret[_-]?key|token|api[_-]?key|access[_-]?key):[[:space:]]+[\"'"'"']?[^[:space:]\"'"'"'\$<{#]{4,}" /etc /opt /srv /var/www 2>/dev/null | head -300 | while read -r f; do echo "$($SUDO stat -c "%a %U:%G %n" "$f") reach=$(lla_reach "$f")"; done'
    run $m env-files '$SUDO find /opt /srv /var/www /home /root /etc -xdev -maxdepth 5 -type f \( -name ".env" -o -name ".env.*" -o -name "*.env" \) ! -name "*.example" ! -name "*.sample" ! -name "*.template" ! -name "*.dist" -printf "%m %u:%g %p\n" 2>/dev/null | while read -r m o p; do echo "$m $o $p reach=$(lla_reach "$p")"; done'
    # Solo archivos cuyo contenido es realmente una clave privada (grep -l no imprime el contenido)
    run $m private-keys '$SUDO find /home /root /etc /opt /srv -xdev -maxdepth 6 -type f \( -name "id_rsa" -o -name "id_dsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.key" -o -name "*.pem" \) ! -path "/etc/ssh/ssh_host_*" 2>/dev/null | while read -r f; do $SUDO grep -qs -- "PRIVATE KEY" "$f" && $SUDO stat -c "%a %U:%G %n" "$f"; done; echo "(fin)"'
    run $m history-files '$SUDO find /home /root -maxdepth 2 -type f -name ".*history" -printf "%m %u:%g %s %p\n" 2>/dev/null'
    run $m history-patterns '$SUDO find /home /root -maxdepth 2 -type f -name ".*history" 2>/dev/null | while read -r f; do n=$($SUDO grep -cEi "(password|passwd|token|secret|api[_-]?key)[=: ]|mysql .*-p[^ ]|sshpass|curl .*(-u|--user) " "$f" 2>/dev/null); [ "${n:-0}" -gt 0 ] && echo "$n coincidencias: $f"; done; echo "(fin)"'
    run $m cloud-credentials '$SUDO find /home /root -maxdepth 3 \( -path "*/.aws/credentials" -o -path "*/.docker/config.json" -o -path "*/.kube/config" -o -name ".netrc" -o -name ".pgpass" -o -name ".my.cnf" -o -path "*/.config/rclone/rclone.conf" \) -printf "%m %u:%g %p\n" 2>/dev/null'
}

mod_integrity() {
    local m=integrity
    run $m tools 'for t in aide debsums rpm tripwire rkhunter chkrootkit; do command -v "$t" >/dev/null && echo "$t: $(command -v "$t")"; done; ls -la /var/lib/aide 2>/dev/null; echo "(fin)"'
    if [ "$QUICK" -eq 1 ]; then
        skip_quick $m debsums; skip_quick $m rpm-verify
    else
        have debsums && run_t "$LONG_TIMEOUT" $m debsums '$SUDO debsums -s 2>&1'
        have rpm && run_t "$LONG_TIMEOUT" $m rpm-verify '$SUDO rpm -Va 2>&1 | grep -vE "^.{8,9} +c " '
    fi
    run $m recent-changes '$SUDO find /etc /usr/local /opt /srv /usr/bin /usr/sbin -xdev -type f -mtime -7 -printf "%TY-%Tm-%Td %TH:%TM %m %u:%g %p\n" 2>/dev/null | sort | tail -500'
}

mod_capacity() {
    local m=capacity
    run $m load 'uptime; echo; top -b -n1 | head -30'
    run $m memory 'free -h; echo; swapon --show 2>/dev/null'
    run $m disk 'df -hTP -x tmpfs -x devtmpfs -x squashfs -x overlay'
    run $m inodes 'df -iP -x tmpfs -x devtmpfs -x squashfs -x overlay'
    runif vmstat $m vmstat 'vmstat 1 3'
    runif iostat $m iostat 'iostat -x 1 2'
    runif smartctl $m smart '$SUDO smartctl --scan | while read -r dev _; do echo "== $dev"; $SUDO smartctl -H "$dev"; done'
    run $m raid 'cat /proc/mdstat 2>/dev/null; command -v zpool >/dev/null && $SUDO zpool status -x; command -v btrfs >/dev/null && findmnt -t btrfs -no TARGET | while read -r t; do $SUDO btrfs device stats "$t"; done; echo "(fin)"'
    run $m kernel-errors '$SUDO dmesg --level=emerg,alert,crit,err -T 2>&1 | tail -100'
    run $m oom '$SUDO journalctl -k --since "$SINCE" --no-pager -q 2>/dev/null | grep -iE "out of memory|oom-kill" | tail -50 || echo "ninguno"'
    run $m readonly-fs 'findmnt -rno TARGET,OPTIONS | awk "\$2 ~ /(^|,)ro(,|\$)/" | grep -vE "^/(sys|proc|snap)" || echo "ninguno"'
}

mod_virtualization() {
    local m=virtualization
    run $m detect 'systemd-detect-virt 2>/dev/null; systemctl list-units --type=service --no-pager --no-legend 2>/dev/null | grep -Ei "libvirt|proxmox|pve|lxc|lxd|incus|docker|podman|xen|vmware|virtualbox" || echo "ninguno"'
    runif virsh $m libvirt '$SUDO virsh list --all; $SUDO virsh net-list --all'
    runif pveversion $m proxmox 'pveversion -v; $SUDO qm list; $SUDO pct list'
    runif incus $m incus '$SUDO incus list'
    runif lxc $m lxd '$SUDO lxc list'
    run $m bridges 'ip -br link show type bridge; ip -d link show type vlan 2>/dev/null | grep -E "^[0-9]+:|vlan protocol"; command -v bridge >/dev/null && bridge vlan show'
}

# --------------------------------------------------------------------------
# Ejecución
# --------------------------------------------------------------------------
START="$(date -Is)"
log "v$VERSION host=$HOST privilegio=$PRIV salida=$OUT"
[ "$PRIV" = "user" ] && log "AVISO: sin root ni sudo -n; varios controles quedarán incompletos (ver limitations.txt)"

for m in $MODULES; do
    log "módulo: $m"
    "mod_$m"
done

{
    echo "tool: linlinaudit-collector"
    echo "version: $VERSION"
    echo "hostname: $HOST"
    echo "fqdn: $(hostname -f 2>/dev/null || echo "$HOST")"
    echo "os: $(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
    echo "kernel: $(uname -r)"
    echo "run_as: $(id -un) (uid=$(id -u))"
    echo "privilege: $PRIV"
    echo "started: $START"
    echo "finished: $(date -Is)"
    echo "modules: $MODULES"
    echo "quick: $QUICK"
    echo "log_window: $SINCE"
} > "$OUT/manifest.txt"

( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )

if [ "$ARCHIVE" -eq 1 ]; then
    tar -C "$(dirname "$OUT")" -czf "$OUT.tar.gz" "$(basename "$OUT")"
    chmod 600 "$OUT.tar.gz"
    # Si se ejecutó con sudo, entregar el archivo al usuario que lo invocó.
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_UID:-}" ]; then
        chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT.tar.gz" 2>/dev/null
        chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" 2>/dev/null
    fi
    log "archivo: $OUT.tar.gz"
elif [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_UID:-}" ]; then
    chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT" 2>/dev/null
fi

log "limitaciones registradas: $(wc -l < "$LIMITS")"
log "evidencia guardada en $OUT"
