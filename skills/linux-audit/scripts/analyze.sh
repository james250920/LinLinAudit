#!/usr/bin/env bash
#
# LinLinAudit — análisis automático PRELIMINAR de la evidencia recolectada por collect.sh.
#
# Produce <salida>/auto-checks.tsv y <salida>/auto-checks.md con estados
# PASS / FAIL / PARTIAL / N/A / UNKNOWN (README.md §28).
#
# Estos resultados son candidatos: el auditor (humano o agente) debe validarlos
# con validación cruzada (README.md §30) antes de convertirlos en hallazgos.
# Nunca se emite PASS sin evidencia legible; ante la duda se emite UNKNOWN.

set -u
set -o pipefail
export LC_ALL=C

VERSION="1.0.0"

usage() {
    cat >&2 <<EOF
Uso: $0 EVIDENCIA_DIR [-o SALIDA_DIR]

  EVIDENCIA_DIR  Directorio generado por collect.sh
  -o SALIDA_DIR  Dónde escribir auto-checks.{tsv,md} (por defecto: EVIDENCIA_DIR/../analysis-<nombre>)
EOF
}

[ $# -ge 1 ] || { usage; exit 2; }
case "$1" in -h|--help) usage; exit 0 ;; esac
EV="${1%/}"; shift
OUTDIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) OUTDIR="$2"; shift 2 ;;
        *) usage; exit 2 ;;
    esac
done
[ -d "$EV" ] || { echo "no existe: $EV" >&2; exit 2; }
[ -f "$EV/manifest.txt" ] || echo "AVISO: $EV no contiene manifest.txt; ¿es salida de collect.sh?" >&2
[ -n "$OUTDIR" ] || OUTDIR="$(dirname "$EV")/analysis-$(basename "$EV")"
mkdir -p "$OUTDIR"

TSV="$OUTDIR/auto-checks.tsv"
printf 'id\tcontrol\tstatus\tevidence\tdetail\n' > "$TSV"

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
# available <rel>: el archivo existe, no fue omitido y no falló por completo
available() {
    local f="$EV/$1"
    [ -f "$f" ] || return 1
    grep -q '^##LLA skipped' "$f" && return 1
    return 0
}
# body <rel>: contenido sin cabeceras ##LLA
body() { grep -v '^##LLA ' "$EV/$1" 2>/dev/null; }
exitcode() { sed -n 's/^##LLA exit: //p' "$EV/$1" 2>/dev/null | tail -1; }
denied() { grep -qiE 'permission denied|operation not permitted|must be (run as )?root|a password is required|you must be root|are you root|requires root' "$EV/$1" 2>/dev/null; }

emit() { # id control status evidence detail
    local d="${5//$'\t'/ }"
    d="${d//$'\n'/; }"
    printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$d" >> "$TSV"
}

unknown_reason() {
    local rel="$1"
    if [ ! -f "$EV/$rel" ]; then echo "evidencia no recolectada"
    elif grep -q '^##LLA skipped' "$EV/$rel"; then sed -n 's/^##LLA skipped: //p' "$EV/$rel" | head -1
    elif denied "$rel"; then echo "sin privilegios suficientes"
    else echo "salida no interpretable"
    fi
}

# --------------------------------------------------------------------------
# Usuarios
# --------------------------------------------------------------------------
check_users() {
    local f=users/uid0.txt n list
    if available "$f"; then
        n=$(body "$f" | grep -c ':')
        list=$(body "$f" | cut -d: -f1 | paste -sd, -)
        if [ "$n" -le 1 ]; then emit USR-001 "Única cuenta UID 0" PASS "$f" "cuentas UID 0: ${list:-ninguna}"
        else emit USR-001 "Única cuenta UID 0" FAIL "$f" "múltiples cuentas UID 0: $list"; fi
    else emit USR-001 "Única cuenta UID 0" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=users/shadow-status.txt
    if available "$f" && ! denied "$f" && body "$f" | grep -qE ' (SET|LOCKED|EMPTY) '; then
        list=$(body "$f" | awk '$2=="EMPTY"{print $1}' | paste -sd, -)
        if [ -n "$list" ]; then emit USR-002 "Sin cuentas con contraseña vacía" FAIL "$f" "contraseña vacía: $list"
        else emit USR-002 "Sin cuentas con contraseña vacía" PASS "$f" "ninguna cuenta con contraseña vacía"; fi
    else emit USR-002 "Sin cuentas con contraseña vacía" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=users/sudoers-rules.txt
    if available "$f" && ! denied "$f"; then
        n=$(body "$f" | grep -cE 'NOPASSWD|!authenticate')
        if [ "$n" -gt 0 ]; then emit USR-003 "Sudo sin contraseña justificado" PARTIAL "$f" "$n regla(s) NOPASSWD/!authenticate: requieren justificación"
        else emit USR-003 "Sudo sin contraseña justificado" PASS "$f" "sin reglas NOPASSWD"; fi
    else emit USR-003 "Sudo sin contraseña justificado" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=users/interactive-shells.txt
    if available "$f"; then
        list=$(body "$f" | awk -F: '$2 > 0 && $2 < 1000 {print $1}' | paste -sd, -)
        if [ -n "$list" ]; then emit USR-004 "Cuentas de sistema sin shell interactiva" PARTIAL "$f" "cuentas de sistema con shell: $list"
        else emit USR-004 "Cuentas de sistema sin shell interactiva" PASS "$f" "ninguna cuenta de sistema (UID 1-999) con shell interactiva"; fi
    else emit USR-004 "Cuentas de sistema sin shell interactiva" UNKNOWN "$f" "$(unknown_reason "$f")"; fi
}

# --------------------------------------------------------------------------
# SSH
# --------------------------------------------------------------------------
sshval() { body ssh/sshd-effective.txt | awk -v k="$1" 'tolower($1)==k {$1=""; sub(/^ /,""); print; exit}'; }

check_ssh() {
    local f=ssh/sshd-effective.txt v weak=""
    if ! available "$f" || denied "$f" || [ -z "$(sshval permitrootlogin)" ]; then
        local r; r=$(unknown_reason "$f")
        emit SSH-001 "Login directo de root restringido" UNKNOWN "$f" "$r"
        emit SSH-002 "Autenticación por contraseña deshabilitada" UNKNOWN "$f" "$r"
        emit SSH-003 "PermitEmptyPasswords deshabilitado" UNKNOWN "$f" "$r"
        emit SSH-004 "X11Forwarding deshabilitado" UNKNOWN "$f" "$r"
        emit SSH-005 "MaxAuthTries <= 4" UNKNOWN "$f" "$r"
        emit SSH-006 "Sin algoritmos criptográficos débiles" UNKNOWN "$f" "$r"
        return
    fi
    v=$(sshval permitrootlogin)
    case "$v" in
        no) emit SSH-001 "Login directo de root restringido" PASS "$f" "permitrootlogin $v" ;;
        prohibit-password|without-password|forced-commands-only) emit SSH-001 "Login directo de root restringido" PARTIAL "$f" "permitrootlogin $v (root con clave permitido)" ;;
        *) emit SSH-001 "Login directo de root restringido" FAIL "$f" "permitrootlogin $v" ;;
    esac
    v=$(sshval passwordauthentication)
    local kbd; kbd=$(sshval kbdinteractiveauthentication)
    if [ "$v" = "no" ] && [ "$kbd" != "yes" ]; then emit SSH-002 "Autenticación por contraseña deshabilitada" PASS "$f" "passwordauthentication $v; kbdinteractiveauthentication ${kbd:-n/a}"
    else emit SSH-002 "Autenticación por contraseña deshabilitada" FAIL "$f" "passwordauthentication ${v:-?}; kbdinteractiveauthentication ${kbd:-n/a} (evaluar exposición y MFA)"; fi
    v=$(sshval permitemptypasswords)
    if [ "$v" = "no" ]; then emit SSH-003 "PermitEmptyPasswords deshabilitado" PASS "$f" "permitemptypasswords $v"
    else emit SSH-003 "PermitEmptyPasswords deshabilitado" FAIL "$f" "permitemptypasswords ${v:-?}"; fi
    v=$(sshval x11forwarding)
    if [ "$v" = "no" ]; then emit SSH-004 "X11Forwarding deshabilitado" PASS "$f" "x11forwarding $v"
    else emit SSH-004 "X11Forwarding deshabilitado" PARTIAL "$f" "x11forwarding ${v:-?}"; fi
    v=$(sshval maxauthtries)
    if [ -n "$v" ] && [ "$v" -le 4 ] 2>/dev/null; then emit SSH-005 "MaxAuthTries <= 4" PASS "$f" "maxauthtries $v"
    else emit SSH-005 "MaxAuthTries <= 4" PARTIAL "$f" "maxauthtries ${v:-?}"; fi
    weak=$( { sshval ciphers | tr ',' '\n' | grep -E 'cbc|3des|arcfour|blowfish|cast128'
              sshval macs | tr ',' '\n' | grep -E 'md5|-96|^hmac-sha1|umac-64@'
              sshval kexalgorithms | tr ',' '\n' | grep -E 'group1-sha1|group14-sha1|group-exchange-sha1'
            } | paste -sd, -)
    if [ -z "$weak" ]; then emit SSH-006 "Sin algoritmos criptográficos débiles" PASS "$f" "ciphers/macs/kex sin algoritmos obsoletos conocidos"
    else emit SSH-006 "Sin algoritmos criptográficos débiles" PARTIAL "$f" "algoritmos débiles habilitados: $weak"; fi
}

# --------------------------------------------------------------------------
# Sistema (sysctl)
# --------------------------------------------------------------------------
check_sysctl() {
    local f=system/sysctl-security.txt
    if ! available "$f"; then emit SYS-000 "Parámetros sysctl de seguridad" UNKNOWN "$f" "$(unknown_reason "$f")"; return; fi
    # id|clave|valor_esperado|estado_si_no_cumple
    local rules="SYS-001|kernel.randomize_va_space|2|FAIL
SYS-002|fs.protected_symlinks|1|FAIL
SYS-003|fs.protected_hardlinks|1|FAIL
SYS-004|fs.suid_dumpable|0|PARTIAL
SYS-005|kernel.kptr_restrict|1,2|PARTIAL
SYS-006|kernel.dmesg_restrict|1|PARTIAL
SYS-007|net.ipv4.conf.all.accept_source_route|0|FAIL
SYS-008|net.ipv4.conf.all.accept_redirects|0|PARTIAL
SYS-009|net.ipv4.conf.all.send_redirects|0|PARTIAL
SYS-010|net.ipv4.tcp_syncookies|1|PARTIAL
SYS-011|kernel.unprivileged_bpf_disabled|1,2|PARTIAL"
    local id key exp bad val
    while IFS='|' read -r id key exp bad; do
        val=$(body "$f" | awk -v k="$key" '$1==k {print $3; exit}')
        if [ -z "$val" ] || [ "$val" = "<n/a>" ]; then
            emit "$id" "sysctl $key" "N/A" "$f" "parámetro no disponible en este kernel"
        elif [[ ",$exp," == *",$val,"* ]]; then
            emit "$id" "sysctl $key" PASS "$f" "$key = $val"
        else
            emit "$id" "sysctl $key" "$bad" "$f" "$key = $val (esperado: $exp)"
        fi
    done <<< "$rules"
}

# --------------------------------------------------------------------------
# Red
# --------------------------------------------------------------------------
# Imprime "proto dirección puerto proceso" para sockets en escucha no-loopback
listening_public() {
    local rel
    for rel in network/listening-tcp.txt network/listening-udp.txt; do
        available "$rel" || continue
        body "$rel" | awk -v proto="${rel##*-}" '
            $1 ~ /^(LISTEN|UNCONN)$/ {
                addr=$4; port=addr; sub(/.*:/,"",port); a=addr; sub(/:[^:]*$/,"",a)
                gsub(/[][]/,"",a); sub(/%.*/,"",a)
                if (a ~ /^127\./ || a == "::1" || a == "localhost") next
                if (a ~ /^(22[4-9]|23[0-9])\./ || a ~ /^ff[0-9a-f][0-9a-f]:/) next   # multicast
                proc="?"; if (match($0,/users:\(\("[^"]+"/)) { proc=substr($0,RSTART+9,RLENGTH-10) }
                sub(/\.txt$/,"",proto)
                print proto, a, port, proc
            }'
    done | sort -u
}

check_network() {
    local f=network/listening-tcp.txt lst n sens
    if ! available "$f"; then emit NET-001 "Servicios escuchando en interfaces no-loopback revisados" UNKNOWN "$f" "$(unknown_reason "$f")"; return; fi
    lst=$(listening_public)
    n=$(printf '%s\n' "$lst" | grep -c .)
    emit NET-001 "Servicios escuchando en interfaces no-loopback revisados" PARTIAL "network/listening-{tcp,udp}.txt" \
        "$n socket(s) no-loopback — revisar necesidad y exposición: $(printf '%s\n' "$lst" | awk 'NF && ++i<=40 {printf "%s/%s@%s(%s) ", $1,$3,$2,$4} END {if (i>40) printf "... (+%d)", i-40}')"
    # Puertos sensibles (bases de datos, APIs de administración)
    sens=$(printf '%s\n' "$lst" | awk '$1=="tcp" && $3 ~ /^(2375|2376|2379|2380|3306|5432|5984|6379|6443|7001|8086|8500|9000|9090|9200|9300|10250|11211|15672|27017|28017|5601|3389|5900|5901|8006|9443)$/ {printf "%s@%s(%s) ", $3,$2,$4}')
    if [ -n "$sens" ]; then emit NET-002 "Puertos sensibles no expuestos en todas las interfaces" PARTIAL "$f" "puertos sensibles en interfaces no-loopback (validar firewall/NAT): $sens"
    else emit NET-002 "Puertos sensibles no expuestos en todas las interfaces" PASS "$f" "ningún puerto sensible conocido fuera de loopback"; fi
    if printf '%s\n' "$lst" | awk '$1=="tcp" && $3=="2375"' | grep -q .; then
        emit NET-003 "API Docker sin TLS no expuesta" FAIL "$f" "puerto 2375 (API Docker sin TLS) escuchando fuera de loopback"
    fi
}

# --------------------------------------------------------------------------
# Firewall
# --------------------------------------------------------------------------
check_firewall() {
    local active="" evidence="firewall/status.txt" partial_unknown=0
    if available firewall/ufw.txt && body firewall/ufw.txt | grep -q '^Status: active'; then active="$active ufw"; fi
    if available firewall/firewalld.txt && body firewall/firewalld.txt | grep -q '^running'; then active="$active firewalld"; fi
    if available firewall/nftables.txt; then
        if denied firewall/nftables.txt; then partial_unknown=1
        elif body firewall/nftables.txt | grep -qE '^[[:space:]]*(ip|tcp|udp|ct|iif|iifname|meta|counter|drop|reject|accept)' ; then active="$active nftables"; fi
    fi
    if available firewall/iptables.txt; then
        if denied firewall/iptables.txt; then partial_unknown=1
        elif body firewall/iptables.txt | grep -qE '^-A (INPUT|FORWARD)|^-P INPUT (DROP|REJECT)'; then active="$active iptables"; fi
    fi
    if [ -n "$active" ]; then
        emit FW-001 "Firewall activo con reglas" PASS "$evidence" "mecanismos con reglas:$active (comparar puertos escuchando vs permitidos)"
    elif [ "$partial_unknown" -eq 1 ]; then
        emit FW-001 "Firewall activo con reglas" UNKNOWN "$evidence" "no se pudo leer nftables/iptables sin privilegios"
    else
        emit FW-001 "Firewall activo con reglas" FAIL "$evidence" "no se detectó ufw/firewalld activo ni reglas nftables/iptables (verificar firewall perimetral)"
    fi
}

# --------------------------------------------------------------------------
# Servicios
# --------------------------------------------------------------------------
check_services() {
    local f=services/failed.txt n
    if available "$f"; then
        n=$(body "$f" | grep -cE '\.(service|socket|mount|timer)')
        if [ "$n" -eq 0 ]; then emit SVC-001 "Sin unidades systemd fallidas" PASS "$f" "0 unidades fallidas"
        else emit SVC-001 "Sin unidades systemd fallidas" PARTIAL "$f" "$n unidad(es) fallida(s): $(body "$f" | grep -oE '[^ ●*]+\.(service|socket|mount|timer)' | paste -sd, -)"; fi
    else emit SVC-001 "Sin unidades systemd fallidas" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=services/suspicious-exe.txt
    if available "$f" && ! denied "$f"; then
        if body "$f" | grep -q '^ninguno'; then emit SVC-002 "Sin procesos ejecutados desde rutas temporales o borradas" PASS "$f" "ninguno"
        else emit SVC-002 "Sin procesos ejecutados desde rutas temporales o borradas" FAIL "$f" "$(body "$f" | sed -n 's#.*\(/proc/[0-9]*/exe\)#\1#p' | head -10 | paste -sd, -) — investigar (un binario '(deleted)' puede ser solo una actualización sin reinicio)"; fi
    else emit SVC-002 "Sin procesos ejecutados desde rutas temporales o borradas" UNKNOWN "$f" "$(unknown_reason "$f")"; fi
}

# --------------------------------------------------------------------------
# Paquetes
# --------------------------------------------------------------------------
check_packages() {
    local n sec f
    if available packages/apt-upgradable.txt; then
        f=packages/apt-upgradable.txt
        n=$(body "$f" | grep -c 'upgradable from')
        sec=$(body packages/apt-security.txt 2>/dev/null | grep -c 'upgradable from')
        if [ "$n" -eq 0 ]; then emit PKG-001 "Sistema actualizado" PASS "$f" "0 actualizaciones pendientes según caché local (verificar antigüedad de caché)"
        elif [ "$sec" -gt 0 ]; then emit PKG-001 "Sistema actualizado" FAIL "$f" "$n pendientes, $sec de seguridad (según caché local)"
        else emit PKG-001 "Sistema actualizado" PARTIAL "$f" "$n pendientes (según caché local)"; fi
    elif available packages/dnf-check-update.txt; then
        f=packages/dnf-check-update.txt
        local rc; rc=$(body "$f" | sed -n 's/^rc=//p' | tail -1)
        sec=$(body packages/dnf-security.txt 2>/dev/null | grep -cE '^[A-Z]*-?[0-9]{4}-|/Sec\.|[Ss]ecurity')
        case "$rc" in
            0)   emit PKG-001 "Sistema actualizado" PASS "$f" "0 actualizaciones pendientes según caché local (verificar antigüedad de caché)" ;;
            100) n=$(body "$f" | grep -cE '^[A-Za-z0-9_.+-]+\.(x86_64|noarch|aarch64|i686|armv7hl|ppc64le|s390x)[[:space:]]')
                 if [ "$sec" -gt 0 ]; then emit PKG-001 "Sistema actualizado" FAIL "$f" "$n pendientes, $sec avisos de seguridad (según caché local)"
                 else emit PKG-001 "Sistema actualizado" PARTIAL "$f" "$n pendientes (según caché local)"; fi ;;
            *)   emit PKG-001 "Sistema actualizado" UNKNOWN "$f" "dnf --cacheonly falló (rc=${rc:-?}); caché vacía o sin permisos" ;;
        esac
    elif available packages/pacman-upgradable.txt; then
        f=packages/pacman-upgradable.txt
        n=$(body "$f" | grep -c ' -> ')
        if [ "$n" -eq 0 ]; then emit PKG-001 "Sistema actualizado" PASS "$f" "0 pendientes según base local (requiere sync reciente)"
        else emit PKG-001 "Sistema actualizado" PARTIAL "$f" "$n pendientes"; fi
    elif available packages/zypper-updates.txt; then
        f=packages/zypper-updates.txt
        n=$(body "$f" | grep -c '^v ')
        if [ "$n" -eq 0 ]; then emit PKG-001 "Sistema actualizado" PASS "$f" "0 pendientes según caché local"
        else emit PKG-001 "Sistema actualizado" PARTIAL "$f" "$n pendientes"; fi
    elif available packages/apk-upgradable.txt; then
        f=packages/apk-upgradable.txt
        n=$(body "$f" | grep -c '<')
        if [ "$n" -eq 0 ]; then emit PKG-001 "Sistema actualizado" PASS "$f" "0 pendientes"
        else emit PKG-001 "Sistema actualizado" PARTIAL "$f" "$n pendientes"; fi
    else
        emit PKG-001 "Sistema actualizado" UNKNOWN "packages/" "gestor de paquetes no reconocido o no recolectado"
    fi

    f=packages/reboot-required.txt
    if available "$f"; then
        local running latest
        running=$(body "$f" | sed -n 's/^running_kernel=//p')
        latest=$(body "$f" | grep '^/boot/vmlinuz-' | sed 's#^/boot/vmlinuz-##' | grep -vE 'rescue' | sort -V | tail -1)
        if body "$f" | grep -q REBOOT_REQUIRED; then
            emit PKG-002 "Sin reinicio pendiente" PARTIAL "$f" "flag /var/run/reboot-required presente"
        elif available packages/needs-restarting.txt && body packages/needs-restarting.txt | grep -qiE 'reboot (is required|should)'; then
            emit PKG-002 "Sin reinicio pendiente" PARTIAL "packages/needs-restarting.txt" "needs-restarting -r indica reinicio necesario"
        elif [ -n "$latest" ] && [ -n "$running" ] && [ "$latest" != "$running" ]; then
            emit PKG-002 "Sin reinicio pendiente" PARTIAL "$f" "kernel en ejecución $running, más reciente instalado $latest"
        else
            emit PKG-002 "Sin reinicio pendiente" PASS "$f" "kernel en ejecución ${running:-?}"
        fi
    fi

    f=packages/repos.txt
    if available "$f"; then
        n=$(body "$f" | grep -cE 'gpgcheck[[:space:]]*=[[:space:]]*0')
        if [ "$n" -gt 0 ]; then emit PKG-003 "Repositorios con verificación GPG" FAIL "$f" "$n repositorio(s) con gpgcheck=0: $(body "$f" | grep -E 'gpgcheck[[:space:]]*=[[:space:]]*0' | cut -d: -f1 | sort -u | paste -sd, -)"
        else emit PKG-003 "Repositorios con verificación GPG" PASS "$f" "sin gpgcheck=0"; fi
    elif available packages/apt-sources.txt; then
        n=$(body packages/apt-sources.txt | grep -cE 'trusted=yes|allow-insecure=yes')
        if [ "$n" -gt 0 ]; then emit PKG-003 "Repositorios con verificación GPG" FAIL "packages/apt-sources.txt" "$n fuente(s) con trusted=yes/allow-insecure"
        else emit PKG-003 "Repositorios con verificación GPG" PASS "packages/apt-sources.txt" "sin trusted=yes"; fi
    fi
}

# --------------------------------------------------------------------------
# Sistema de archivos
# --------------------------------------------------------------------------
KNOWN_SUID="su sudo sudoedit passwd chsh chfn newgrp gpasswd mount umount pkexec ping ping6 fusermount fusermount3 ssh-keysign dbus-daemon-launch-helper polkit-agent-helper-1 Xorg.wrap unix_chkpwd pam_timestamp_check crontab at chage expiry sg userhelper newuidmap newgidmap mount.nfs mount.cifs mount.ecryptfs_private snap-confine chrome-sandbox pppd ksu staprun traceroute6.iputils write wall ssh-agent locate mlocate plocate bsd-write dotlockfile utempter lxc-user-nic vmware-user-suid-wrapper grub2-set-bootflag suexec cockpit-session Xorg sm-client lockdev netreport usernetctl mount.davfs ntfs-3g exim4 postdrop postqueue qemu-bridge-helper spice-client-glib-usb-acl-helper nvidia-modprobe"

check_filesystem() {
    local f n list b unexpected=""
    f=filesystem/suid.txt
    if available "$f" && ! denied "$f"; then
        while read -r _ _ path; do
            [ -n "${path:-}" ] || continue
            b=$(basename "$path")
            case " $KNOWN_SUID " in *" $b "*) ;; *) unexpected="$unexpected $path" ;; esac
        done < <(body "$f" | grep -E '^[0-7]{3,4} ')
        n=$(body "$f" | grep -cE '^[0-7]{3,4} ')
        if [ -z "$unexpected" ]; then emit FS-001 "Binarios SUID esperados" PASS "$f" "$n binarios SUID, todos en la lista de conocidos"
        else emit FS-001 "Binarios SUID esperados" PARTIAL "$f" "$n binarios SUID; no reconocidos:$unexpected"; fi
    else emit FS-001 "Binarios SUID esperados" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=filesystem/world-writable-files.txt
    if available "$f"; then
        n=$(body "$f" | grep -cE '^[0-7]{3,4} ')
        if [ "$n" -eq 0 ]; then emit FS-002 "Sin archivos world-writable" PASS "$f" "0 archivos"
        else emit FS-002 "Sin archivos world-writable" PARTIAL "$f" "$n archivo(s): $(body "$f" | grep -E '^[0-7]{3,4} ' | awk '{print $3}' | head -10 | paste -sd, -)"; fi
    else emit FS-002 "Sin archivos world-writable" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=filesystem/world-writable-dirs.txt
    if available "$f"; then
        # Directorios world-writable SIN sticky bit (modo sin 1xxx)
        list=$(body "$f" | awk '$1 ~ /^[0-7]+$/ { m=$1; if (length(m)==4) s=substr(m,1,1); else s="0"; if (s!="1" && s!="3" && s!="5" && s!="7") print $3 }')
        if [ -z "$list" ]; then emit FS-003 "Directorios world-writable con sticky bit" PASS "$f" "todos los directorios world-writable tienen sticky bit"
        else emit FS-003 "Directorios world-writable con sticky bit" FAIL "$f" "sin sticky bit: $(printf '%s\n' "$list" | head -10 | paste -sd, -)"; fi
    else emit FS-003 "Directorios world-writable con sticky bit" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=filesystem/tmp-mounts.txt
    if available "$f"; then
        local line opts missing=""
        line=$(body "$f" | awk -F'\t' '$1=="/tmp"{print $2}')
        if [ -z "$line" ] || [[ "$line" == *"no es punto de montaje"* ]]; then
            emit FS-004 "/tmp con nodev,nosuid,noexec" PARTIAL "$f" "/tmp no es un punto de montaje separado"
        else
            opts=$(printf '%s' "$line" | awk '{print $NF}')
            for o in nodev nosuid noexec; do [[ ",$opts," == *",$o,"* ]] || missing="$missing $o"; done
            if [ -z "$missing" ]; then emit FS-004 "/tmp con nodev,nosuid,noexec" PASS "$f" "$opts"
            else emit FS-004 "/tmp con nodev,nosuid,noexec" PARTIAL "$f" "faltan:$missing (opciones: $opts)"; fi
        fi
    else emit FS-004 "/tmp con nodev,nosuid,noexec" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=filesystem/critical-perms.txt
    if available "$f"; then
        local bad
        bad=$(body "$f" | awk '
            { m=$1; o=substr(m,length(m),1); g=substr(m,length(m)-1,1) }
            $3 ~ /\/(shadow|gshadow)$/ && o != "0" { print $3" ("m")" ; next }
            $3 ~ /\/sudoers$/ && (o != "0") { print $3" ("m")"; next }
            $3 ~ /grub2?\/grub\.cfg$/ && (o ~ /[2367]/) { print $3" ("m")"; next }
            (o ~ /[2367]/ || g ~ /[2367]/) && $3 !~ /\/(shadow|gshadow)$/ { print $3" ("m")" }')
        if [ -z "$bad" ]; then emit FS-005 "Permisos de archivos críticos" PASS "$f" "passwd/shadow/sudoers/sshd_config con permisos restrictivos"
        else emit FS-005 "Permisos de archivos críticos" FAIL "$f" "permisos laxos: $(printf '%s\n' "$bad" | paste -sd, -)"; fi
    else emit FS-005 "Permisos de archivos críticos" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=filesystem/unowned.txt
    if available "$f" && ! denied "$f"; then
        n=$(body "$f" | grep -cE '^[0-7]{3,4} ')
        if [ "$n" -eq 0 ]; then emit FS-006 "Sin archivos huérfanos (sin usuario/grupo)" PASS "$f" "0"
        else emit FS-006 "Sin archivos huérfanos (sin usuario/grupo)" PARTIAL "$f" "$n archivo(s) sin usuario o grupo válido"; fi
    else emit FS-006 "Sin archivos huérfanos (sin usuario/grupo)" UNKNOWN "$f" "$(unknown_reason "$f")"; fi
}

# --------------------------------------------------------------------------
# Logs, auditd, MAC
# --------------------------------------------------------------------------
check_logging() {
    local f=logs/journald-conf.txt
    if available "$f"; then
        if body "$f" | grep -qiE '^Storage=persistent' || body "$f" | grep -qE '^d.* /var/log/journal$'; then
            emit LOG-001 "Journal persistente" PASS "$f" "journald con almacenamiento persistente"
        elif body "$f" | grep -qiE '^Storage=(volatile|none)'; then
            emit LOG-001 "Journal persistente" FAIL "$f" "journald sin persistencia (Storage=volatile/none)"
        else
            emit LOG-001 "Journal persistente" PARTIAL "$f" "no existe /var/log/journal; verificar syslog tradicional"
        fi
    else emit LOG-001 "Journal persistente" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=logs/remote-forwarding.txt
    if available "$f"; then
        if body "$f" | grep -q '^ninguno'; then emit LOG-002 "Logs centralizados / reenviados" PARTIAL "$f" "no se detectó reenvío remoto de logs (puede existir un agente no cubierto)"
        else emit LOG-002 "Logs centralizados / reenviados" PASS "$f" "configuración de reenvío detectada"; fi
    fi

    f=auditd/status.txt
    if available "$f"; then
        if body "$f" | head -1 | grep -qx active; then emit AUD-001 "auditd activo" PASS "$f" "auditd active"
        else emit AUD-001 "auditd activo" FAIL "$f" "auditd: $(body "$f" | head -1)"; fi
        if available auditd/rules.txt && ! denied auditd/rules.txt; then
            if body auditd/rules.txt | grep -q '^No rules'; then emit AUD-002 "Reglas de auditd cargadas" FAIL auditd/rules.txt "sin reglas"
            else emit AUD-002 "Reglas de auditd cargadas" PASS auditd/rules.txt "$(body auditd/rules.txt | grep -c '^-') regla(s)"; fi
        fi
    else emit AUD-001 "auditd activo" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    local se="" aa=""
    available mac/selinux-mode.txt && se=$(body mac/selinux-mode.txt | head -1)
    if available mac/apparmor.txt && ! denied mac/apparmor.txt; then aa=$(body mac/apparmor.txt | grep -oE '^[0-9]+ profiles are in enforce mode' | awk '{print $1}'); fi
    if [ "$se" = "Enforcing" ]; then emit MAC-001 "SELinux/AppArmor en modo enforcing" PASS mac/selinux-mode.txt "SELinux Enforcing"
    elif [ -n "$aa" ] && [ "$aa" -gt 0 ]; then emit MAC-001 "SELinux/AppArmor en modo enforcing" PASS mac/apparmor.txt "AppArmor: $aa perfiles en enforce"
    elif [ "$se" = "Permissive" ]; then emit MAC-001 "SELinux/AppArmor en modo enforcing" PARTIAL mac/selinux-mode.txt "SELinux Permissive"
    elif [ "$se" = "Disabled" ] || [ "$aa" = "0" ]; then emit MAC-001 "SELinux/AppArmor en modo enforcing" FAIL "mac/" "SELinux=${se:-n/a} AppArmor_enforce=${aa:-n/a}"
    elif available mac/apparmor.txt && denied mac/apparmor.txt; then emit MAC-001 "SELinux/AppArmor en modo enforcing" UNKNOWN mac/apparmor.txt "aa-status requiere privilegios"
    else emit MAC-001 "SELinux/AppArmor en modo enforcing" FAIL "mac/" "no se detectó SELinux ni AppArmor"; fi
}

# --------------------------------------------------------------------------
# Tareas programadas
# --------------------------------------------------------------------------
check_scheduled() {
    local f=scheduled/suspicious.txt n
    if available "$f"; then
        n=$(body "$f" | grep -vc '^(fin)$')
        if [ "$n" -eq 0 ]; then emit SCH-001 "Tareas programadas sin patrones sospechosos" PASS "$f" "sin curl/wget/tmp/base64 en cron"
        else emit SCH-001 "Tareas programadas sin patrones sospechosos" PARTIAL "$f" "$n línea(s) con curl/wget/tmp/pipe a shell: revisar origen y propietario"; fi
    else emit SCH-001 "Tareas programadas sin patrones sospechosos" UNKNOWN "$f" "$(unknown_reason "$f")"; fi
}

# --------------------------------------------------------------------------
# Contenedores
# --------------------------------------------------------------------------
check_containers() {
    local f=containers/docker-summary.txt
    if ! available containers/docker-version.txt; then
        emit CTR-000 "Docker" "N/A" containers/docker-version.txt "Docker no instalado"
    elif ! available "$f" || denied "$f" || body "$f" | grep -qiE 'cannot connect|permission denied'; then
        emit CTR-000 "Docker" UNKNOWN "$f" "no se pudo consultar el daemon Docker"
    elif body "$f" | grep -q '^sin contenedores'; then
        emit CTR-000 "Docker" "N/A" "$f" "Docker instalado, sin contenedores"
    else
        local priv hostnet hostpid sock nomem root
        priv=$(body "$f" | awk '/ privileged=true /{print $1}' | paste -sd, -)
        hostnet=$(body "$f" | awk '/ network=host /{print $1}' | paste -sd, -)
        hostpid=$(body "$f" | awk '/ pid=host /{print $1}' | paste -sd, -)
        sock=$(body "$f" | awk '/docker\.sock->/{print $1}' | paste -sd, -)
        nomem=$(body "$f" | awk '/ memory=0 /{print $1}' | paste -sd, -)
        root=$(body "$f" | awk '/ user= |user=root |user=0 |user=0:/{print $1}' | paste -sd, -)
        if [ -n "$priv" ]; then emit CTR-001 "Sin contenedores privilegiados" FAIL "$f" "privileged: $priv"; else emit CTR-001 "Sin contenedores privilegiados" PASS "$f" "ninguno"; fi
        if [ -n "$hostnet$hostpid" ]; then emit CTR-002 "Sin namespaces del host compartidos" PARTIAL "$f" "network=host: ${hostnet:-ninguno}; pid=host: ${hostpid:-ninguno}"; else emit CTR-002 "Sin namespaces del host compartidos" PASS "$f" "ninguno"; fi
        if [ -n "$sock" ]; then emit CTR-003 "docker.sock no montado en contenedores" FAIL "$f" "montan docker.sock: $sock (equivale a root en el host)"; else emit CTR-003 "docker.sock no montado en contenedores" PASS "$f" "ninguno"; fi
        if [ -n "$nomem" ]; then emit CTR-004 "Contenedores con límite de memoria" PARTIAL "$f" "sin límite: $nomem"; else emit CTR-004 "Contenedores con límite de memoria" PASS "$f" "todos con límite"; fi
        if [ -n "$root" ]; then emit CTR-005 "Contenedores sin usuario root" PARTIAL "$f" "usuario root/por defecto: $root (verificar USER de la imagen)"; else emit CTR-005 "Contenedores sin usuario root" PASS "$f" "todos con usuario no-root"; fi
    fi
    f=containers/docker-daemon.txt
    if available "$f"; then
        if body "$f" | grep -qE -- '-H[= ]*tcp://|"hosts".*tcp://' && ! body "$f" | grep -qE -- '--tlsverify|"tlsverify": *true'; then
            emit CTR-006 "API Docker no expuesta por TCP sin TLS" FAIL "$f" "dockerd configurado con -H tcp:// sin --tlsverify"
        else
            emit CTR-006 "API Docker no expuesta por TCP sin TLS" PASS "$f" "sin listener TCP inseguro"
        fi
    fi
}

# --------------------------------------------------------------------------
# Secretos
# --------------------------------------------------------------------------
check_secrets() {
    local f=secrets/pattern-files.txt n
    if available "$f" && ! denied "$f"; then
        n=$(body "$f" | grep -cE '^[0-7]{3,4} ')
        local wr; wr=$(body "$f" | awk '$1 ~ /[4567]$/ {print $3}' | head -10 | paste -sd, -)
        if [ -n "$wr" ]; then emit SEC-001 "Archivos con secretos no legibles por todos" PARTIAL "$f" "$n coincidencia(s); legibles por cualquier usuario (validar manualmente, posibles falsos positivos): $wr"
        elif [ "$n" -gt 0 ]; then emit SEC-001 "Archivos con secretos no legibles por todos" PARTIAL "$f" "$n archivo(s) con patrones de secreto (permisos restringidos; revisar necesidad)"
        else emit SEC-001 "Archivos con secretos no legibles por todos" PASS "$f" "sin coincidencias"; fi
    else emit SEC-001 "Archivos con secretos no legibles por todos" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=secrets/private-keys.txt
    if available "$f" && ! denied "$f"; then
        local bad; bad=$(body "$f" | awk '$1 ~ /^[0-7]+$/ && substr($1,length($1)-1,2) != "00" {print $3" ("$1")"}' | head -10 | paste -sd, -)
        if [ -n "$bad" ]; then emit SEC-002 "Claves privadas con permisos restrictivos" FAIL "$f" "accesibles por grupo/otros: $bad"
        else emit SEC-002 "Claves privadas con permisos restrictivos" PASS "$f" "$(body "$f" | grep -cE '^[0-7]{3,4} ') clave(s), todas 600/400"; fi
    else emit SEC-002 "Claves privadas con permisos restrictivos" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=secrets/env-files.txt
    if available "$f"; then
        local wr2; wr2=$(body "$f" | awk '$1 ~ /[4567]$/ {print $3}' | head -10 | paste -sd, -)
        if [ -n "$wr2" ]; then emit SEC-003 "Archivos .env no legibles por todos" FAIL "$f" "legibles por cualquier usuario: $wr2"
        else emit SEC-003 "Archivos .env no legibles por todos" PASS "$f" "$(body "$f" | grep -cE '^[0-7]{3,4} ') archivo(s) .env sin lectura global"; fi
    fi
}

# --------------------------------------------------------------------------
# Capacidad
# --------------------------------------------------------------------------
check_capacity() {
    local f=capacity/disk.txt full warn
    if available "$f"; then
        full=$(body "$f" | awk 'NR>1 {p=$6; sub(/%/,"",p); if (p+0 >= 90) print $7"("$6")"}' | paste -sd, -)
        warn=$(body "$f" | awk 'NR>1 {p=$6; sub(/%/,"",p); if (p+0 >= 80 && p+0 < 90) print $7"("$6")"}' | paste -sd, -)
        if [ -n "$full" ]; then emit CAP-001 "Uso de disco < 80%" FAIL "$f" ">=90%: $full ${warn:+; >=80%: $warn}"
        elif [ -n "$warn" ]; then emit CAP-001 "Uso de disco < 80%" PARTIAL "$f" ">=80%: $warn"
        else emit CAP-001 "Uso de disco < 80%" PASS "$f" "todos los filesystems < 80%"; fi
    else emit CAP-001 "Uso de disco < 80%" UNKNOWN "$f" "$(unknown_reason "$f")"; fi

    f=capacity/inodes.txt
    if available "$f"; then
        full=$(body "$f" | awk 'NR>1 && $5 ~ /%/ {p=$5; sub(/%/,"",p); if (p+0 >= 80) print $6"("$5")"}' | paste -sd, -)
        if [ -n "$full" ]; then emit CAP-002 "Uso de inodos < 80%" PARTIAL "$f" "$full"
        else emit CAP-002 "Uso de inodos < 80%" PASS "$f" "todos < 80%"; fi
    fi

    f=capacity/smart.txt
    if available "$f" && ! denied "$f"; then
        if body "$f" | grep -qE 'FAILED|FAILING'; then emit CAP-003 "Salud SMART" FAIL "$f" "fallo SMART en: $(body "$f" | grep -B3 -E 'FAILED|FAILING' | grep '^==' | sed 's/^== //' | paste -sd, -)"
        elif body "$f" | grep -qE 'PASSED|OK'; then emit CAP-003 "Salud SMART" PASS "$f" "$(body "$f" | grep -c '^==') disco(s) PASSED"
        else emit CAP-003 "Salud SMART" UNKNOWN "$f" "sin discos SMART (VM o controladora sin soporte)"; fi
    fi

    f=capacity/raid.txt
    if available "$f"; then
        if body "$f" | grep -qE '\[[U_]*_[U_]*\]|DEGRADED|FAULTED|UNAVAIL'; then emit CAP-004 "RAID/pools sin degradación" FAIL "$f" "array o pool degradado"
        elif body "$f" | grep -qE 'md[0-9]|all pools are healthy|pool:'; then emit CAP-004 "RAID/pools sin degradación" PASS "$f" "sin degradación"; fi
    fi

    f=capacity/readonly-fs.txt
    if available "$f"; then
        local ro; ro=$(body "$f" | grep -v '^ninguno' | awk '{print $1}' | grep -vE '^/(sys|proc|boot/efi|run/credentials)' | paste -sd, -)
        if [ -n "$ro" ]; then emit CAP-005 "Sin filesystems en solo lectura inesperados" PARTIAL "$f" "montados ro: $ro"; fi
    fi
}

# --------------------------------------------------------------------------
# Backups
# --------------------------------------------------------------------------
check_backups() {
    local f=backups/tools.txt tools refs
    if available "$f"; then
        tools=$(body "$f" | grep -v '^(fin)' | cut -d: -f1 | grep -vx rsync | paste -sd, -)
        refs=$(body backups/references.txt 2>/dev/null | grep -vc '^(fin)')
        if [ -n "$tools" ] || [ "${refs:-0}" -gt 0 ]; then
            emit BKP-001 "Backups configurados" PARTIAL "$f" "herramientas: ${tools:-ninguna dedicada}; referencias en cron/systemd: ${refs:-0}. Configurado ≠ verificado ≠ restore probado"
        else
            emit BKP-001 "Backups configurados" UNKNOWN "$f" "no se detectó backup local (puede gestionarse externamente: PBS, NAS, snapshots del hypervisor) — preguntar al administrador"
        fi
    fi
    emit BKP-002 "Restore probado" UNKNOWN "-" "no verificable automáticamente: requiere evidencia de prueba de restauración"
}

# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------
check_tls() {
    local f=webapps/certificates.txt now exp soon="" expired="" cur="" end ts
    available "$f" || return
    body "$f" | grep -q '^==' || { emit TLS-001 "Certificados vigentes" "N/A" "$f" "no se encontraron certificados en rutas conocidas"; return; }
    now=$(date +%s)
    while IFS= read -r line; do
        case "$line" in
            "== "*) cur="${line#== }" ;;
            notAfter=*)
                end="${line#notAfter=}"
                ts=$(date -d "$end" +%s 2>/dev/null) || continue
                if [ "$ts" -lt "$now" ]; then expired="$expired $cur"
                elif [ "$ts" -lt $((now + 30*86400)) ]; then soon="$soon $cur"; fi ;;
        esac
    done < <(body "$f")
    if [ -n "$expired" ]; then emit TLS-001 "Certificados vigentes" FAIL "$f" "vencidos:$expired${soon:+; vencen en <30 días:$soon}"
    elif [ -n "$soon" ]; then emit TLS-001 "Certificados vigentes" PARTIAL "$f" "vencen en <30 días:$soon"
    else emit TLS-001 "Certificados vigentes" PASS "$f" "$(body "$f" | grep -c '^==') certificado(s) vigentes > 30 días"; fi
}

# --------------------------------------------------------------------------
check_users
check_ssh
check_sysctl
check_network
check_firewall
check_services
check_packages
check_filesystem
check_logging
check_scheduled
check_containers
check_secrets
check_capacity
check_backups
check_tls

# --------------------------------------------------------------------------
# Resumen Markdown
# --------------------------------------------------------------------------
MD="$OUTDIR/auto-checks.md"
{
    echo "# Controles automáticos (preliminares)"
    echo
    echo "- Evidencia: \`$EV\`"
    [ -f "$EV/manifest.txt" ] && sed -n 's/^\(hostname\|os\|kernel\|privilege\|started\): \(.*\)$/- \1: \2/p' "$EV/manifest.txt"
    echo "- Analizador: v$VERSION — $(date -Is)"
    echo
    echo "> Resultados candidatos. Cada FAIL/PARTIAL debe validarse (README §30) antes de"
    echo "> registrarse como hallazgo. UNKNOWN ≠ PASS."
    echo
    echo "| Estado | Cantidad |"
    echo "|---|---|"
    for s in FAIL PARTIAL UNKNOWN PASS N/A; do
        printf '| %s | %s |\n' "$s" "$(awk -F'\t' -v s="$s" 'NR>1 && $3==s' "$TSV" | wc -l)"
    done
    echo
    echo "| ID | Control | Estado | Evidencia | Detalle |"
    echo "|---|---|---|---|---|"
    awk -F'\t' 'NR>1 {
        o = ($3=="FAIL")?1:($3=="PARTIAL")?2:($3=="UNKNOWN")?3:($3=="PASS")?4:5
        gsub(/\|/,"\\|",$5); print o "\t| " $1 " | " $2 " | **" $3 "** | `" $4 "` | " $5 " |"
    }' "$TSV" | sort -t$'\t' -k1,1n -s | cut -f2-
    if [ -s "$EV/limitations.txt" ]; then
        echo
        echo "## Limitaciones de la recolección"
        echo
        echo '```text'
        cat "$EV/limitations.txt"
        echo '```'
    fi
} > "$MD"

echo "auto-checks: $TSV"
echo "resumen:     $MD"
awk -F'\t' 'NR>1 {c[$3]++} END {printf "FAIL=%d PARTIAL=%d UNKNOWN=%d PASS=%d N/A=%d\n", c["FAIL"], c["PARTIAL"], c["UNKNOWN"], c["PASS"], c["N/A"]}' "$TSV"
