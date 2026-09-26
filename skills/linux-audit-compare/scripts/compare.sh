#!/usr/bin/env bash
#
# LinLinAudit — compara dos capturas de evidencia (antes / después) de collect.sh.
#
# Uso: compare.sh ANTES_DIR DESPUES_DIR [-o informe.md]
#
# 1. Ejecuta analyze.sh sobre ambas capturas (si no existe el análisis) y compara
#    el estado de cada control automático.
# 2. Compara archivos de evidencia estables (usuarios, SSH, puertos, firewall,
#    servicios, SUID, cron, contenedores...), normalizando datos volátiles (PIDs).
#
# README.md §34: un hallazgo solo pasa a RESOLVED con evidencia posterior.

set -u
set -o pipefail
export LC_ALL=C

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZE=""
for c in "$HERE/../../linux-audit/scripts/analyze.sh" "$HERE/analyze.sh"; do
    [ -f "$c" ] && { ANALYZE="$c"; break; }
done

usage() { echo "Uso: $0 ANTES_DIR DESPUES_DIR [-o informe.md]" >&2; }
[ $# -ge 2 ] || { usage; exit 2; }
A="${1%/}"; B="${2%/}"; shift 2
OUT=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) OUT="$2"; shift 2 ;;
        *) usage; exit 2 ;;
    esac
done
[ -d "$A" ] || { echo "no existe: $A" >&2; exit 2; }
[ -d "$B" ] || { echo "no existe: $B" >&2; exit 2; }

analysis_of() {
    local ev="$1" dir
    dir="$(dirname "$ev")/analysis-$(basename "$ev")"
    if [ ! -f "$dir/auto-checks.tsv" ]; then
        [ -n "$ANALYZE" ] || { echo "analyze.sh no encontrado" >&2; return 1; }
        bash "$ANALYZE" "$ev" -o "$dir" >/dev/null || return 1
    fi
    echo "$dir/auto-checks.tsv"
}

# Normalización de archivos volátiles antes del diff
normalize() { # rel file
    local rel="$1" f="$2"
    grep -v '^##LLA ' "$f" 2>/dev/null | case "$rel" in
        network/listening-tcp.txt|network/listening-udp.txt)
            awk '$1 ~ /^(LISTEN|UNCONN)$/ { p="-"; if (match($0,/users:\(\("[^"]+"/)) p=substr($0,RSTART+9,RLENGTH-10); print $1, $4, p }' | sort -u ;;
        services/running.txt)
            awk '{print $1}' | sort ;;
        containers/docker-summary.txt)
            sort ;;
        filesystem/suid.txt|filesystem/sgid.txt|secrets/*.txt)
            sort ;;
        *) cat ;;
    esac
}

STABLE_FILES="
users/passwd.txt
users/uid0.txt
users/interactive-shells.txt
users/admin-groups.txt
users/sudoers-rules.txt
users/shadow-status.txt
ssh/sshd-effective.txt
ssh/authorized-keys-fp.txt
system/sysctl-security.txt
network/listening-tcp.txt
network/listening-udp.txt
firewall/status.txt
firewall/ufw.txt
firewall/firewalld.txt
firewall/nftables.txt
firewall/iptables.txt
services/running.txt
services/failed.txt
filesystem/tmp-mounts.txt
filesystem/critical-perms.txt
filesystem/suid.txt
filesystem/sgid.txt
filesystem/world-writable-files.txt
auditd/status.txt
auditd/rules.txt
mac/selinux-mode.txt
scheduled/etc-crontab.txt
scheduled/cron-d-content.txt
scheduled/user-crontabs.txt
scheduled/timers.txt
containers/docker-summary.txt
containers/docker-daemon.txt
secrets/pattern-files.txt
secrets/private-keys.txt
secrets/env-files.txt
"

TA="$(analysis_of "$A")" || exit 1
TB="$(analysis_of "$B")" || exit 1

report() {
    echo "# Comparación de auditorías"
    echo
    echo "| | Antes | Después |"
    echo "|---|---|---|"
    for k in hostname started privilege modules; do
        printf '| %s | %s | %s |\n' "$k" \
            "$(sed -n "s/^$k: //p" "$A/manifest.txt" 2>/dev/null)" \
            "$(sed -n "s/^$k: //p" "$B/manifest.txt" 2>/dev/null)"
    done
    local ha hb
    ha=$(sed -n 's/^hostname: //p' "$A/manifest.txt" 2>/dev/null)
    hb=$(sed -n 's/^hostname: //p' "$B/manifest.txt" 2>/dev/null)
    if [ -n "$ha" ] && [ "$ha" != "$hb" ]; then
        echo
        echo "> **AVISO:** los hostnames difieren ($ha ≠ $hb). ¿Es el mismo servidor?"
    fi
    if [ "$(sed -n 's/^privilege: //p' "$A/manifest.txt" 2>/dev/null)" != "$(sed -n 's/^privilege: //p' "$B/manifest.txt" 2>/dev/null)" ]; then
        echo
        echo "> **AVISO:** las capturas se hicieron con privilegios distintos; las diferencias pueden deberse a visibilidad, no a cambios reales."
    fi

    echo
    echo "## Controles automáticos"
    echo
    echo "| ID | Control | Antes | Después | Cambio |"
    echo "|---|---|---|---|---|"
    awk -F'\t' '
        function rank(s) { return (s=="PASS")?4:(s=="N/A")?3:(s=="PARTIAL")?2:(s=="UNKNOWN")?1:(s=="FAIL")?0:-1 }
        FNR==1 { next }
        NR==FNR { a[$1]=$3; n[$1]=$2; order[++i]=$1; next }
        { b[$1]=$3; n[$1]=$2; if (!($1 in a)) order[++i]=$1 }
        END {
            for (k=1; k<=i; k++) {
                id=order[k]; sa=(id in a)?a[id]:"—"; sb=(id in b)?b[id]:"—"
                if (sa==sb) ch="="
                else if (sa=="—") ch="nuevo"
                else if (sb=="—") ch="ya no evaluado"
                else if (sa=="UNKNOWN" || sb=="UNKNOWN") ch="visibilidad"
                else if (rank(sb)>rank(sa)) ch="✅ mejora"
                else ch="❌ regresión"
                if (sa!=sb) printf "| %s | %s | %s | %s | %s |\n", id, n[id], sa, sb, ch
            }
        }' "$TA" "$TB"
    local same
    same=$(awk -F'\t' 'FNR==1{next} NR==FNR{a[$1]=$3; next} ($1 in a) && a[$1]==$3' "$TA" "$TB" | wc -l)
    echo
    echo "Controles sin cambios: $same"

    echo
    echo "## Diferencias en evidencia"
    local rel fa fb d changed=0
    for rel in $STABLE_FILES; do
        fa="$A/$rel"; fb="$B/$rel"
        [ -f "$fa" ] || [ -f "$fb" ] || continue
        d=$(diff -u --label "antes/$rel" --label "después/$rel" \
                <(normalize "$rel" "$fa") <(normalize "$rel" "$fb"))
        [ -n "$d" ] || continue
        changed=$((changed + 1))
        echo
        echo "### \`$rel\`"
        echo
        echo '```diff'
        printf '%s\n' "$d" | head -80
        [ "$(printf '%s\n' "$d" | wc -l)" -gt 80 ] && echo "... (diff truncado; ver archivos completos)"
        echo '```'
    done
    [ "$changed" -eq 0 ] && { echo; echo "Sin diferencias en los archivos de evidencia estables."; }
    echo
    echo "---"
    echo "Recordatorio (README §34): marcar RESOLVED solo si el control mejora con evidencia posterior"
    echo "y el servicio sigue funcionando. Cambios en UNKNOWN indican diferencia de visibilidad."
}

if [ -n "$OUT" ]; then
    report > "$OUT"
    echo "informe: $OUT"
else
    report
fi
