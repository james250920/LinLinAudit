#!/usr/bin/env bash
#
# LinLinAudit — ejecuta collect.sh en un servidor remoto por SSH y trae la evidencia.
#
# Huella en el servidor remoto: un directorio temporal (mktemp -d, modo 700) con el
# script y la evidencia, que se elimina al terminar. No se modifica nada más.
#
# Uso:
#   remote-collect.sh [opciones] [usuario@]host [-- opciones de collect.sh]
#
# Opciones:
#   -d, --dest DIR     Directorio local base (por defecto ./linux-audit/servers)
#   -p, --port PUERTO  Puerto SSH
#   -i, --identity F   Clave SSH
#       --sudo         Ejecuta el colector con sudo (pedirá contraseña en una TTY si hace falta)
#   -h, --help
#
# Ejemplo:
#   remote-collect.sh --sudo admin@192.168.1.10 -- --quick --since "3 days ago"

set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECT="$HERE/collect.sh"
DEST="./linux-audit/servers"
USE_SUDO=0
SSH_OPTS=(-o ControlMaster=auto -o "ControlPath=${TMPDIR:-/tmp}/lla-ssh-%C" -o ControlPersist=120)
TARGET=""
COLLECT_ARGS=()

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//' >&2; }
die() { printf '[remote-collect] ERROR: %s\n' "$*" >&2; exit 2; }
log() { printf '[remote-collect] %s\n' "$*" >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        -d|--dest)     DEST="$2"; shift 2 ;;
        -p|--port)     SSH_OPTS+=(-p "$2"); shift 2 ;;
        -i|--identity) SSH_OPTS+=(-i "$2"); shift 2 ;;
        --sudo)        USE_SUDO=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        --)            shift; COLLECT_ARGS=("$@"); break ;;
        -*)            die "opción desconocida: $1" ;;
        *)             [ -z "$TARGET" ] || die "solo se admite un host"; TARGET="$1"; shift ;;
    esac
done
[ -n "$TARGET" ] || { usage; exit 2; }
[ -f "$COLLECT" ] || die "no se encuentra $COLLECT"
for a in "${COLLECT_ARGS[@]+"${COLLECT_ARGS[@]}"}"; do
    case "$a" in -o|--output|--archive|--redact) die "la opción $a la gestiona remote-collect.sh" ;; esac
done

rssh() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }

log "conectando con $TARGET"
RDIR="$(rssh 'umask 077; mktemp -d /tmp/linlinaudit.XXXXXX')" || die "no se pudo crear el directorio temporal remoto"
RDIR="${RDIR//$'\r'/}"
case "$RDIR" in /tmp/linlinaudit.*) ;; *) die "respuesta inesperada del host remoto: $RDIR" ;; esac

cleanup() {
    log "eliminando $RDIR en $TARGET"
    if [ "$USE_SUDO" -eq 1 ]; then
        ssh -t "${SSH_OPTS[@]}" "$TARGET" "sudo rm -rf '$RDIR'" </dev/tty 2>/dev/null || rssh "rm -rf '$RDIR'"
    else
        rssh "rm -rf '$RDIR'"
    fi
    ssh "${SSH_OPTS[@]}" -O exit "$TARGET" 2>/dev/null || true
}
trap cleanup EXIT

rssh "cat > '$RDIR/collect.sh'" < "$COLLECT" || die "no se pudo copiar collect.sh"

REMOTE_HOST="$(rssh 'hostname' | tr -d '\r')"
TS="$(date +%Y%m%d-%H%M%S)"
NAME="evidence-$TS"

ARGS=""
for a in "${COLLECT_ARGS[@]+"${COLLECT_ARGS[@]}"}"; do ARGS="$ARGS $(printf '%q' "$a")"; done

if [ "$USE_SUDO" -eq 1 ]; then
    log "ejecutando collect.sh con sudo (puede solicitar contraseña)"
    ssh -t "${SSH_OPTS[@]}" "$TARGET" "sudo bash '$RDIR/collect.sh' -o '$RDIR/$NAME' --archive $ARGS" </dev/tty \
        || log "AVISO: collect.sh terminó con error; se intentará recuperar la evidencia parcial"
else
    rssh "bash '$RDIR/collect.sh' -o '$RDIR/$NAME' --archive $ARGS" </dev/null \
        || log "AVISO: collect.sh terminó con error; se intentará recuperar la evidencia parcial"
fi

OUTBASE="$DEST/${REMOTE_HOST:-$TARGET}/evidence"
mkdir -p "$OUTBASE"
chmod 700 "$DEST" 2>/dev/null || true
rssh "cat '$RDIR/$NAME.tar.gz'" > "$OUTBASE/$NAME.tar.gz" || die "no se pudo descargar la evidencia"
[ -s "$OUTBASE/$NAME.tar.gz" ] || die "el archivo descargado está vacío"
chmod 600 "$OUTBASE/$NAME.tar.gz"

tar -C "$OUTBASE" -xzf "$OUTBASE/$NAME.tar.gz" || die "no se pudo extraer el archivo"
if ( cd "$OUTBASE/$NAME" && sha256sum -c --quiet SHA256SUMS ); then
    log "integridad verificada (SHA256SUMS)"
else
    log "AVISO: la verificación SHA256SUMS falló"
fi

log "evidencia: $OUTBASE/$NAME"
echo "$OUTBASE/$NAME"
