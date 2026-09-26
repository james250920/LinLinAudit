#!/usr/bin/env bash
#
# Instala los skills de LinLinAudit sin usar el sistema de plugins de Claude Code.
#
#   ./install.sh               # usuario: ~/.claude/skills (disponible en todos los proyectos)
#   ./install.sh --project DIR # proyecto: DIR/.claude/skills
#   ./install.sh --copy        # copia en vez de enlace simbólico
#   ./install.sh --uninstall   # elimina los enlaces/copias instalados
#
# Alternativa recomendada (plugin):
#   /plugin marketplace add james250920/LinLinAudit
#   /plugin install linlinaudit@linlinaudit

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${HOME}/.claude/skills"
MODE="link"
ACTION="install"

while [ $# -gt 0 ]; do
    case "$1" in
        --project)   TARGET="$(cd "${2:?falta DIR}" && pwd)/.claude/skills"; shift 2 ;;
        --copy)      MODE="copy"; shift ;;
        --uninstall) ACTION="uninstall"; shift ;;
        -h|--help)   sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "opción desconocida: $1" >&2; exit 2 ;;
    esac
done

mkdir -p "$TARGET"
for dir in "$REPO"/skills/*/; do
    name="$(basename "$dir")"
    dest="$TARGET/$name"
    if [ "$ACTION" = "uninstall" ]; then
        if [ -L "$dest" ] || { [ -d "$dest" ] && [ -f "$dest/SKILL.md" ]; }; then
            rm -rf "$dest"; echo "eliminado: $dest"
        fi
        continue
    fi
    if [ -e "$dest" ] && [ ! -L "$dest" ]; then
        echo "omitido (ya existe y no es un enlace): $dest" >&2
        continue
    fi
    rm -f "$dest"
    if [ "$MODE" = "copy" ]; then
        cp -a "$dir" "$dest"
    else
        ln -s "${dir%/}" "$dest"
    fi
    echo "instalado: $dest"
done

if [ "$ACTION" = "install" ]; then
    echo "Listo. En Claude Code: /linux-audit, /linux-audit-report, /linux-audit-remediate, /linux-audit-compare"
fi
