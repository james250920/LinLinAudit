#!/usr/bin/env bash
#
# Tests de LinLinAudit. Uso: tests/run-tests.sh
#
#  1. Sintaxis bash y shellcheck (si está instalado).
#  2. Validez de los manifiestos del plugin y del frontmatter de los skills.
#  3. Redacción de secretos.
#  4. analyze.sh sobre fixtures (inseguro / endurecido) con estados esperados.
#  5. compare.sh entre fixtures.
#  6. collect.sh real sobre esta máquina (sin sudo, --quick, módulos ligeros).

set -u
set -o pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COLLECT="$ROOT/skills/linux-audit/scripts/collect.sh"
ANALYZE="$ROOT/skills/linux-audit/scripts/analyze.sh"
COMPARE="$ROOT/skills/linux-audit-compare/scripts/compare.sh"
FIX="$ROOT/tests/fixtures"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ $# -gt 1 ] && printf '       %s\n' "$2"; }
section() { printf '\n== %s\n' "$1"; }

mapfile -t SCRIPTS < <(find "$ROOT" -name '*.sh' -not -path '*/.git/*' | sort)

section "Sintaxis"
for s in "${SCRIPTS[@]}"; do
    if bash -n "$s" 2>"$TMP/err"; then ok "bash -n ${s#"$ROOT"/}"; else fail "bash -n ${s#"$ROOT"/}" "$(cat "$TMP/err")"; fi
done
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "${SCRIPTS[@]}" > "$TMP/sc" 2>&1; then ok "shellcheck (warning+)"; else fail "shellcheck" "$(head -40 "$TMP/sc")"; fi
else
    echo "  (shellcheck no instalado: omitido)"
fi

section "Manifiestos y skills"
if command -v jq >/dev/null 2>&1; then
    for j in "$ROOT"/.claude-plugin/*.json; do
        if jq -e . "$j" >/dev/null 2>&1; then ok "JSON válido: ${j#"$ROOT"/}"; else fail "JSON inválido: ${j#"$ROOT"/}"; fi
    done
    v1=$(jq -r .version "$ROOT/.claude-plugin/plugin.json")
    v2=$(jq -r '.plugins[0].version' "$ROOT/.claude-plugin/marketplace.json")
    v3=$(sed -n 's/^VERSION="\(.*\)"/\1/p' "$COLLECT")
    if [ "$v1" = "$v2" ] && [ "$v1" = "$v3" ]; then ok "versiones coherentes ($v1)"; else fail "versiones incoherentes" "plugin=$v1 marketplace=$v2 collect=$v3"; fi
else
    echo "  (jq no instalado: validación JSON omitida)"
fi
for sk in "$ROOT"/skills/*/SKILL.md; do
    dir=$(basename "$(dirname "$sk")")
    name=$(awk 'NR==1 && $0!="---"{exit 1} NR>1 && /^---$/{exit} /^name:/{sub(/^name:[ ]*/,""); print}' "$sk")
    desc=$(awk 'NR>1 && /^---$/{exit} /^description:/{print}' "$sk")
    if [ "$name" = "$dir" ] && [ -n "$desc" ]; then ok "frontmatter $dir"; else fail "frontmatter $dir" "name='$name'"; fi
    # Todo recurso relativo citado en SKILL.md debe existir
    for ref in $(grep -oE '`(scripts|references|templates)/[A-Za-z0-9_.-]+`' "$sk" | tr -d '`' | sort -u); do
        if [ -e "$(dirname "$sk")/$ref" ]; then ok "$dir → $ref"; else fail "$dir cita recurso inexistente: $ref"; fi
    done
done

section "Redacción de secretos"
redacted=$(printf '%s\n' \
    'DB_PASSWORD=hunter2' \
    '"api_key": "AKIA123456"' \
    'token: abcdef123' \
    'requirepass s3cr3t' \
    'Authorization: Bearer eyJhbGciOi.x.y' \
    'postgres://app:pa55@db/app' \
    '-----BEGIN RSA PRIVATE KEY-----' 'MIIEowIBAAKCAQEA' '-----END RSA PRIVATE KEY-----' \
    'PasswordAuthentication yes' | bash "$COLLECT" --redact)
for leak in hunter2 AKIA123456 abcdef123 s3cr3t eyJhbGciOi pa55 MIIEowIBAAKCAQEA; do
    if printf '%s' "$redacted" | grep -q "$leak"; then fail "no redacta: $leak"; else ok "redacta: $leak"; fi
done
if printf '%s' "$redacted" | grep -q 'PasswordAuthentication yes'; then ok "no altera directivas sshd"; else fail "altera 'PasswordAuthentication yes'"; fi

section "analyze.sh — fixture inseguro"
bash "$ANALYZE" "$FIX/insecure" -o "$TMP/an-insecure" >/dev/null 2>&1 || fail "analyze.sh terminó con error (inseguro)"
expect() { # tsv id estado
    local got; got=$(awk -F'\t' -v id="$2" '$1==id{print $3}' "$1")
    if [ "$got" = "$3" ]; then ok "$2 = $3"; else fail "$2 esperado $3, obtenido '${got:-<ausente>}'"; fi
}
T="$TMP/an-insecure/auto-checks.tsv"
for pair in USR-001:FAIL USR-002:FAIL USR-003:PARTIAL USR-004:PARTIAL \
            SSH-001:FAIL SSH-002:FAIL SSH-003:PASS SSH-004:PARTIAL SSH-005:PARTIAL SSH-006:PARTIAL \
            SYS-001:FAIL SYS-011:N/A NET-002:PARTIAL NET-003:FAIL FW-001:FAIL \
            SVC-001:PARTIAL SVC-002:FAIL PKG-001:FAIL PKG-002:PARTIAL PKG-003:FAIL \
            FS-001:PARTIAL FS-002:PARTIAL FS-003:FAIL FS-004:PARTIAL FS-005:FAIL \
            LOG-001:FAIL AUD-001:FAIL MAC-001:FAIL SCH-001:PARTIAL \
            CTR-001:FAIL CTR-002:PARTIAL CTR-003:FAIL CTR-004:PARTIAL CTR-005:PARTIAL CTR-006:FAIL \
            SEC-002:FAIL SEC-003:FAIL CAP-001:FAIL CAP-003:FAIL CAP-004:FAIL \
            BKP-001:UNKNOWN BKP-002:UNKNOWN TLS-001:FAIL; do
    expect "$T" "${pair%%:*}" "${pair#*:}"
done
if grep -q '5353' "$T"; then fail "NET-001 incluye multicast 224.0.0.251"; else ok "NET-001 ignora multicast"; fi

section "analyze.sh — fixture endurecido"
bash "$ANALYZE" "$FIX/hardened" -o "$TMP/an-hardened" >/dev/null 2>&1 || fail "analyze.sh terminó con error (endurecido)"
T="$TMP/an-hardened/auto-checks.tsv"
n=$(awk -F'\t' 'NR>1 && $3=="FAIL"' "$T" | wc -l)
if [ "$n" -eq 0 ]; then ok "sin FAIL en servidor endurecido"; else fail "FAIL inesperados en endurecido" "$(awk -F'\t' '$3=="FAIL"{print $1": "$5}' "$T")"; fi
for pair in SSH-001:PASS SSH-002:PASS FW-001:PASS MAC-001:PASS CTR-003:PASS BKP-001:PARTIAL BKP-002:UNKNOWN TLS-001:PASS; do
    expect "$T" "${pair%%:*}" "${pair#*:}"
done

grep -P '^SEC-003\t' "$TMP/an-insecure/auto-checks.tsv" | grep -q '/home/alice/app/.env' \
    && fail "SEC-003 marca un .env no alcanzable (reach=no)" || ok "SEC-003 ignora .env no alcanzable por otros"

section "analyze.sh — recolección sin privilegios ⇒ sin PASS de visibilidad"
cp -r "$FIX/hardened" "$TMP/lowpriv"
sed -i 's/^privilege: .*/privilege: user/' "$TMP/lowpriv/manifest.txt"
bash "$ANALYZE" "$TMP/lowpriv" -o "$TMP/an-lowpriv" >/dev/null 2>&1
T="$TMP/an-lowpriv/auto-checks.tsv"
for pair in FS-001:UNKNOWN FS-002:UNKNOWN FS-003:UNKNOWN SVC-002:UNKNOWN SCH-001:UNKNOWN SEC-002:UNKNOWN SEC-003:UNKNOWN SSH-001:PASS; do
    expect "$T" "${pair%%:*}" "${pair#*:}"
done

section "analyze.sh — sin evidencia ⇒ UNKNOWN, nunca PASS"
mkdir -p "$TMP/empty"; echo "hostname: vacío" > "$TMP/empty/manifest.txt"
bash "$ANALYZE" "$TMP/empty" -o "$TMP/an-empty" >/dev/null 2>&1
n=$(awk -F'\t' 'NR>1 && $3=="PASS"' "$TMP/an-empty/auto-checks.tsv" | wc -l)
if [ "$n" -eq 0 ]; then ok "evidencia vacía no produce PASS"; else fail "evidencia vacía produjo $n PASS" "$(awk -F'\t' '$3=="PASS"{print $1}' "$TMP/an-empty/auto-checks.tsv" | paste -sd, -)"; fi

section "compare.sh"
cp -r "$FIX/insecure" "$TMP/before"; cp -r "$FIX/hardened" "$TMP/after"
if bash "$COMPARE" "$TMP/before" "$TMP/after" -o "$TMP/cmp.md" >/dev/null 2>&1; then ok "compare.sh ejecuta"; else fail "compare.sh terminó con error"; fi
grep -q 'SSH-001 .*FAIL | PASS | ✅ mejora' "$TMP/cmp.md" && ok "detecta mejora SSH-001" || fail "no detecta mejora SSH-001"
grep -q 'ssh/sshd-effective.txt' "$TMP/cmp.md" && ok "diff de evidencia SSH" || fail "sin diff de evidencia SSH"
bash "$COMPARE" "$TMP/after" "$TMP/before" > "$TMP/cmp2.md" 2>/dev/null
grep -q '❌ regresión' "$TMP/cmp2.md" && ok "detecta regresiones" || fail "no detecta regresiones"

section "collect.sh (ejecución real, sin sudo, --quick)"
if bash "$COLLECT" --no-sudo --quick -m inventory,users,network,secrets -o "$TMP/ev" 2>"$TMP/collect.log"; then ok "collect.sh termina"; else fail "collect.sh falló" "$(tail -5 "$TMP/collect.log")"; fi
for f in manifest.txt commands.tsv limitations.txt SHA256SUMS inventory/os-release.txt users/uid0.txt network/listening-tcp.txt; do
    [ -f "$TMP/ev/$f" ] && ok "existe $f" || fail "falta $f"
done
[ "$(stat -c %a "$TMP/ev")" = "700" ] && ok "directorio de evidencia con modo 700" || fail "modo del directorio: $(stat -c %a "$TMP/ev")"
(cd "$TMP/ev" && sha256sum -c --quiet SHA256SUMS) && ok "SHA256SUMS verifica" || fail "SHA256SUMS no verifica"
grep -q '^##LLA exit: ' "$TMP/ev/users/uid0.txt" && ok "cabeceras ##LLA presentes" || fail "faltan cabeceras ##LLA"
if bash "$COLLECT" -m noexiste -o "$TMP/ev-bad" 2>/dev/null; then fail "acepta módulo desconocido"; else ok "rechaza módulo desconocido"; fi
if bash "$COLLECT" --no-sudo -m inventory -o "$TMP/ev" 2>/dev/null; then fail "sobrescribe evidencia existente"; else ok "no sobrescribe evidencia existente"; fi

printf '\n%d ok, %d fallos\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
