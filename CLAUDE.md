# LinLinAudit — guía para contribuir

Plugin de Claude Code con skills para auditar servidores Linux/Homelab. `README.md` es la
**metodología** (fuente de verdad); los skills la implementan.

## Estructura

```text
.claude-plugin/            plugin.json + marketplace.json (versión = VERSION de collect.sh)
skills/
  linux-audit/             DISCOVERY + AUDIT
    SKILL.md
    scripts/collect.sh     colector read-only (módulos mod_*)
    scripts/analyze.sh     controles automáticos (check_*) → auto-checks.tsv/md
    scripts/remote-collect.sh
    references/            phases.md (guía por fase), severity.md
    templates/             scope, finding, baseline
  linux-audit-report/      informe final
  linux-audit-remediate/   remediación (disable-model-invocation: true)
  linux-audit-compare/     re-auditoría (compare.sh usa ../../linux-audit/scripts/analyze.sh)
tests/run-tests.sh         suite completa; fixtures en tests/fixtures/{insecure,hardened}
```

## Reglas para el colector (`collect.sh`)

- **Estrictamente read-only.** Nada que modifique estado: ni `apt update`, ni `dnf makecache`,
  ni reinicios, ni escritura fuera del directorio de salida. Gestores de paquetes con caché local
  (`--cacheonly`, `--no-refresh`).
- **Sin secretos**: nunca leer `/etc/shadow` más allá del estado; nunca `docker inspect` completo;
  para secretos solo rutas y permisos (`grep -l`, `stat`). Toda salida pasa por `redact()`.
- Comandos en comillas simples y `$SUDO` expandido dentro de `bash -c` (queda literal en la
  cabecera `##LLA command:` para reproducibilidad).
- Herramientas opcionales con `runif <tool>`; escaneos pesados detrás de `--quick`/`run_t`.
- Compatibilidad: bash ≥ 4, GNU coreutils/findutils/sed. Probar en Debian/Ubuntu y Fedora/RHEL.

## Reglas para el analizador (`analyze.sh`)

- Nunca `PASS` si la evidencia falta, fue omitida o dio error de permisos → `UNKNOWN`.
- Los IDs de control (`SSH-001`…) son estables: se usan en plantillas, baseline y `compare.sh`.
  No renumerar; añadir nuevos al final de su prefijo.
- Todo control nuevo necesita casos en `tests/fixtures/insecure` y `hardened` y una línea en
  `tests/run-tests.sh`.

## Verificación

```bash
bash tests/run-tests.sh          # requiere jq; shellcheck recomendado
```

Al cambiar la versión, actualizar `plugin.json`, `marketplace.json`, `VERSION` en `collect.sh`
y `CHANGELOG.md` (el test comprueba que coincidan).
