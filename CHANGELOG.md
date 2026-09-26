# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y
[SemVer](https://semver.org/lang/es/).

## [1.0.1] - 2026-09-25

### Corregido

- `analyze.sh`: los controles que requieren visibilidad completa (FS-001/002/003/006, SVC-002,
  SCH-001, SEC-001/002/003) devolvían `PASS` en recolecciones sin root/sudo, aunque `find`/`grep`
  omitían en silencio lo que no podían leer. Ahora devuelven `UNKNOWN`.
- `collect.sh`: `secrets/env-files` y `secrets/pattern-files` indican `reach=yes|no` según si otros
  usuarios pueden atravesar los directorios padre; SEC-001/SEC-003 ya no marcan archivos dentro de
  directorios privados (p. ej. un home 700).

## [1.0.0] - 2026-09-25

### Añadido

- Plugin de Claude Code `linlinaudit` (`.claude-plugin/plugin.json`, `marketplace.json`).
- Skill `linux-audit`: DISCOVERY + AUDIT con alcance, recolección, análisis, hallazgos y baseline.
- Skill `linux-audit-report`: informe final (README §32).
- Skill `linux-audit-remediate`: REVIEW / REMEDIATION / VALIDATION con autorización por cambio
  (solo invocable manualmente).
- Skill `linux-audit-compare`: re-auditoría antes/después (README §34).
- `collect.sh`: colector read-only con 21 módulos, redacción de secretos, `manifest.txt`,
  `commands.tsv`, `limitations.txt`, `SHA256SUMS` y modo `--archive`.
- `remote-collect.sh`: ejecución remota por SSH con limpieza del directorio temporal.
- `analyze.sh`: ~55 controles automáticos preliminares (`PASS/FAIL/PARTIAL/N/A/UNKNOWN`).
- `compare.sh`: comparación de controles y diff normalizado de evidencia.
- Plantillas: alcance, hallazgo, baseline, informe, plan de remediación.
- Referencias: guía por fase, severidad y playbook de remediación.
- Tests (`tests/run-tests.sh`) con fixtures y CI en Ubuntu, Debian, Fedora y Rocky Linux.
