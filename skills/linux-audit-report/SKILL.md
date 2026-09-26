---
name: linux-audit-report
description: Genera el informe final de una auditoría de seguridad Linux/Homelab (README §32) a partir de la evidencia, la baseline y los hallazgos producidos por el skill linux-audit - executive summary, arquitectura observada, hallazgos ordenados por severidad, baseline, limitaciones y resumen del plan de remediación. Usar cuando el usuario pida el informe, reporte o resumen ejecutivo de una auditoría Linux ya realizada.
argument-hint: "[ruta del workspace linux-audit]"
---

# Informe final de auditoría (REPORT)

Construye `linux-audit/report/final-report.md` (varios servidores) o
`linux-audit/servers/<host>/report.md` (un servidor) usando `templates/report.md` de este skill.

## Entradas

Localiza el workspace (por defecto `./linux-audit/`; si no existe, pregunta la ruta):

- `scope/scope.md` — alcance, autorización, limitaciones.
- `servers/<host>/evidence/evidence-<ts>/manifest.txt` y `limitations.txt` — por cada captura.
- `servers/<host>/analysis-evidence-<ts>/auto-checks.md` — controles automáticos.
- `servers/<host>/findings/FINDING-*.md` — hallazgos.
- `servers/<host>/baseline.md` — matriz de controles.
- `remediation/plan.md` — si existe.

Si faltan hallazgos o baseline, no los inventes: indica al usuario que primero ejecute
`/linux-audit` (o complétalos con él) y detente.

## Reglas

1. **Solo lo que respalda la evidencia.** Cada hallazgo del informe enlaza a su archivo
   `FINDING-NNN.md` y al archivo de evidencia. No añadas hallazgos que no estén documentados.
2. **Secretos redactados.** Revisa que ningún extracto contenga contraseñas, tokens, hashes o claves
   (`PASSWORD=<REDACTED>`). Ante la duda, pasa el texto por `collect.sh --redact` del skill
   `linux-audit`.
3. **Orden por severidad** (CRITICAL → INFORMATIONAL). Dentro del mismo nivel, por ID; sin rankings
   subjetivos entre hallazgos del mismo nivel.
4. **Limitaciones explícitas**: controles `UNKNOWN`, módulos omitidos, ejecución sin root, caché de
   paquetes antigua, exposición externa no verificada.
5. **Estado real**: si hubo remediación, usa el estado validado (`RESOLVED` solo con evidencia
   posterior; ver `/linux-audit-compare`).
6. Informe en el idioma del usuario; conserva los nombres de estados y severidades en inglés
   (`HIGH`, `PASS`, `OPEN`) como en la metodología.

## Procedimiento

1. Cuenta hallazgos por severidad y estado (lee la tabla de cada `FINDING-*.md`).
2. Redacta el **Executive Summary**: 3–6 frases sobre la postura general, riesgos principales y
   acción prioritaria, legibles por alguien no técnico.
3. **Arquitectura observada**: diagrama ASCII (README §24/§32) con lo verificado; marca con `?`
   lo supuesto.
4. **Superficie expuesta**: tabla de puertos/servicios expuestos con su justificación.
5. **Hallazgos**: por cada uno, el bloque del README §32 (Severity, Asset, Category, Description,
   Evidence, Impact, Recommendation, Validation, Status). Puedes resumir la evidencia y enlazar el
   archivo completo.
6. **Baseline**: incorpora la matriz de cada servidor.
7. **Plan de remediación resumido**: Quick Wins / Hardening / Architecture (README §33).
8. **Respuestas del README §38**: responde brevemente cada pregunta con lo que se sabe, o
   "desconocido" y por qué.
9. **Anexos**: lista de capturas de evidencia con hash de `SHA256SUMS` (`sha256sum SHA256SUMS`),
   versión del colector y fecha.

Al terminar, muestra al usuario la ruta del informe y el conteo por severidad. Si el usuario quiere
compartirlo, ofrece revisar antes que no contenga datos internos que no deba divulgar (IPs, nombres
de host, usuarios).
