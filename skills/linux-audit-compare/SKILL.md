---
name: linux-audit-compare
description: Re-auditoría (README §34) - compara dos capturas de evidencia de linux-audit (antes y después de una remediación o entre dos ciclos de hardening), muestra mejoras, regresiones y cambios en usuarios, SSH, puertos, firewall, servicios, SUID, cron y contenedores, y actualiza el estado de los hallazgos con evidencia. Usar cuando el usuario pida validar una remediación, comparar auditorías o ver qué cambió en un servidor.
argument-hint: "[host] [captura-antes] [captura-después]"
---

# Re-auditoría y comparación

## Procedimiento

1. **Nueva captura.** Si no existe una captura posterior al cambio, obtenla con el skill `linux-audit`
   (mismos módulos y, sobre todo, **mismo nivel de privilegio** que la captura anterior; si no,
   las diferencias reflejarán visibilidad y no cambios reales).
2. **Comparar.** Con las capturas en `linux-audit/servers/<host>/evidence/`:

   ```bash
   bash SKILL_DIR/scripts/compare.sh \
       linux-audit/servers/<host>/evidence/evidence-<antes> \
       linux-audit/servers/<host>/evidence/evidence-<después> \
       -o linux-audit/servers/<host>/compare-<antes>_vs_<después>.md
   ```

   `SKILL_DIR` es el directorio base de este skill. El script ejecuta `analyze.sh` (del skill
   `linux-audit`) sobre ambas capturas si falta el análisis, compara estados de control
   (mejora / regresión / visibilidad) y hace `diff` normalizado de la evidencia estable.
3. **Interpretar.**
   - `✅ mejora` en un control ligado a un hallazgo → candidato a `RESOLVED`; confirma que la
     evidencia posterior demuestra la corrección y que el servicio funciona.
   - `❌ regresión` o cambios inesperados (usuarios, claves SSH, puertos, timers, SUID nuevos) →
     informa al usuario de inmediato; pueden ser nuevos hallazgos.
   - `visibilidad` → diferencias por privilegios/herramientas; no concluyas nada de ellas.
4. **Actualizar hallazgos.** En cada `FINDING-NNN.md` afectado, cambia `Estado` y añade al historial
   la fecha y la referencia a la captura/archivo que lo demuestra:
   `OPEN` · `PARTIALLY_REMEDIATED` · `RESOLVED` · `ACCEPTED_RISK`.
   **Nunca** `RESOLVED` sin evidencia posterior.
5. **Baseline.** Actualiza `baseline.md` con la nueva captura y resume al usuario: controles
   mejorados, regresiones, hallazgos cerrados y pendientes.
