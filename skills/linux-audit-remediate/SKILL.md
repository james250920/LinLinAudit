---
name: linux-audit-remediate
description: Fases REVIEW, REMEDIATION y VALIDATION de una auditoría de seguridad Linux/Homelab - revisa hallazgos con el administrador, construye un plan de remediación (Quick Wins / Hardening / Architecture) con backup, validación y rollback por cambio, y aplica ÚNICAMENTE los cambios que el usuario autorice explícitamente, uno a uno. Invocar solo manualmente tras /linux-audit.
argument-hint: "[FINDING-NNN ... | plan]"
disable-model-invocation: true
---

# Revisión, remediación y validación

Implementa README §33–§36 (modos REVIEW → REMEDIATION → VALIDATION). Este skill **sí puede
modificar sistemas**, por eso tiene reglas más estrictas que la auditoría.

Recursos de este skill (directorio base mostrado al cargarlo):

- `templates/remediation-plan.md` — plan de remediación.
- `references/remediation-playbook.md` — procedimientos seguros por tipo de hallazgo.

## Reglas no negociables

1. **Autorización por cambio.** Antes de cada cambio muestra: hallazgo, comandos exactos, impacto
   esperado, riesgo (p. ej. perder acceso SSH), backup y rollback. Ejecuta solo tras un "sí"
   explícito para **ese** cambio. Una aprobación no se extiende a otros cambios ni a otros servidores.
2. **Nunca** borrar usuarios, datos, volúmenes o contenedores; nunca rotar credenciales ni reiniciar
   el servidor sin petición expresa. Prefiere desactivar/bloquear a eliminar.
3. **Backup antes de editar**: `cp -a archivo archivo.bak-lla-<fecha>` y registra la ruta.
4. **Validar la sintaxis antes de recargar** (`sshd -t`, `nginx -t`, `visudo -c`, `nft -c -f`…).
5. **No cortar el acceso**: para SSH y firewall, mantén abierta la sesión actual, recarga (no
   reinicies) y pide al usuario que pruebe una **nueva** conexión antes de cerrar la actual.
   Para cambios de firewall remotos, propone un rollback temporizado.
6. **Secretos**: nunca los muestres; si un hallazgo requiere rotarlos, indícalo como acción del
   administrador.
7. Registra todo en `remediation/changelog.md`: fecha, servidor, hallazgo, comandos, backup,
   resultado de validación.

## Flujo

### 1. REVIEW

1. Lee `linux-audit/servers/*/findings/FINDING-*.md` (o los IDs pasados como argumento).
2. Repasa con el usuario cada hallazgo: ¿es correcto?, ¿el servicio es necesario?, ¿hay controles
   compensatorios que no vimos? Ajusta severidad o marca `ACCEPTED_RISK` (con justificación y
   responsable) según lo que decida el usuario.

### 2. Plan

Crea `linux-audit/remediation/plan.md` con `templates/remediation-plan.md`, agrupando en:

- **Quick Wins** — bajo riesgo y alta claridad.
- **Hardening** — requiere planificación (SSH, firewall, MAC, contenedores, segmentación).
- **Architecture** — cambios estructurales (VLANs, VPN, reverse proxy, logs centralizados, backups, DR).

Para cada acción usa el procedimiento correspondiente de `references/remediation-playbook.md`,
adaptado a la distro y al mecanismo detectado en la evidencia (no asumir UFW, systemd, etc.).

### 3. REMEDIATION

Solo acciones autorizadas, una por vez, siguiendo las reglas. Si el usuario debe introducir la
contraseña de sudo, pídele que ejecute el comando con el prefijo `!`. Para servidores remotos, usa
`ssh usuario@host '<comando>'` o pide al usuario que abra la sesión.

Si algo falla: detente, aplica el rollback, informa.

### 4. VALIDATION

Para cada cambio aplicado:

1. Ejecuta el comando de la sección **Validación** del hallazgo y guarda la salida en
   `linux-audit/servers/<host>/evidence/manual/validation-<FINDING>-<ts>.txt` (primera línea = comando).
2. Confirma que el servicio afectado sigue funcionando.
3. Actualiza el estado del hallazgo: `RESOLVED` (con referencia a la evidencia),
   `PARTIALLY_REMEDIATED` o se mantiene `OPEN`. **Nunca** `RESOLVED` solo porque se ejecutó el
   comando de configuración.
4. Recomienda al terminar una re-captura completa y `/linux-audit-compare` (README §34).
