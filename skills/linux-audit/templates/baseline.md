# Baseline de seguridad — <hostname>

Captura de evidencia: `evidence-<ts>` · Fecha: <fecha>

Estados: `PASS` · `FAIL` · `PARTIAL` · `N/A` · `UNKNOWN`. Nunca `PASS` sin evidencia suficiente.

| Control | Estado | Evidencia | Observación |
|---|---|---|---|
| Sistema operativo soportado (no EOL) | | `inventory/os-release.txt` | |
| Sistema actualizado | | `packages/` · PKG-001 | |
| Reinicio pendiente aplicado | | `packages/reboot-required.txt` · PKG-002 | |
| Repositorios verificados (GPG) | | PKG-003 | |
| Firewall activo | | `firewall/` · FW-001 | |
| Puertos escuchando = necesarios | | `network/listening-*.txt` · NET-001/002 | |
| SSH endurecido | | `ssh/sshd-effective.txt` · SSH-002…006 | |
| Root SSH restringido | | SSH-001 | |
| Claves SSH autorizadas revisadas | | `ssh/authorized-keys*.txt` | |
| Usuarios revisados | | `users/` · USR-001/002/004 | |
| Sudo revisado | | `users/sudoers-rules.txt` · USR-003 | |
| Parámetros de kernel (sysctl) | | `system/sysctl-security.txt` · SYS-* | |
| Servicios revisados | | `services/` · SVC-001/002 | |
| Permisos de archivos críticos | | FS-005 | |
| SUID/SGID revisados | | FS-001 | |
| Sin world-writable indebidos | | FS-002/003 | |
| Logs activos y persistentes | | LOG-001 | |
| Logs centralizados | | LOG-002 | |
| Auditd | | AUD-001/002 | |
| SELinux/AppArmor | | MAC-001 | |
| Cron / timers revisados | | `scheduled/` · SCH-001 | |
| Docker/Podman seguro | | `containers/` · CTR-* | |
| Kubernetes seguro | | `kubernetes/` | |
| TLS / certificados | | `webapps/` · TLS-001 | |
| Paneles administrativos protegidos | | `webapps/`, `network/` | |
| Secretos protegidos | | `secrets/` · SEC-* | |
| Integridad de paquetes | | `integrity/` | |
| Backups configurados y ejecutados | | `backups/` · BKP-001 | |
| Restore probado | | BKP-002 | |
| Disco saludable (espacio, SMART, RAID) | | `capacity/` · CAP-* | |
| Monitorización | | <!-- preguntar al administrador --> | |

## Limitaciones

<!-- Copiar lo relevante de limitations.txt y explicar qué controles quedaron UNKNOWN y por qué. -->
