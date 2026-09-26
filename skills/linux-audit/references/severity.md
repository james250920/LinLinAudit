# Severidad, IDs y calibración

## Niveles (README §26)

| Severidad | Definición | Plazo orientativo |
|---|---|---|
| **CRITICAL** | Compromiso o exposición con impacto potencial muy alto, explotable con poco esfuerzo. | Inmediato |
| **HIGH** | Riesgo importante que debe corregirse prioritariamente. | Días |
| **MEDIUM** | Debilidad relevante que requiere condiciones adicionales para explotarse. | Semanas |
| **LOW** | Mejora de hardening o higiene operativa. | Planificado |
| **INFORMATIONAL** | Observación sin riesgo directo significativo. | — |

## Cómo decidir

Severidad = **impacto** × **probabilidad**, ajustada por **exposición real**:

1. ¿Qué gana un atacante? (root en el host, datos, pivote a la red, disponibilidad).
2. ¿Quién puede alcanzarlo? Internet > LAN compartida/IoT > LAN de confianza > VPN de gestión > local.
3. ¿Qué condiciones previas necesita? (credenciales, cuenta local, interacción).
4. ¿Hay controles compensatorios verificados? (firewall perimetral, VPN, MFA, allowlist).

Sube un nivel si está expuesto a Internet; baja uno si solo es alcanzable por una red de gestión
aislada **y** lo has verificado. Si no puedes verificar la exposición, decláralo en el hallazgo
y usa el supuesto más conservador razonable.

## Ejemplos calibrados

| Observación | Contexto | Severidad |
|---|---|---|
| API Docker `tcp://0.0.0.0:2375` sin TLS | Cualquiera | CRITICAL |
| Cuenta con contraseña vacía y login posible | Cualquiera | CRITICAL |
| Credencial administrativa en archivo legible por todos | Host multiusuario / web root | CRITICAL/HIGH |
| Redis/Elasticsearch/DB sin autenticación escuchando en `0.0.0.0` | Alcanzable desde LAN/Internet | CRITICAL/HIGH |
| `PermitRootLogin yes` + `PasswordAuthentication yes` | SSH expuesto a Internet | HIGH |
| Mismo caso | Solo LAN de gestión/VPN | MEDIUM |
| Contenedor `privileged` o con `docker.sock` sin necesidad | Docker host | HIGH |
| Sin firewall local | Servidor expuesto sin firewall perimetral | HIGH |
| Sin firewall local | Detrás de firewall perimetral verificado | LOW/MEDIUM |
| Sistema operativo EOL | Expuesto | HIGH |
| Actualizaciones de seguridad pendientes | Según paquete y exposición | MEDIUM/HIGH |
| Script de cron ejecutado por root, escribible por otro usuario | Cualquiera | HIGH |
| SELinux/AppArmor deshabilitado | Servidor con servicios expuestos | MEDIUM |
| auditd ausente, logs solo locales | — | MEDIUM/LOW |
| Backups sin restore probado | Datos importantes | MEDIUM (HIGH si no hay backup) |
| Disco > 90 % | Servidor de producción del Homelab | MEDIUM |
| `/tmp` sin `noexec`, sysctl de hardening | — | LOW |
| `X11Forwarding yes` | — | LOW |
| Puerto escuchando por un servicio legítimo documentado | — | INFORMATIONAL |

## Prefijos de ID

`FINDING-NNN` es el ID del hallazgo (secuencial por auditoría). La categoría se indica aparte con
estos prefijos, que coinciden con los controles automáticos de `analyze.sh`:

| Prefijo | Categoría |
|---|---|
| `USR` | Usuarios y privilegios |
| `SSH` | SSH |
| `SYS` | Sistema / kernel |
| `NET` | Red |
| `FW` | Firewall |
| `SVC` | Servicios y procesos |
| `PKG` | Paquetes y actualizaciones |
| `FS` | Sistema de archivos |
| `LOG` / `AUD` | Logs / auditd |
| `MAC` | SELinux / AppArmor |
| `SCH` | Cron y timers |
| `CTR` / `K8S` | Contenedores / Kubernetes |
| `APP` / `TLS` | Aplicaciones / TLS |
| `BKP` | Backups |
| `SEC` | Secretos |
| `INT` | Integridad |
| `CAP` | Capacidad y disponibilidad |
| `ARC` | Arquitectura / segmentación |

## Estados de un hallazgo (README §34)

`OPEN` → `PARTIALLY_REMEDIATED` → `RESOLVED`, o `ACCEPTED_RISK` (con justificación y responsable).
`RESOLVED` exige evidencia posterior al cambio.

## Estados de la baseline (README §28)

`PASS` · `FAIL` · `PARTIAL` · `N/A` · `UNKNOWN`. Nunca `PASS` sin evidencia.
