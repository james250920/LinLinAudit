# Linux & Homelab Security Audit Skill

## 1. Propósito

Este skill define un procedimiento profesional y repetible para auditar servidores Linux y entornos Homelab.

Objetivos:

- Obtener un inventario técnico completo.
- Evaluar configuración, exposición y postura de seguridad.
- Detectar configuraciones inseguras y software vulnerable.
- Revisar usuarios, privilegios, servicios, red, firewall, almacenamiento, logs, contenedores y tareas programadas.
- Identificar desviaciones de buenas prácticas.
- Recolectar evidencia reproducible.
- Clasificar hallazgos por severidad.
- Proponer remediaciones concretas.
- Generar un informe final auditable.
- Mantener separación entre observación, evidencia, riesgo y recomendación.

El skill está pensado para servidores propios o para sistemas donde exista autorización explícita para realizar la auditoría.

---

# 2. Principios de operación

## 2.1 Regla principal: observar antes de modificar

La auditoría debe ser inicialmente:

- Read-only.
- No destructiva.
- Reproducible.
- Trazable.
- Con evidencia.

No ejecutar cambios de configuración, reinicios, eliminación de archivos, instalación de paquetes ni modificaciones de firewall durante la fase de diagnóstico.

Si se requiere una remediación, crear una fase separada:

`AUDIT -> REVIEW -> REMEDIATION -> VALIDATION`

---

## 2.2 No asumir

Nunca asumir:

- Que SSH utiliza el puerto 22.
- Que el firewall es UFW.
- Que existe systemd.
- Que Docker está instalado.
- Que el servidor utiliza ext4.
- Que SELinux está activo.
- Que AppArmor está activo.
- Que root tiene SSH deshabilitado.
- Que los backups funcionan.
- Que un servicio es innecesario simplemente porque no se reconoce.

Primero identificar el entorno.

---

# 3. Flujo general de auditoría

Ejecutar las siguientes fases:

```text
01_SCOPE
   ↓
02_INVENTORY
   ↓
03_SYSTEM
   ↓
04_USERS_PRIVILEGES
   ↓
05_NETWORK
   ↓
06_SERVICES
   ↓
07_SSH
   ↓
08_FIREWALL
   ↓
09_STORAGE
   ↓
10_LOGS
   ↓
11_SCHEDULED_TASKS
   ↓
12_SOFTWARE_UPDATES
   ↓
13_CONTAINERS
   ↓
14_APPLICATIONS
   ↓
15_BACKUPS
   ↓
16_SECURITY_CONTROLS
   ↓
17_FINDINGS
   ↓
18_REMEDIATION_PLAN
   ↓
19_FINAL_REPORT
```

---

# 4. Preparación

## 4.1 Registrar contexto

Antes de comenzar documentar:

```text
Servidor:
Hostname:
IP:
Sistema operativo:
Versión:
Kernel:
Rol:
Entorno:
Fecha:
Auditor:
Autorización:
```

Ejemplos de roles:

- Hypervisor
- NAS
- Docker host
- Web server
- Database server
- Reverse proxy
- VPN
- Monitoring
- CI/CD
- Development
- General-purpose server

---

# 5. Inventario del sistema

## Objetivo

Determinar exactamente qué sistema estamos auditando.

## Comandos

```bash
hostnamectl
uname -a
cat /etc/os-release
uptime
who
w
last -n 20
```

CPU:

```bash
lscpu
nproc
```

Memoria:

```bash
free -h
cat /proc/meminfo
```

Almacenamiento:

```bash
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS,UUID
df -hT
findmnt
```

PCI:

```bash
lspci
```

USB:

```bash
lsusb
```

## Evidencia

Guardar:

```text
inventory/
├── os.txt
├── kernel.txt
├── cpu.txt
├── memory.txt
├── storage.txt
├── pci.txt
└── usb.txt
```

---

# 6. Usuarios y privilegios

## Objetivo

Identificar cuentas innecesarias, privilegios excesivos y configuraciones peligrosas.

## Usuarios

```bash
getent passwd
getent group
```

Usuarios humanos:

```bash
awk -F: '$3 >= 1000 && $1 != "nobody" {print}' /etc/passwd
```

UID 0:

```bash
awk -F: '$3 == 0 {print}' /etc/passwd
```

Shells válidos:

```bash
cat /etc/shells
```

Usuarios con shell:

```bash
awk -F: '$7 !~ /(nologin|false)$/ {print $1 ":" $7}' /etc/passwd
```

Grupos administrativos:

```bash
getent group sudo
getent group wheel
```

Sudo:

```bash
sudo -l
```

Configuración:

```bash
sudo grep -RInE '^[[:space:]]*[^#].*(ALL|NOPASSWD)' /etc/sudoers /etc/sudoers.d 2>/dev/null
```

## Revisar

- Usuarios desconocidos.
- Múltiples cuentas UID 0.
- Cuentas de servicio con login interactivo.
- Usuarios con sudo innecesario.
- `NOPASSWD` no justificado.
- Grupos privilegiados.
- Cuentas antiguas.
- Cuentas sin propietario claro.

---

# 7. SSH

## Objetivo

Auditar el principal vector de administración remota.

Detectar configuración efectiva:

```bash
sshd -T 2>/dev/null
```

Si está disponible:

```bash
sshd -T | grep -Ei 'port|permitrootlogin|passwordauthentication|pubkeyauthentication|permitempty|x11forwarding|allowusers|allowgroups|maxauthtries|logingracetime'
```

Archivo:

```bash
grep -RInE '^[[:space:]]*(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|PermitEmptyPasswords|X11Forwarding|AllowUsers|AllowGroups|MaxAuthTries|LoginGraceTime)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null
```

Claves:

```bash
find /home /root -maxdepth 3 -name authorized_keys -type f -ls 2>/dev/null
```

Revisar:

- Root login.
- Password authentication.
- Claves SSH.
- Usuarios permitidos.
- Grupos permitidos.
- Algoritmos obsoletos.
- Intentos fallidos.
- Puertos expuestos.
- Forwarding.
- MFA si existe.
- Gestión de claves.

No cambiar configuración durante la auditoría.

---

# 8. Red

## Interfaces

```bash
ip -br addr
ip route
ip -6 route
```

DNS:

```bash
resolvectl status 2>/dev/null || cat /etc/resolv.conf
```

Puertos escuchando:

```bash
ss -tulpn
```

Solo TCP:

```bash
ss -lntp
```

Solo UDP:

```bash
ss -lnup
```

Conexiones:

```bash
ss -tunap
```

## Auditar

Para cada puerto:

```text
Puerto
Protocolo
Proceso
PID
Servicio
Interfaz
Exposición LAN
Exposición WAN
Necesidad
Propietario
```

Especial atención:

- `0.0.0.0`
- `::`
- Puertos administrativos expuestos.
- Bases de datos expuestas.
- Docker APIs.
- Interfaces de administración.
- Servicios sin autenticación.

---

# 9. Firewall

Detectar qué mecanismo existe.

```bash
systemctl is-active ufw 2>/dev/null
systemctl is-active firewalld 2>/dev/null
systemctl is-active nftables 2>/dev/null
```

UFW:

```bash
sudo ufw status verbose
```

nftables:

```bash
sudo nft list ruleset
```

iptables:

```bash
sudo iptables -L -n -v
sudo ip6tables -L -n -v
```

firewalld:

```bash
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null
```

Comparar:

```text
Puertos escuchando
vs.
Puertos permitidos
vs.
Puertos realmente necesarios
```

---

# 10. Servicios y procesos

Servicios:

```bash
systemctl list-units --type=service --state=running
systemctl list-unit-files --type=service
```

Fallos:

```bash
systemctl --failed
```

Procesos:

```bash
ps aux --sort=-%cpu | head -30
ps aux --sort=-%mem | head -30
```

Revisar:

- Servicios desconocidos.
- Servicios innecesarios.
- Servicios ejecutándose como root.
- Servicios sin mantenimiento.
- Procesos anómalos.
- Binarios ejecutados desde rutas sospechosas.

---

# 11. Paquetes y actualizaciones

Debian/Ubuntu:

```bash
apt list --upgradable 2>/dev/null
dpkg -l
```

RHEL/Fedora:

```bash
dnf check-update
rpm -qa
```

Arch:

```bash
pacman -Qu
pacman -Q
```

Revisar:

- Sistema sin actualizar.
- Paquetes EOL.
- Repositorios externos.
- Paquetes instalados manualmente.
- Software que ya no necesita mantenimiento.

No instalar actualizaciones automáticamente durante la auditoría.

---

# 12. Sistema de archivos

## Montajes

```bash
findmnt
cat /etc/fstab
```

Permisos críticos:

```bash
stat /etc/passwd
stat /etc/shadow
stat /etc/sudoers
stat /etc/ssh/sshd_config
```

SUID:

```bash
find / -xdev -type f -perm -4000 -ls 2>/dev/null
```

SGID:

```bash
find / -xdev -type f -perm -2000 -ls 2>/dev/null
```

World-writable:

```bash
find / -xdev -type f -perm -0002 -ls 2>/dev/null
```

Directorios world-writable:

```bash
find / -xdev -type d -perm -0002 -ls 2>/dev/null
```

Revisar:

- `/tmp`
- `/var/tmp`
- `/home`
- `/srv`
- `/opt`
- `/var/www`
- directorios de aplicaciones
- volúmenes de contenedores

---

# 13. Logs

Systemd:

```bash
journalctl --disk-usage
journalctl -p warning..alert --since "7 days ago"
journalctl --since "7 days ago"
```

Autenticación:

Debian/Ubuntu:

```bash
grep -Ei 'failed|invalid|accepted|sudo' /var/log/auth.log 2>/dev/null
```

RHEL/Fedora:

```bash
grep -Ei 'failed|invalid|accepted|sudo' /var/log/secure 2>/dev/null
```

Buscar patrones:

```text
Failed password
Invalid user
Accepted password
Accepted publickey
sudo
su:
authentication failure
```

Revisar:

- Intentos de login.
- IPs repetitivas.
- Usuarios inexistentes.
- Accesos fuera de horario esperado.
- Elevación de privilegios.
- Errores repetitivos.
- Logs inexistentes o deshabilitados.

---

# 14. Auditd

Comprobar:

```bash
systemctl status auditd 2>/dev/null
auditctl -s 2>/dev/null
```

Si existe:

```bash
sudo ausearch -m USER_LOGIN --start recent 2>/dev/null
sudo ausearch -m USER_CMD --start recent 2>/dev/null
```

Evaluar:

- ¿Existe auditoría?
- ¿Los logs tienen retención?
- ¿Existe suficiente información para investigar cambios?
- ¿El almacenamiento de logs está protegido?

---

# 15. SELinux / AppArmor

SELinux:

```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```

AppArmor:

```bash
aa-status 2>/dev/null
```

Revisar:

- Estado.
- Políticas cargadas.
- Denegaciones recientes.
- Servicios críticos protegidos.

---

# 16. Cron y systemd timers

Cron:

```bash
crontab -l 2>/dev/null
sudo crontab -l 2>/dev/null
ls -la /etc/cron.d
ls -la /etc/cron.daily
ls -la /etc/cron.hourly
ls -la /etc/cron.weekly
ls -la /etc/cron.monthly
```

Buscar crons de todos los usuarios:

```bash
for u in $(cut -d: -f1 /etc/passwd); do
    crontab -u "$u" -l 2>/dev/null
done
```

Timers:

```bash
systemctl list-timers --all
```

Revisar:

- Scripts desconocidos.
- Descargas remotas.
- Ejecución como root.
- Binarios desde `/tmp`.
- Curl/wget hacia dominios desconocidos.
- Tareas que modifican firewall, usuarios o SSH.

---

# 17. Docker / Podman

Docker:

```bash
docker version
docker info
docker ps -a
docker images
docker network ls
docker volume ls
```

Inspeccionar contenedores:

```bash
docker inspect <container>
```

Revisar especialmente:

- `privileged: true`
- Host networking.
- Host PID.
- Host filesystem mounts.
- `/var/run/docker.sock`
- Containers running as root.
- Secrets en environment variables.
- Puertos publicados.
- Imágenes antiguas.
- Imágenes no verificadas.
- Contenedores sin límites de recursos.
- Volúmenes sensibles.

Podman:

```bash
podman ps -a
podman images
podman network ls
podman volume ls
```

---

# 18. Kubernetes / Homelab Orchestration

Si existe Kubernetes:

```bash
kubectl get nodes
kubectl get pods -A
kubectl get svc -A
kubectl get ingress -A
kubectl get secrets -A
```

Revisar:

- RBAC.
- ServiceAccounts.
- Privileged pods.
- HostPath.
- HostNetwork.
- Secrets.
- Ingress.
- Exposición externa.
- NetworkPolicies.
- Namespace isolation.

---

# 19. Reverse proxy y aplicaciones

Detectar:

```bash
systemctl list-units --type=service | grep -Ei 'nginx|apache|caddy|traefik'
```

Revisar:

- TLS.
- Certificados.
- HTTP -> HTTPS.
- Headers.
- Exposición administrativa.
- Paneles de administración.
- Aplicaciones sin autenticación.
- Versiones.
- Logs.
- Secretos.

Nunca almacenar credenciales reales en el informe.

Redactar:

```text
PASSWORD=<REDACTED>
TOKEN=<REDACTED>
API_KEY=<REDACTED>
```

---

# 20. Backups

Determinar:

```text
Qué se respalda
Dónde
Con qué frecuencia
Retención
Cifrado
Quién puede acceder
Última ejecución
Última restauración probada
```

Buscar herramientas:

```bash
systemctl list-timers --all
grep -RInE 'backup|restic|borg|rsync|rclone|duplicity' /etc/systemd /etc/cron* 2>/dev/null
```

Una existencia de backup no implica que exista recuperación.

Clasificar:

```text
Backup configurado
Backup ejecutado
Backup verificado
Restore probado
Restore documentado
```

---

# 21. Secrets

Buscar patrones sin imprimir secretos completos:

```bash
grep -RIlE 'password=|passwd=|api[_-]?key|secret=|token=' \
    /etc /opt /srv /var/www 2>/dev/null | head -100
```

No ejecutar comandos que revelen secretos innecesariamente.

Revisar:

- `.env`
- Configuraciones.
- Docker Compose.
- CI/CD.
- Scripts.
- SSH keys.
- Tokens.
- Certificados privados.

Si se encuentra un secreto:

```text
Hallazgo: secreto almacenado en texto plano
Evidencia: ruta y permisos
Valor: REDACTED
```

---

# 22. Integridad

Comprobar herramientas disponibles:

```bash
command -v aide
command -v debsums
command -v rpm
```

Debian:

```bash
debsums -s 2>/dev/null
```

RPM:

```bash
rpm -Va 2>/dev/null
```

Buscar modificaciones recientes:

```bash
find /etc /usr/local /opt /srv -xdev -type f -mtime -7 -ls 2>/dev/null
```

La fecha debe interpretarse en contexto: una modificación reciente no implica automáticamente compromiso.

---

# 23. Capacidad y disponibilidad

CPU:

```bash
uptime
top -b -n1 | head -30
```

Memoria:

```bash
free -h
```

Disco:

```bash
df -hT
df -ih
```

I/O:

```bash
iostat 2>/dev/null
```

SMART:

```bash
smartctl --scan 2>/dev/null
```

Si está autorizado:

```bash
sudo smartctl -a /dev/sdX
```

Revisar:

- Disco > 80%.
- Inodos agotados.
- RAM insuficiente.
- Swap.
- I/O elevado.
- SMART warnings.
- Filesystems read-only.
- Hardware degradado.

---

# 24. Virtualización y Homelab

Si el servidor es hypervisor:

Identificar:

```bash
systemctl list-units --type=service | grep -Ei 'libvirt|proxmox|pve|docker|podman|lxc'
```

Revisar arquitectura:

```text
Internet
   |
Router/Firewall
   |
Reverse Proxy / VPN
   |
Servers
   |
Containers / VMs
   |
Applications
   |
Databases / Storage
```

Evaluar segmentación:

- Management VLAN.
- Server VLAN.
- IoT VLAN.
- Guest VLAN.
- Trusted LAN.
- DMZ.
- Backup network.

No recomendar una arquitectura concreta sin conocer las necesidades del Homelab.

---

# 25. Seguridad de red externa

Si la auditoría incluye infraestructura propia expuesta a Internet, registrar únicamente activos autorizados.

Inventario:

```text
Dominio
IP pública
Servicio
Puerto
Propietario
Justificación
```

No realizar escaneo agresivo o de terceros.

Para activos propios, cualquier prueba activa debe estar dentro del alcance autorizado y de una ventana controlada.

---

# 26. Matriz de riesgo

Cada hallazgo debe incluir:

```text
ID:
Título:
Severidad:
Activo:
Categoría:
Descripción:
Evidencia:
Impacto:
Probabilidad:
Riesgo:
Recomendación:
Prioridad:
Estado:
```

Severidades:

### CRITICAL

Compromiso o exposición con impacto potencial muy alto.

Ejemplos:

- Credencial administrativa expuesta públicamente.
- Servicio crítico sin autenticación expuesto a Internet.
- Control total del servidor accesible sin protección adecuada.

### HIGH

Riesgo importante que debe corregirse prioritariamente.

Ejemplos:

- SSH administrativo expuesto con autenticación débil.
- Firewall inexistente en un servidor expuesto.
- Contenedor privilegiado innecesario.

### MEDIUM

Debilidad relevante pero con condiciones adicionales necesarias para explotarla.

### LOW

Mejora de hardening o higiene operativa.

### INFORMATIONAL

Observación sin riesgo directo significativo.

---

# 27. Evidencia

Cada hallazgo debe tener evidencia reproducible.

Ejemplo:

```text
FINDING: SSH-001

Comando:
sshd -T | grep permitrootlogin

Resultado:
permitrootlogin yes

Interpretación:
El daemon SSH permite autenticación directa de root.

Riesgo:
Aumenta la superficie de autenticación administrativa.

Recomendación:
Evaluar deshabilitar login directo de root y utilizar cuentas nominativas
con sudo, de acuerdo con el modelo operativo del servidor.
```

No utilizar solamente:

```text
"SSH está mal configurado"
```

La conclusión debe estar respaldada por evidencia.

---

# 28. Baseline esperado

Crear una matriz:

| Control | Estado | Evidencia | Observación |
|---|---|---|---|
| Sistema actualizado | | | |
| Firewall activo | | | |
| SSH endurecido | | | |
| Root SSH restringido | | | |
| Usuarios revisados | | | |
| Sudo revisado | | | |
| Logs activos | | | |
| Auditd | | | |
| SELinux/AppArmor | | | |
| Backups | | | |
| Restore probado | | | |
| Docker seguro | | | |
| TLS | | | |
| Secretos protegidos | | | |
| Disco saludable | | | |
| Monitorización | | | |

Estados permitidos:

```text
PASS
FAIL
PARTIAL
N/A
UNKNOWN
```

Nunca utilizar `PASS` si no existe evidencia suficiente.

---

# 29. Automatización

Crear un directorio de auditoría:

```text
linux-audit/
├── README.md
├── scope/
├── inventory/
├── evidence/
├── findings/
├── remediation/
└── report/
```

Cada servidor:

```text
servers/
└── server-01/
    ├── inventory/
    ├── evidence/
    ├── findings/
    └── report.md
```

Los comandos pueden ejecutarse mediante un script read-only.

Ejemplo conceptual:

```bash
#!/usr/bin/env bash

set -u

OUT="./audit-$(hostname)-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

hostnamectl > "$OUT/hostnamectl.txt" 2>&1
uname -a > "$OUT/uname.txt" 2>&1
cat /etc/os-release > "$OUT/os-release.txt" 2>&1
uptime > "$OUT/uptime.txt" 2>&1
free -h > "$OUT/memory.txt" 2>&1
lsblk > "$OUT/storage.txt" 2>&1
df -hT > "$OUT/disk.txt" 2>&1
ip -br addr > "$OUT/network.txt" 2>&1
ss -tulpn > "$OUT/listening.txt" 2>&1
systemctl --failed > "$OUT/systemd-failed.txt" 2>&1
systemctl list-units --type=service --state=running > "$OUT/services.txt" 2>&1

echo "Evidence saved to $OUT"
```

Reglas:

- No almacenar passwords.
- No almacenar private keys.
- Redactar tokens.
- No modificar configuración.
- Registrar fecha/hora.
- Registrar hostname.
- Registrar versión del script.

---

# 30. Validación cruzada

Nunca depender de una sola fuente.

Ejemplo:

```text
ss -tulpn
        +
systemctl
        +
firewall
        +
configuración de aplicación
```

Si `ss` muestra:

```text
0.0.0.0:5432
```

no concluir inmediatamente que PostgreSQL está expuesto a Internet.

También verificar:

```text
Firewall
NAT
Router
Cloud Security Group
VPN
VLAN
```

La exposición real depende de la arquitectura completa.

---

# 31. Hallazgos que requieren especial atención

Buscar explícitamente:

```text
[ ] SSH root login
[ ] Password authentication
[ ] Usuarios desconocidos
[ ] UID 0 adicional
[ ] Sudo excesivo
[ ] Puertos inesperados
[ ] Servicios públicos innecesarios
[ ] Firewall ausente
[ ] Docker socket expuesto
[ ] Containers privileged
[ ] Secrets en texto plano
[ ] Backups inexistentes
[ ] Restore nunca probado
[ ] Discos llenos
[ ] Sistema EOL
[ ] Paquetes vulnerables
[ ] Logs deshabilitados
[ ] Auditd inexistente
[ ] SELinux/AppArmor deshabilitado
[ ] Cron desconocido
[ ] systemd timer desconocido
[ ] Binarios SUID inesperados
[ ] Archivos world-writable
[ ] Certificados vencidos
[ ] TLS débil
[ ] Paneles administrativos expuestos
```

---

# 32. Informe final

El informe debe comenzar con:

## Executive Summary

```text
Servidores auditados:
Fecha:
Alcance:
Limitaciones:

Critical:
High:
Medium:
Low:
Informational:
```

Después:

## Arquitectura observada

Documentar:

```text
Internet
   |
Firewall
   |
Router
   |
VPN / Reverse Proxy
   |
Homelab
   |
Servers
   |
Containers / VMs
```

## Hallazgos

Ordenar por severidad para facilitar la remediación, pero no utilizar rankings subjetivos entre hallazgos del mismo nivel.

Formato:

```markdown
## FINDING-001 — [Título]

Severity: HIGH
Asset: server-01
Category: SSH

### Description

...

### Evidence

```text
...
```

### Impact

...

### Recommendation

...

### Validation

...

### Status

OPEN
```

---

# 33. Plan de remediación

Separar:

## Quick Wins

Cambios de bajo riesgo y alta claridad.

Ejemplos:

- Eliminar cuentas obsoletas.
- Corregir permisos claramente incorrectos.
- Cerrar servicios no utilizados.
- Activar controles de logging.

## Hardening

Cambios que requieren planificación:

- SSH.
- Firewall.
- AppArmor/SELinux.
- Container security.
- Segmentación de red.

## Architecture

Cambios estructurales:

- VLANs.
- VPN.
- Reverse proxy.
- Centralización de logs.
- Backup architecture.
- Monitoring.
- Disaster recovery.

---

# 34. Re-auditoría

Después de una remediación:

```text
1. Ejecutar nuevamente el control.
2. Guardar nueva evidencia.
3. Comparar antes/después.
4. Confirmar que el cambio no rompió el servicio.
5. Marcar el hallazgo como:
   OPEN
   PARTIALLY_REMEDIATED
   RESOLVED
   ACCEPTED_RISK
```

Nunca marcar `RESOLVED` solamente porque se ejecutó un comando de configuración.

Debe existir evidencia posterior.

---

# 35. Reglas para un agente de IA que utilice este skill

El agente debe:

1. Preguntar o determinar el alcance.
2. Identificar el servidor antes de emitir conclusiones.
3. Preferir comandos de lectura.
4. Ejecutar primero inventario.
5. No cambiar configuraciones automáticamente.
6. No borrar usuarios, archivos o servicios.
7. No reiniciar servicios.
8. No modificar firewall.
9. No rotar credenciales.
10. No exponer secretos en la conversación.
11. Redactar secretos encontrados.
12. Mantener evidencia de cada conclusión.
13. Diferenciar `UNKNOWN` de `PASS`.
14. No confundir un warning con una vulnerabilidad.
15. Explicar las limitaciones de cada prueba.
16. Validar hallazgos importantes mediante más de una fuente.
17. Generar recomendaciones específicas.
18. Proponer comandos de remediación por separado.
19. Pedir autorización antes de aplicar cambios.
20. Repetir la auditoría después de cambios.

---

# 36. Modo operativo recomendado

## Modo 1 — DISCOVERY

Solo inventario.

## Modo 2 — AUDIT

Recopilar evidencia y generar hallazgos.

## Modo 3 — REVIEW

Revisar los hallazgos con el administrador.

## Modo 4 — REMEDIATION

Aplicar únicamente cambios autorizados.

## Modo 5 — VALIDATION

Comprobar que los cambios funcionaron.

## Modo 6 — REPORT

Generar informe final.

Flujo:

```text
DISCOVERY
   ↓
AUDIT
   ↓
REVIEW
   ↓
REMEDIATION
   ↓
VALIDATION
   ↓
REPORT
```

---

# 37. Definition of Done

Una auditoría se considera completa cuando:

- [ ] El alcance está documentado.
- [ ] Todos los servidores autorizados fueron inventariados.
- [ ] SO y kernel registrados.
- [ ] Usuarios revisados.
- [ ] Privilegios revisados.
- [ ] SSH revisado.
- [ ] Puertos revisados.
- [ ] Firewall revisado.
- [ ] Servicios revisados.
- [ ] Paquetes y actualizaciones revisados.
- [ ] Filesystem revisado.
- [ ] SUID/SGID revisado.
- [ ] Logs revisados.
- [ ] Auditd revisado.
- [ ] SELinux/AppArmor revisado.
- [ ] Cron revisado.
- [ ] Containers revisados.
- [ ] Aplicaciones revisadas.
- [ ] Secrets revisados.
- [ ] Backups revisados.
- [ ] Restauración evaluada.
- [ ] Capacidad revisada.
- [ ] Hallazgos documentados con evidencia.
- [ ] Riesgos explicados.
- [ ] Remediaciones propuestas.
- [ ] Cambios validados.
- [ ] Informe final generado.

---

# 38. Resultado esperado

El resultado final debe permitir responder:

```text
¿Qué servidores tengo?
¿Qué servicios ejecutan?
¿Qué está expuesto?
¿Quién puede acceder?
¿Qué privilegios existen?
¿Qué configuraciones son riesgosas?
¿Qué software necesita actualización?
¿Tengo firewall?
¿Tengo logging?
¿Puedo detectar incidentes?
¿Tengo backups?
¿Puedo restaurarlos?
¿Mis containers están correctamente aislados?
¿Tengo secretos expuestos?
¿Qué debo corregir primero?
¿Cómo demuestro que fue corregido?
```

El objetivo no es únicamente encontrar problemas.

El objetivo es construir una fotografía reproducible de la seguridad, disponibilidad y configuración del Homelab y poder comparar esa fotografía después de cada ciclo de hardening.
