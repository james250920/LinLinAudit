# Guía de revisión por fase

Para cada fase: archivos de evidencia (relativos al directorio de la captura), controles automáticos
relacionados, qué revisar y trampas de interpretación. Las secciones del README se indican entre
paréntesis.

---

## 02 · Inventario (§5)

**Evidencia:** `inventory/*` — `os-release`, `uname`, `hostnamectl`, `virt`, `dmi`, `cpu`, `memory`,
`storage`, `last`, `init`, `time`.

- Identifica distro, versión y kernel **antes** de emitir cualquier conclusión.
- ¿La versión está soportada? (EOL → hallazgo, típicamente HIGH si el host está expuesto).
- ¿Es VM, contenedor LXC o bare metal? Cambia la interpretación de SMART, firewall y kernel.
- `last`: accesos recientes, orígenes inesperados, reinicios.
- `time`: NTP sincronizado (logs sin hora fiable pierden valor forense).

## 03 · Sistema / kernel

**Evidencia:** `system/sysctl-security`, `cmdline`, `modules`, `secureboot`, `login-defs`,
`pam-password`, `limits-core`. **Auto:** `SYS-*`.

- `net.ipv4.ip_forward=1` es normal en routers, hosts Docker/Kubernetes e hypervisores; no es hallazgo
  por sí solo.
- Política de contraseñas (`PASS_MAX_DAYS`, pwquality, faillock) solo importa si hay autenticación por
  contraseña (SSH, consola, aplicaciones PAM).

## 04 · Usuarios y privilegios (§6)

**Evidencia:** `users/*`. **Auto:** `USR-001…004`.

- Contrasta `human-users` e `interactive-shells` con las personas que el administrador reconoce.
- Grupos equivalentes a root: `sudo`, `wheel`, `admin`, `docker`, `lxd`, `libvirt`, `disk`.
  Pertenecer a `docker` = root en el host.
- `sudoers-rules`: `NOPASSWD: ALL` para cuentas humanas es riesgo; para una cuenta de automatización
  con comandos acotados puede estar justificado.
- `shadow-status`: `EMPTY` es crítico si esa cuenta puede autenticarse (SSH `PermitEmptyPasswords`,
  consola). `LOCKED` en cuentas de servicio es lo esperado.
- `lastlog`: cuentas sin uso en meses → candidatas a desactivar (LOW).
- `home-perms`: homes legibles por otros exponen claves y `.env`.

## 05 · Red (§8)

**Evidencia:** `network/*`. **Auto:** `NET-001…003`.

Para cada socket no-loopback construye la tabla del README §8: puerto, protocolo, proceso, interfaz,
exposición LAN/WAN, necesidad, propietario.

- `0.0.0.0` / `::` / `*` = todas las interfaces, **no** necesariamente Internet. Exposición real =
  bind + firewall local + NAT/port-forward del router + security group del proveedor + VPN.
- Docker publica puertos saltándose UFW/firewalld (inserta reglas en `DOCKER`/`nat`). Un puerto de
  contenedor en `0.0.0.0` puede estar expuesto aunque UFW no lo permita.
- Bases de datos, Redis, Elasticsearch, APIs de Docker/Kubernetes, paneles (Proxmox 8006, Portainer
  9443/9000, Cockpit 9090) → especial atención.
- Sin privilegios, `ss` no muestra el proceso (`?`): mencionarlo como limitación.

## 06 · Servicios y procesos (§10)

**Evidencia:** `services/*`. **Auto:** `SVC-001`, `SVC-002`.

- Servicios desconocidos: identifica el paquete dueño del binario antes de calificarlo.
  "No lo reconozco" ≠ "innecesario".
- `systemd-security`: puntuación de exposición por unidad (≥ 9 = UNSAFE). Útil para priorizar
  hardening, no es un hallazgo por sí mismo.
- `suspicious-exe`: `(deleted)` suele significar binario actualizado sin reiniciar el servicio;
  ejecución desde `/tmp` o `/dev/shm` sí es un indicador fuerte.

## 07 · SSH (§7)

**Evidencia:** `ssh/sshd-effective` (config **efectiva**, prevalece sobre los archivos),
`sshd-config`, `authorized-keys`, `authorized-keys-fp`, `host-keys`. **Auto:** `SSH-001…006`.

- Evalúa junto con la exposición: `PasswordAuthentication yes` en SSH expuesto a Internet es HIGH;
  solo accesible por VPN/LAN de gestión, MEDIUM/LOW.
- Bloques `Match` pueden cambiar la configuración para usuarios/IPs concretos; `sshd -T` sin `-C`
  muestra la configuración por defecto.
- Claves autorizadas: tipo/tamaño (RSA < 2048, DSA → débil), comentarios que identifiquen al dueño,
  claves en `root`, archivos con permisos laxos.
- Intentos fallidos: ver `logs/auth-failed-by-ip`.

## 08 · Firewall (§9)

**Evidencia:** `firewall/*`. **Auto:** `FW-001`.

- Identifica el mecanismo real (UFW y firewalld son front-ends de nftables/iptables).
- Política por defecto de `INPUT`: `ACCEPT` sin reglas = sin filtrado.
- Compara **puertos escuchando vs permitidos vs necesarios**. Documenta la tabla.
- Revisa IPv6: con frecuencia se filtra IPv4 y se olvida IPv6.
- Un firewall perimetral (router, OPNsense, security group) puede compensar la ausencia de firewall
  local: pregunta antes de calificar severidad.

## 09 · Almacenamiento y filesystem (§12)

**Evidencia:** `filesystem/*`. **Auto:** `FS-001…006`.

- SUID no reconocidos: verifica el paquete propietario (`rpm -qf` / `dpkg -S`) antes de concluir.
  SUID fuera de rutas de paquetes (`/home`, `/opt`, `/tmp`) es grave.
- World-writable en `/etc`, `/usr`, `/opt`, directorios de aplicaciones o volúmenes → hallazgo.
- `/tmp` sin `noexec` es hardening (LOW), no vulnerabilidad.

## 10 · Logs (§13) · Auditd (§14)

**Evidencia:** `logs/*`, `auditd/*`. **Auto:** `LOG-001`, `LOG-002`, `AUD-001`, `AUD-002`.

- `auth-failed-by-ip` / `auth-invalid-users`: fuerza bruta es ruido habitual si SSH está en Internet;
  lo relevante es si hubo `Accepted` desde esos orígenes (`auth-accepted`).
- Accesos `Accepted password` para root o fuera de horario → investigar.
- Retención suficiente para investigar un incidente (journal con `SystemMaxUse`, logrotate).
- Logs solo locales: un atacante con root puede borrarlos (LOG-002).
- auditd activo sin reglas aporta poco (AUD-002).

## 11 · SELinux / AppArmor (§15)

**Evidencia:** `mac/*`. **Auto:** `MAC-001`.

- `Permissive` o perfiles en `complain` = sin protección efectiva.
- Denegaciones recientes: ¿servicio mal configurado o intento bloqueado?

## 12 · Cron y timers (§16)

**Evidencia:** `scheduled/*`. **Auto:** `SCH-001`.

- Por cada tarea: quién la ejecuta, qué script, de quién es el script y quién puede escribirlo.
  Script ejecutado por root pero escribible por otro usuario → escalada de privilegios (HIGH).
- Descargas remotas (`curl | sh`), binarios en `/tmp`, tareas que tocan firewall/usuarios/SSH.
- `SCH-001` da falsos positivos (p. ej. `mktemp /tmp/...` de paquetes oficiales): verifica el origen.

## 13 · Paquetes y actualizaciones (§11)

**Evidencia:** `packages/*`. **Auto:** `PKG-001…003`.

- El colector usa solo la caché local: consulta `apt-cache-age` / fecha de caché. Caché antigua →
  resultado `UNKNOWN` o limitación explícita.
- Repositorios de terceros y `gpgcheck=0` / `trusted=yes`.
- Actualizaciones automáticas (unattended-upgrades / dnf-automatic): ¿existen? ¿solo seguridad?
- Reinicio pendiente: parches de kernel/glibc no aplicados hasta reiniciar.

## 14 · Contenedores y orquestación (§17, §18)

**Evidencia:** `containers/*`, `kubernetes/*`. **Auto:** `CTR-001…006`.

- `docker-summary` es una línea por contenedor: `privileged`, `network=host`, `pid=host`, `capadd`,
  montajes (`docker.sock`, `/`, `/etc`, `/root`), `memory=0`, `user=` (vacío = usuario de la imagen,
  habitualmente root), `env_names` (nombres de variables que sugieren secretos, sin valores).
- Contenedores con `docker.sock` (Portainer, Traefik, Watchtower): documenta y evalúa si es necesario
  y si está en modo solo lectura/proxy de socket.
- Imágenes antiguas (`docker-images` → `CreatedSince`) y sin tag fijo (`latest`).
- Kubernetes: `pod-security` (hostNetwork/hostPID/privileged/hostPath), `clusterrolebindings` a
  `cluster-admin`, ausencia de `networkpolicies`, ingress expuestos.

## 15 · Aplicaciones y reverse proxy (§19)

**Evidencia:** `webapps/*`. **Auto:** `TLS-001`.

- `nginx -T` / `apache -S`: vhosts, `listen`, redirección HTTP→HTTPS, `ssl_protocols`
  (TLSv1/1.1 → débil), headers (HSTS, X-Frame-Options, CSP), `autoindex on`, `server_tokens`.
- Paneles de administración publicados sin autenticación adicional (VPN, SSO, IP allowlist).
- `database-binds`: `bind-address 0.0.0.0`, `protected-mode no`, Redis sin `requirepass`,
  `pg_hba.conf` con `trust` o `0.0.0.0/0`.

## 16 · Backups (§20)

**Evidencia:** `backups/*`. **Auto:** `BKP-001`, `BKP-002`.

Clasifica: configurado → ejecutado → verificado → restore probado → restore documentado. Pide al
administrador la evidencia de la última restauración; sin ella, `Restore probado = UNKNOWN/FAIL`.
Los backups pueden gestionarse fuera del host (Proxmox Backup Server, NAS, snapshots): pregunta.

## Secretos (§21)

**Evidencia:** `secrets/*` (solo rutas y permisos). **Auto:** `SEC-001…003`.

- `pattern-files` produce falsos positivos (plantillas, documentación, código). Si necesitas confirmar,
  usa `grep -c` o `grep -l` sobre el archivo; **nunca** imprimas la línea con el valor.
- Permisos: secretos legibles por `others` o por grupos amplios, `.env` en web roots, claves en
  repos, históricos de shell con contraseñas.

## Integridad (§22)

**Evidencia:** `integrity/*`.

- `rpm-verify` / `debsums`: binarios modificados (`5` en la columna de digest para archivos no-config)
  → investigar. Archivos de configuración modificados son normales.
- `recent-changes`: interpreta en contexto (actualizaciones recientes, despliegues).

## Capacidad y disponibilidad (§23)

**Evidencia:** `capacity/*`. **Auto:** `CAP-001…005`.

- Disco > 80 %, inodos, swap en uso intensivo, OOM kills, errores de kernel, SMART, RAID/ZFS degradado.

## Virtualización y Homelab (§24, §25)

**Evidencia:** `virtualization/*`, `network/addr`, `network/link`.

- Inventario de VMs/CTs, bridges y VLANs. Documenta la arquitectura observada con el diagrama
  del README §24 y señala qué segmentos comparten red de gestión con servicios expuestos.
- No recomiendes una arquitectura concreta sin conocer las necesidades del Homelab.
