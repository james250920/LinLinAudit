# Playbook de remediación

Procedimientos de referencia. **Adáptalos** a la distro, al mecanismo detectado y al modelo operativo
del servidor; no los apliques a ciegas. Cada uno sigue: backup → cambio → validar sintaxis →
aplicar → validar → rollback.

---

## SSH (SSH-001…006)

Preferir un drop-in en vez de editar `sshd_config` (si la versión soporta `Include sshd_config.d/*.conf`;
verifícalo en `ssh/sshd-config.txt`). En OpenSSH **gana el primer valor** leído, así que el drop-in
debe ordenarse antes que otros (`00-…`).

```bash
sudo tee /etc/ssh/sshd_config.d/00-linlinaudit-hardening.conf >/dev/null <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 4
EOF
sudo sshd -t                                  # validar sintaxis
sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|kbdinteractive|x11forwarding|maxauthtries'
```

Precondiciones críticas antes de deshabilitar contraseñas/root:

- Hay una cuenta nominativa con clave pública funcionando **y** sudo.
- Se prueba una **nueva** conexión SSH antes de cerrar la sesión actual.
- Rollback: `sudo rm /etc/ssh/sshd_config.d/00-linlinaudit-hardening.conf && sudo systemctl reload sshd`.

## Firewall (FW-001, NET-*)

Detectar el mecanismo en la evidencia; no instalar uno distinto sin decisión explícita.

**Rollback temporizado** para cambios remotos (si el acceso se pierde, se revierte solo):

```bash
# nftables
sudo nft list ruleset > /root/nft-backup-$(date +%F).nft
sudo systemd-run --on-active=5min --unit=lla-fw-rollback \
    sh -c 'nft flush ruleset && nft -f /root/nft-backup-YYYY-MM-DD.nft'
# ... aplicar cambios y probar nueva conexión ...
sudo systemctl stop lla-fw-rollback.timer     # confirmar si todo funciona
```

UFW (política por defecto + SSH antes de habilitar):

```bash
sudo ufw allow <puerto_ssh>/tcp comment 'SSH'
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
sudo ufw status verbose
```

firewalld:

```bash
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --zone=<zona> --remove-service=<servicio>          # runtime: se prueba primero
sudo firewall-cmd --runtime-to-permanent                              # solo tras validar
```

Docker ignora UFW para puertos publicados: la corrección es publicar en `127.0.0.1:PUERTO:PUERTO`
o en la IP interna adecuada, o filtrar en la cadena `DOCKER-USER`.

## Servicios innecesarios (NET-001, SVC-*)

```bash
systemctl status <servicio>                   # confirmar qué es y quién lo usa
sudo systemctl disable --now <servicio>       # desactivar, no desinstalar
# Rollback: sudo systemctl enable --now <servicio>
```

Para bases de datos, restringir el bind a `127.0.0.1` o a la interfaz interna en su configuración
y reiniciar el servicio en ventana acordada.

## Usuarios y sudo (USR-*)

```bash
sudo usermod -L <usuario>                     # bloquear contraseña
sudo usermod -s /usr/sbin/nologin <usuario>   # quitar shell
sudo chage -E 0 <usuario>                     # expirar cuenta
# Nunca userdel durante la remediación salvo petición explícita.
```

Sudoers: siempre con `visudo`, y validar:

```bash
sudo visudo -cf /etc/sudoers.d/<archivo>
sudo visudo -c
```

## Actualizaciones (PKG-*)

Ejecutar en ventana acordada y con backup/snapshot previo si es un hypervisor o servidor crítico.

```bash
# Debian/Ubuntu
sudo apt update && apt list --upgradable && sudo apt upgrade
# Fedora/RHEL
sudo dnf upgrade --refresh
# Reinicio si PKG-002 lo indica — solo con autorización explícita.
```

`gpgcheck=0` → `gpgcheck=1` en el `.repo` tras importar la clave del proveedor.

## Sistema de archivos (FS-*)

```bash
sudo chmod o-w <archivo>                      # world-writable
sudo chmod +t <directorio>                    # sticky bit
sudo chmod u-s <binario>                      # SUID no justificado (verificar paquete antes)
sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow   # Debian (en RHEL: 000 root:root)
```

`/tmp` con `nodev,nosuid,noexec`: cambio en `/etc/fstab` o `tmp.mount`; requiere remontar y puede
romper instaladores que ejecutan desde `/tmp`. Clasificar como Hardening, no Quick Win.

## sysctl (SYS-*)

```bash
sudo tee /etc/sysctl.d/90-linlinaudit.conf >/dev/null <<'EOF'
kernel.kptr_restrict = 1
fs.suid_dumpable = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF
sudo sysctl --system
# No desactivar ip_forward en hosts Docker/Kubernetes/routers/hypervisores.
# Rollback: sudo rm /etc/sysctl.d/90-linlinaudit.conf && reiniciar o restaurar valores con sysctl -w.
```

## Logging y auditd (LOG-*, AUD-*)

```bash
sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal
sudo systemctl restart systemd-journald
sudo systemctl enable --now auditd            # instalar paquete solo con autorización
```

## SELinux / AppArmor (MAC-*)

Pasar a enforcing sin preparar políticas rompe servicios. Procedimiento: revisar denegaciones en
modo permissive/complain, corregir, y solo entonces `setenforce 1` / `aa-enforce`, persistiendo
después en `/etc/selinux/config`.

## Contenedores (CTR-*)

Cambios en `docker-compose.yml` / definición del contenedor, luego `docker compose up -d <servicio>`:

- Quitar `privileged: true`; añadir solo las `cap_add` necesarias.
- Reemplazar montaje de `docker.sock` por un proxy de socket con permisos mínimos, o `:ro` si procede.
- Publicar puertos en `127.0.0.1` detrás del reverse proxy.
- `mem_limit` / `deploy.resources.limits`.
- `user: "UID:GID"` no-root cuando la imagen lo soporta.

## Secretos (SEC-*)

```bash
sudo chmod 600 <archivo>; sudo chown <servicio>:<servicio> <archivo>
```

Si un secreto estuvo legible por otros usuarios o expuesto, **rotarlo** es tarea del administrador
(no automatizar). Documentar como acción pendiente.

## TLS (TLS-001)

Renovar certificados (`certbot renew --dry-run` primero), revisar `ssl_protocols TLSv1.2 TLSv1.3`,
HSTS y redirección HTTP→HTTPS; `nginx -t` antes de `systemctl reload nginx`.

## Backups (BKP-*)

No es un cambio de configuración: planificar prueba de restauración a un destino aislado, documentar
tiempo y resultado, y guardar esa evidencia para el control "Restore probado".
