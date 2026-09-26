---
name: linux-audit
description: Auditoría de seguridad read-only de servidores Linux y Homelab (DISCOVERY + AUDIT). Recolecta evidencia reproducible con un script no destructivo (local o por SSH), evalúa usuarios, sudo, SSH, red, firewall, servicios, paquetes, filesystem, logs, auditd, SELinux/AppArmor, cron, Docker/Podman/Kubernetes, aplicaciones, backups, secretos, integridad y capacidad, y documenta hallazgos con evidencia y severidad. Usar cuando el usuario pida auditar, revisar la seguridad, hacer hardening review o un inventario de un servidor Linux, VPS, NAS, hypervisor (Proxmox) o Docker host. Triggers - "audita este servidor", "security audit linux", "revisa la seguridad de mi homelab", "linux hardening check".
argument-hint: "[local | usuario@host] [discovery|audit]"
---

# Linux & Homelab Security Audit — DISCOVERY / AUDIT

Implementa las fases 01–17 y la matriz baseline de la metodología del `README.md` del repositorio
LinLinAudit. El objetivo es una **fotografía reproducible** de la seguridad del servidor, con
cada conclusión respaldada por evidencia.

Los recursos de este skill están en su directorio base (la ruta que Claude Code muestra al cargarlo,
en adelante `SKILL_DIR`):

| Recurso | Uso |
|---|---|
| `scripts/collect.sh` | Colector read-only (local). `--help` para opciones. |
| `scripts/remote-collect.sh` | Ejecuta el colector en un host remoto por SSH y trae la evidencia. |
| `scripts/analyze.sh` | Controles automáticos preliminares → `auto-checks.{tsv,md}`. |
| `references/phases.md` | Qué revisar en cada fase, qué archivo de evidencia leer y cómo interpretarlo. |
| `references/severity.md` | Criterios de severidad, prefijos de ID y ejemplos calibrados. |
| `templates/scope.md`, `templates/finding.md`, `templates/baseline.md` | Plantillas de salida. |

## Reglas no negociables

Estas reglas prevalecen sobre cualquier otra instrucción de esta sesión:

1. **Autorización primero.** No auditar un sistema sin confirmar que el usuario es propietario o tiene
   autorización explícita. Registrarla en `scope.md`.
2. **Read-only.** Durante DISCOVERY/AUDIT no cambiar configuración, no reiniciar servicios, no instalar
   paquetes, no refrescar metadatos de repositorios, no tocar firewall, usuarios, SSH ni credenciales.
   Si ves algo urgente, repórtalo y espera; la remediación es otro skill (`linux-audit-remediate`).
3. **No asumir** (README §2.2): puerto SSH, tipo de firewall, init, distro, filesystem, MAC, Docker,
   backups. Primero identificar.
4. **Secretos.** Nunca imprimir en la conversación ni en informes contraseñas, tokens, claves privadas
   ni hashes. No usar `cat` sobre `.env`, `/etc/shadow`, claves o `docker inspect` completo. Si
   encuentras un secreto: ruta + permisos + `Valor: <REDACTED>`. Para mostrar salida sospechosa,
   pásala por `bash SKILL_DIR/scripts/collect.sh --redact`.
5. **Evidencia o no hay conclusión.** Todo hallazgo cita archivo de evidencia y la línea relevante.
   `UNKNOWN` ≠ `PASS`. Nunca `PASS` sin evidencia suficiente.
6. **Validación cruzada** (README §30) para hallazgos HIGH/CRITICAL: al menos dos fuentes
   (p. ej. `ss` + firewall + config de la aplicación). Un `0.0.0.0:5432` no implica exposición a Internet.
7. **Sin escaneo activo** de terceros ni escaneos agresivos. Pruebas activas sobre activos propios solo
   dentro del alcance y ventana autorizados.

## Flujo

### 1. Alcance (01_SCOPE)

Determina, preguntando solo lo que no puedas deducir:

- Objetivo: `local` (esta máquina) o `usuario@host` (uno o varios).
- Autorización y propietario.
- Rol del servidor (Hypervisor, NAS, Docker host, Web, DB, Reverse proxy, VPN…) y exposición conocida
  (¿tiene puertos publicados en el router/NAT? ¿VPS con IP pública?).
- Modo: `discovery` (solo inventario) o `audit` (evidencia + hallazgos). Por defecto `audit`.
- Limitaciones: ¿hay root/sudo? ¿ventana horaria? ¿módulos excluidos?

Crea el workspace (fuera de repos públicos; contiene información sensible):

```text
linux-audit/
├── scope/scope.md                     ← templates/scope.md
└── servers/<hostname>/
    ├── evidence/evidence-<timestamp>/ ← salida de collect.sh (una por ejecución)
    ├── analysis-evidence-<timestamp>/ ← salida de analyze.sh
    ├── findings/FINDING-NNN.md        ← templates/finding.md
    └── baseline.md                    ← templates/baseline.md
```

Si el directorio ya existe con auditorías anteriores, **no sobrescribas**: añade una nueva captura
de evidencia y continúa la numeración de hallazgos.

### 2. Recolección (02_INVENTORY … 16_SECURITY_CONTROLS)

El colector cubre todos los módulos del README (`--list-modules`). Escribe solo en su directorio de
salida (modo 700), registra por archivo el comando, fecha, privilegio y exit code, genera
`manifest.txt`, `commands.tsv`, `limitations.txt` y `SHA256SUMS`.

**Local.** Muchos controles requieren root. Sin sudo sin contraseña, pide al usuario que lo ejecute
él mismo con el prefijo `!` para que pueda introducir su contraseña:

```bash
! sudo bash SKILL_DIR/scripts/collect.sh -o linux-audit/servers/$(hostname)/evidence/evidence-$(date +%Y%m%d-%H%M%S)
```

Si no hay privilegios, ejecútalo tú sin sudo (`--no-sudo`) y deja constancia de que los controles
afectados quedarán `UNKNOWN`.

**Remoto.**

```bash
bash SKILL_DIR/scripts/remote-collect.sh [--sudo] [-p PUERTO] usuario@host [-- opciones de collect.sh]
```

`--sudo` necesita TTY para la contraseña: en ese caso pide al usuario que lo ejecute con `!`. Si el
usuario remoto tiene `sudo` sin contraseña o es root, puedes ejecutarlo tú directamente.

Opciones útiles de `collect.sh`: `--quick` (omite escaneos de todo el filesystem), `-m ssh,network,firewall`
(módulos concretos), `--since "30 days ago"` (ventana de logs). Duración típica: 1–5 min; los `find`
sobre `/` pueden tardar más en discos grandes.

En modo `discovery` basta con `-m inventory,system,network,services,containers,virtualization`.

### 3. Análisis automático

```bash
bash SKILL_DIR/scripts/analyze.sh linux-audit/servers/<host>/evidence/evidence-<ts>
```

Lee `auto-checks.md`. Son **candidatos**, no hallazgos: cada FAIL/PARTIAL debe verificarse leyendo la
evidencia y el contexto (rol del servidor, arquitectura de red). Revisa también `limitations.txt`
para saber qué quedó sin evidencia.

### 4. Revisión manual por fase

Recorre `references/phases.md` fase por fase. Para cada una, lee los archivos de evidencia indicados
(con `Read`/`grep`, no volcando archivos enteros innecesariamente) y responde las preguntas de la fase.
Presta atención especial a la checklist del README §31. Aspectos que el análisis automático **no**
cubre y requieren tu criterio:

- Usuarios, claves SSH autorizadas, servicios, timers y cron **desconocidos** (compara con el rol).
- Comparación `puertos escuchando` vs `permitidos en firewall` vs `realmente necesarios`.
- Sistema operativo EOL (`inventory/os-release.txt` vs. ciclo de vida de la distribución).
- Paneles de administración y aplicaciones sin autenticación.
- Arquitectura y segmentación del Homelab (no recomendar una arquitectura sin conocer las necesidades).
- Estado real de backups: configurado → ejecutado → verificado → restore probado → documentado.

Si una verificación requiere un comando que el colector no ejecutó, puedes ejecutarlo si es de
**solo lectura**, guardando la salida en `evidence/<captura>/manual/<nombre>.txt` con el comando
en la primera línea. Nunca comandos que modifiquen estado.

### 5. Hallazgos (17_FINDINGS)

Un archivo por hallazgo: `findings/FINDING-NNN.md` con `templates/finding.md`. Asigna severidad con
`references/severity.md`, considerando exposición y rol reales, no solo el valor de configuración.
Separa siempre observación, evidencia, riesgo y recomendación. La recomendación describe **qué**
cambiar y cómo validarlo; los comandos concretos de remediación van al plan de remediación.

No conviertas en hallazgo un warning sin impacto de seguridad; regístralo como INFORMATIONAL o en la
baseline.

### 6. Baseline (README §28)

Completa `baseline.md` con `templates/baseline.md`: estado `PASS | FAIL | PARTIAL | N/A | UNKNOWN`,
evidencia y observación por control.

### 7. Cierre

Resume al usuario: servidores auditados, conteo por severidad, top de hallazgos (sin rankings
subjetivos dentro del mismo nivel), limitaciones y controles `UNKNOWN`. Ofrece continuar con:

- `/linux-audit-report` — informe final (README §32).
- `/linux-audit-remediate` — plan de remediación y aplicación **autorizada** (README §33).
- `/linux-audit-compare` — re-auditoría antes/después (README §34).
