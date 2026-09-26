# Plan de remediación

Fecha: · Auditoría de referencia: · Aprobado por:

## Resumen

| Grupo | Acciones | Hallazgos cubiertos |
|---|---|---|
| Quick Wins | | |
| Hardening | | |
| Architecture | | |
| Riesgo aceptado | | |

## Quick Wins

### RM-001 — <acción> (FINDING-NNN)

| Campo | Valor |
|---|---|
| Servidor | |
| Riesgo del cambio | Bajo \| Medio \| Alto (p. ej. posible pérdida de acceso SSH) |
| Ventana | |
| Autorizado | ☐ <!-- quién, cuándo --> |

**Precondiciones**

- <acceso alternativo disponible (consola/IPMI/segunda sesión)>

**Backup**

```bash
sudo cp -a /ruta/archivo /ruta/archivo.bak-lla-YYYYMMDD
```

**Cambio**

```bash
# comandos exactos
```

**Validación de sintaxis**

```bash
# p. ej. sudo sshd -t
```

**Aplicación**

```bash
# p. ej. sudo systemctl reload sshd
```

**Validación funcional y de seguridad**

```bash
# comando de la sección Validación del hallazgo
# Resultado esperado:
```

**Rollback**

```bash
sudo cp -a /ruta/archivo.bak-lla-YYYYMMDD /ruta/archivo && sudo systemctl reload <servicio>
```

## Hardening

<!-- Mismo formato -->

## Architecture

<!-- Cambios estructurales: describir objetivo, dependencias, fases y criterio de éxito. -->

## Riesgos aceptados

| Hallazgo | Justificación | Responsable | Revisión |
|---|---|---|---|
| | | | |

## Changelog

<!-- Ver remediation/changelog.md -->
