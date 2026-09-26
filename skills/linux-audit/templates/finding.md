## FINDING-NNN — <Título concreto y verificable>

| Campo | Valor |
|---|---|
| ID | FINDING-NNN |
| Severidad | CRITICAL \| HIGH \| MEDIUM \| LOW \| INFORMATIONAL |
| Activo | <hostname> |
| Categoría | <prefijo, p. ej. SSH> |
| Control automático | <p. ej. SSH-002, o "manual"> |
| Probabilidad | Alta \| Media \| Baja |
| Impacto | Alto \| Medio \| Bajo |
| Prioridad | P1 \| P2 \| P3 \| P4 |
| Estado | OPEN |
| Detectado | <fecha> — captura `evidence-<ts>` |

### Descripción

<Qué se observó, en términos objetivos. Sin juicios no respaldados por evidencia.>

### Evidencia

Archivo: `evidence/evidence-<ts>/<módulo>/<archivo>.txt`

Comando:

```bash
<comando exacto, tal como figura en la cabecera ##LLA command>
```

Resultado (extracto, secretos redactados):

```text
<líneas relevantes>
```

Validación cruzada:

- <segunda fuente: firewall, config de la aplicación, NAT, etc.>

### Interpretación

<Qué significa la evidencia. Qué NO se puede concluir con ella (limitaciones).>

### Impacto

<Qué podría lograr un atacante y bajo qué condiciones. Exposición real verificada o supuesta.>

### Recomendación

<Qué cambiar, en términos específicos y adaptados al modelo operativo del servidor. Los comandos
concretos se documentan en el plan de remediación.>

### Validación

<Cómo demostrar que quedó corregido: comando de verificación y resultado esperado.>

```bash
<comando de verificación>
# Resultado esperado: ...
```

### Estado

OPEN

<!-- Historial:
YYYY-MM-DD OPEN — detectado
YYYY-MM-DD RESOLVED — evidencia: evidence-<ts2>/...
-->
