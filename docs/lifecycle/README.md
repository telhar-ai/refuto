# Ciclo de vida

Trece fases. Cada una declara **cuándo puede empezar** y **cuándo ha terminado**, y las dos
cosas son artefactos, no opiniones.

```
DISCOVER → SPECIFY → PLAN → ARCHITECT → DESIGN → IMPLEMENT → TEST
        → SECURE → VALIDATE → INTEGRATE → RELEASE → OBSERVE → DOCUMENT
```

## Por qué criterios explícitos

Sin criterio de entrada, una fase arranca con lo que haya y produce basura plausible.
Sin criterio de salida, «terminada» significa «el agente dejó de escribir» — que es exactamente
la afirmación que refuto existe para no aceptar.

**Una fase termina cuando sus artefactos existen y sus puertas pasan.** No cuando el modelo dice
que terminó.

| Fase | Entra con | Sale con | Puertas | Opcional |
|---|---|---|---|---|
| `DISCOVER` | intent | problem-statement | — | no |
| `SPECIFY` | problem-statement | requirements, acceptance-criteria | `G-TRACE` | no |
| `PLAN` | requirements | plan, test-strategy | — | no |
| `ARCHITECT` | requirements | architecture, threat-model | `G-SDD` | no |
| `DESIGN` | requirements | ux-spec, a11y-spec | — | **sí** |
| `IMPLEMENT` | plan, architecture | code | `G-POLICY`, `G-SDD` | no |
| `TEST` | code | tests, test-report | `G-TRACE`, `G-SDD` | no |
| `SECURE` | code | sbom, security-report | `G-SECURITY` | no |
| `VALIDATE` | code | review-report | `G-PR`, `G-HUMAN` | no |
| `INTEGRATE` | review-report | merge | `G-PR`, `G-HUMAN` | **sí** |
| `RELEASE` | review-report | release, attestation | `G-LOCK`, `G-HUMAN` | **sí** |
| `OBSERVE` | release | observation-report | — | **sí** |
| `DOCUMENT` | code | documentation | — | **sí** |

Las opcionales **no se omiten en silencio**: si no se piden, no salen en el plan; si se piden y
no se pueden ejecutar, salen `BLOCKED` con motivo.

## Roles, no agentes

Cada fase la ejecutan uno o varios **roles**. Un rol es una unidad de trabajo con contrato; un
**agente** es un runtime que puede ejecutarlo. El router los empareja por capacidad.

```
ROL     qué hay que hacer, qué produce, qué puede tocar, qué revisión necesita
AGENTE  un runtime con adapter: claude · kiro · gemini · opencode · codex
```

Esa lista es la de los **adapters registrados**, es decir, de quién se puede sondear. No es la de
quién abre sesión gobernada (cuatro: `claude`, `kiro`, `gemini`, `opencode`) ni la de quién tiene
el guardián enganchado (tres: `claude`, `kiro`, `antigravity`). Los tres conjuntos son distintos y
están en la tabla de capacidades del [`README.md`](../../README.md).

Esa separación entre rol y agente es lo que permite cambiar de agente sin tocar el proceso, y
añadir un rol sin tocar ningún adapter.

## Dónde para el trabajo y espera a una persona

| Fase | Revisión | Qué mira que ninguna máquina mira |
|---|---|---|
| `SPECIFY` | `HUMAN_APPROVAL` | ¿la fase siguiente se puede construir encima de esto? |
| `ARCHITECT` | `HUMAN_APPROVAL` | ¿hay un requisito que nadie sabrá comprobar? |
| `VALIDATE` | `HUMAN_VISUAL_REVIEW` | ¿el orden de tabulación tiene sentido? ¿se entiende con lector de pantalla? |
| `VALIDATE` | `HUMAN_PR_REVIEW` | ¿hay algo aquí que nadie sabrá mantener dentro de un año? |
| `SECURE` | `HUMAN_SECURITY_REVIEW` | ¿algún hallazgo «bajo» deja de serlo en producción? |
| `RELEASE` | `HUMAN_RELEASE_APPROVAL` | ¿se puede revertir esto en cinco minutos? |

Una fase con revisión obligatoria **no termina sin ella**, aunque el agente diga que acabó y
todas las puertas estén en verde. El motor la deja en `BLOCKED` y lo dice.
