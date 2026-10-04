# Modelo de eventos — diseño, con lo que hoy existe medido

> Estado: **DISEÑO**. Nada de este documento está implementado todavía. Las tablas marcan qué
> es `HOY` (medido en ejecución) y qué es `PROPUESTO`. Un documento de diseño que no distingue
> las dos cosas es la documentación obsoleta que §25 prohíbe, escrita por adelantado.

## 1 · Lo que hay hoy, medido

```
/usr/bin/grep -rn 'append_event' core gates adapters refuto.py
python3 -c "…collections.Counter(kind) sobre .harness/evidence/ledger.jsonl…"
```

**Ocho** tipos emitibles; **tres** observados en el diario real de este espacio (117 eventos):

| tipo | emisor | observados |
|---|---:|---:|
| `policy/decision` | `core/guard.py::main` | 114 |
| `run/complete` | `core/evidence.py::write_run` | 2 |
| `session/open` | `core/session.py::launch` | 1 |
| `session/close` | `core/session.py::launch` | 0 |
| `session/error` | `core/session.py::launch` | 0 |
| `run/finish` | `core/run.py::finish` | 0 |
| `agent/run` | `core/run.py::execute_step` | 0 |

Dos observaciones que el diseño tiene que resolver:

1. **`run/finish` y `run/complete` son terminales de entidades distintas** — orquestación y
   verificación — y se leen como sinónimos. Ver [ADR-0012](../decisions/ADR-0012-identidad-de-ejecucion.md).
2. **El 97 % de los eventos son del guardián.** El diario describe bien lo que se denegó y casi
   nada de lo que se hizo. Para §14 («reconstruir la cadena») eso es un diario de una sola capa.

## 2 · Por qué NO se adopta OpenTelemetry como modelo de eventos

Investigado el 2026-09-22 ([fuentes](#fuentes)):

- Las convenciones GenAI de OTel definen `invoke_agent` → `chat` / `execute_tool` con
  atributos `gen_ai.*`, y son la opción obvia para la neutralidad que §6 exige.
- **Pero** la parte de agentes y orquestación de herramientas está marcada **Development** y
  cambió en cada versión de v1.37 a v1.41.

**Decisión:** la evidencia de refuto **no** se define como telemetría OTel. §23 ya lo pide por
otra razón —«separar explícitamente Evidence, Telemetry y Evaluation»— y la inestabilidad del
estándar lo confirma: atar el formato de la evidencia a un blanco móvil haría que una evidencia
de hace seis meses dejara de validar sin que nada del sistema hubiera cambiado.

**Lo que sí se adopta:** un *mapeo* declarado de eventos de refuto a spans OTel, en un módulo
aparte y opcional. La evidencia es la autoridad; la telemetría es una proyección de ella. Si el
estándar cambia, cambia el mapeo y no el archivo histórico.

## 3 · Lo que se adopta de in-toto

Para el **artefacto** de evidencia (no para el evento suelto), la forma in-toto Statement v1:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{"name": "…", "digest": {"sha256": "…"}}],
  "predicateType": "https://refuto.dev/harness.run/v1",
  "predicate": { … }
}
```

Tres propiedades que se quieren y que hoy no se tienen:

- `subject[]` **obliga** a que todo artefacto citado lleve su digest. Hoy la evidencia cita
  rutas; una ruta sin digest no demuestra sobre qué se opinó.
- `predicateType` lleva la versión mayor en la URI: romper el formato obliga a cambiar la URI,
  así que una rotura silenciosa deja de ser posible (§31).
- La regla de parseo «los consumidores **deben** ignorar campos desconocidos» permite añadir
  campos sin romper lectores viejos.

## 4 · Vocabulario propuesto

Los 8 de hoy se conservan como alias de lectura. Ninguno se borra: un diario histórico tiene que
seguir siendo legible por el código que lo lee (§31).

| dominio | evento | hoy | nota |
|---|---|---|---|
| ciclo | `run/created` `run/started` `run/paused` `run/resumed` `run/completed` `run/failed` `run/aborted` | `run/finish` | §19 exige los estados intermedios; hoy sólo hay terminal |
| sesión | `session/started` `session/ended` `session/error` | ✓ 3 | renombrado con alias |
| descubrimiento | `discovery/started` `discovery/completed` | — | |
| política | `policy/compiled` `policy/bound` `policy/decided` | ✓ 1 | `policy/decision` → alias |
| agente | `agent/started` `agent/stopped` | ✓ `agent/run` | se parte en dos: hoy no se sabe cuánto duró |
| subagente | `subagent/started` `subagent/stopped` | — | §21; exige `parent_id` |
| herramienta | `tool/requested` `tool/allowed` `tool/denied` `tool/executed` `tool/failed` | — | hoy `policy/decision` mezcla pedir y decidir |
| artefacto | `artifact/created` `artifact/modified` | — | **con digest**, o no es evidencia |
| prueba | `test/started` `test/passed` `test/failed` | — | |
| puerta | `gate/started` `gate/pass` `gate/fail` `gate/blocked` | — | hoy sólo el agregado en `run/complete` |
| humano | `approval/requested` `approval/granted` `approval/rejected` | — | §22; con identidad y ámbito |
| recurso | `resource/exceeded` | — | §20 |

### Procedencia mínima obligatoria de todo evento

```
ts            instante con zona horaria
kind          del vocabulario cerrado; uno desconocido NO se acepta en silencio
correlation   { session_id, orchestration_id, context_id, parent_id }
actor         { runtime, version, euid, sudo_user }
```

`actor.euid` y `sudo_user` ya se escriben hoy en `policy/decision` — se generalizan, porque la
pregunta «¿quién hizo esto?» no es sólo del guardián.

## 4 bis · `evidence/anchor` (añadido el 2026-09-27, ADR-0017)

Un `kind` nuevo que SÍ se emite hoy (`core/concordia.py::anclar`), uno por intento de anclaje,
con o sin éxito — un anclaje fallido es un hecho del diario:

```
kind              evidence/anchor
run_id            la verificación a la que pertenece («» si se ancló a demanda sin verificación)
status            PASS | FAIL | NOT_EXECUTABLE | BLOCKED   (los de core.model)
seq               posición certificada en el log de concordia (null si no hubo certificado)
entry_digest      digest de la entrada certificada
root · size       el checkpoint: cabeza y tamaño del diario que se anclaron
membership_digest el pin bajo el que se ancló
signers           índices que firmaron; rejected: atestaciones que no contaron y por qué
reason · path     motivo si no es PASS; fichero refuto.anchor/v1 en .harness/evidence/anchors/
```

El evento **no** es el ancla: el ancla es el fichero (certificado + membresía + carga, tal cual
llegaron). El evento es la constancia encadenada de que se intentó y con qué resultado; editarlo
rompe la cadena (`test_evento_de_anclaje_manipulado_rompe_la_cadena`). En el vocabulario de §4
cae en el dominio «artefacto» con digest, que es la condición que ese apartado ponía.

## 5 · Lo que este documento NO afirma

- Que el vocabulario propuesto sea suficiente. Se derivó de §8 y de lo medido; sólo la
  implementación dirá qué falta.
- Que el mapeo a OTel funcione: `NOT_RUN`.
- Que la forma in-toto sea compatible con los lectores actuales del ledger: `NOT_RUN` hasta que
  exista la prueba de compatibilidad de [ADR-0012](../decisions/ADR-0012-identidad-de-ejecucion.md).

## Fuentes

- OpenTelemetry, convenciones semánticas GenAI — estado Development para spans de agente,
  cambios en v1.37–v1.41. `https://opentelemetry.io/docs/specs/semconv/gen-ai/`
- in-toto Attestation Framework, Statement v1 — `_type`, `subject[]` con digest obligatorio,
  `predicateType`, regla de campos desconocidos.
  `https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md`
- SLSA, modelo de atestación — `https://slsa.dev/attestation-model`
