# ADR-0017 · El ancla del diario la certifica un quórum de concordia, y refuto la verifica solo

**Estado:** aceptado · **Fecha:** 2026-09-27 · **Implementación:** `core/concordia.py`, `core/ed25519.py`,
`refuto.py` (`verify`, `status`, `evidence --anchor|--anchor-check`), `schemas/manifest.schema.json` (`anchoring`).

## Contexto

`core/evidence.py::verificar_cadena(ws, esperado, eventos_minimos)` acepta desde C-02 un **ancla
publicada** —la cabeza del diario y su tamaño— y con ella detecta los seis ataques que la cadena
sola no ve (reescritura coherente, sustitución, truncación de cola, cadena alternativa, rollback,
vaciado: `tests/adversarial/test_ledger_ataques.py`). Medido el 2026-09-25: **ninguna orden producía
esa ancla** y `core/evidence.py` citaba un `--anchor` que no existía. Los seis estaban «cerrados en
el motor y abiertos en la práctica» (`docs/research/sistemas-de-frontera.md §1`).

Y un ancla no vale por existir: vale por **quién** la sostiene. Un fichero del mismo `uid` lo mueve el
mismo `uid` (FORMAL-MODEL §6.2); un servidor único traslada la confianza a su operador. La primitiva
que resuelve eso es una entrada **ordenada por consenso BFT y certificada por `≥ q` réplicas**:
`ai/concordia`, PHASE 1 (`docs/CERTIFICATE-SPEC.md`, `telhar:v1:ordered-evidence-entry`).

## Decisión

1. **Refuto ancla checkpoints, no eventos.** Un `refuto.checkpoint/v1` =
   `{origin, size, root, engine_digest, policy_digest, membership_digest, run_id}` se envía a
   `POST /v1/order` tras cada `verify` (y a demanda con `evidence --anchor`). `root`+`size` son las
   dos mitades del ancla en un objeto; `engine_digest`+`policy_digest` atan `I6'` a terceros.
2. **Refuto verifica el certificado él mismo, offline, desde la especificación.** No delega el
   veredicto en concordia ni en `hicon`: reconstruye la membresía (§2), el sujeto de 140 bytes (§3)
   y las comprobaciones 1–9 (§5) en `core/concordia.py`, con Ed25519 en `core/ed25519.py` (RFC 8032,
   sólo `hashlib`). `hicon verify-entry` queda como **oráculo diferencial** en las pruebas, no como
   dependencia.
3. **El pin de membresía es de una persona y vive en el manifiesto** (`anchoring.membership_digest`,
   ruta protegida, esquema cerrado), con una segunda fuente opcional del invocador
   (`--membership-digest` / `REFUTO_MEMBERSHIP_DIGEST`). Sin pin → `BLOCKED`. Dos fuentes que
   discrepan → `FAIL`. **Nunca** se toma de lo que sirve el clúster.
4. **Estados: los seis de refuto, sin inventar ninguno.** PASS sólo con certificado válido bajo el
   pin y carga byte a byte igual al checkpoint enviado. Clúster caído, plazo, basura, certificado
   incompleto en todas las réplicas → `NOT_EXECUTABLE`. Membresía ≠ pin, firma inválida, quórum
   insuficiente, carga distinta, ancla que ya no está en el diario → `FAIL`. Sin pin → `BLOCKED`. Ancla
   ausente o ilegible con anclaje declarado → `INCONCLUSIVE`. Espacio sin `anchoring` →
   `NOT_APPLICABLE` y comportamiento histórico intacto.
5. **`status` relee OFFLINE.** No habla con el clúster: verifica el ancla guardada (certificado +
   membresía + carga) contra el pin de ahora y el diario de ahora. Es lo que convierte los seis
   ataques en detectados en la frontera operativa.
6. **Verificación ≠ operación.** Las puertas y el ancla son dos dimensiones; se imprimen y viajan por
   separado (`payload.gates`, `payload.anchor`) y sólo se funden en el estado agregado, donde ninguna
   convierte a la otra en PASS. La excepción documentada de `status` (puertas en rojo → PASS con
   `next`) se conserva.

7. **Sólo local hasta la publicación** (añadido el 2026-09-27 por decisión de la persona). `anchoring.endpoints`
   sólo admite loopback (`127.0.0.1`, `localhost`, `[::1]`), en el esquema y en `anclar` (`es_local`), que lo
   decide antes de abrir ninguna conexión. No hay SDK de TELHAR que exponga concordia (medido: `sdk/python`
   vacío, `sdk/typescript` sin referencia alguna); refuto consume la API HTTP del contrato directamente con
   `urllib`, que es además lo único compatible con ADR-0002. Cuando se publique, levantar la restricción es
   una decisión de persona y un cambio en los dos sitios nombrados.

8. **Lo que el ancla afirma se vuelve a comprobar** (añadido el 2026-09-28 tras auditar la
   decisión: [`docs/assurance/AUDITORIA-ANCLA-CONCORDIA.md`](../assurance/AUDITORIA-ANCLA-CONCORDIA.md)).
   El punto 1 decía que `engine_digest`+`policy_digest` atan `I6'` a terceros, y era cierto sólo a
   medias: los campos se certificaban y **ninguna orden los volvía a mirar**. Medido, un motor
   mutado releía el ancla y devolvía `PASS`. Ahora la discrepancia de motor es `INCONCLUSIVE`
   —el certificado sigue valiendo; lo que no se puede establecer es a quién atribuir el veredicto—
   y un `policy_digest` sin digest dice `sin-politica` o `irresoluble` en vez de ir en blanco.
   El `timeout_s` del punto 4, que se leía como plazo por petición, es ahora un presupuesto de la
   operación entera: declarando 2 s, una réplica que goteaba la respuesta lo estiraba a 34,4 s.

## Alternativas descartadas

| opción | por qué no |
|---|---|
| A · delegar en `hicon verify-entry` | añade un ejecutable de 8 MB cuya procedencia refuto no puede atestar; rompe ADR-0002 y «offline por construcción»; un `exit 0` es un booleano remoto |
| B · una dependencia (`pynacl`, `cryptography`) | no está instalada; ADR-0002 la admite sólo como opcional con `BLOCKED` en ausencia, es decir, el ancla quedaría bloqueada en la instalación por omisión |
| C · verificador propio + diferencial con Rust en las pruebas | **elegida**: ~150 líneas de Ed25519 verificables y huelladas por `core.trust`; conformidad con los 21 vectores y 200 mutaciones; regeneración byte a byte del vector 01 desde la semilla de `testkit.rs` |

## Divergencias declaradas con la referencia

- `core/ed25519.py` rechaza codificaciones no canónicas de puntos (`y ≥ p`, «−0») y claves de orden
  pequeño; `ed25519-dalek::verify` tolera las primeras al decodificar. Dirección segura (refuto
  rechaza más); ningún firmante honesto las produce.
- Refuto rechaza **campos fuera del contrato** en la entrada (`Malformed`) y en la membresía
  (`BadMembership`); `serde` en concordia los ignora. Es lo que el esquema
  (`additionalProperties: false`) exige.

## Límites que esta decisión NO cierra

- **`uid(S) = uid(J)`**: el pin del manifiesto es tamper-evidente, no tamper-proof. Quien reescriba el
  manifiesto por fuera del guardián **y** controle un clúster falso obtiene anclas que verifican; lo
  visible es que **todas las anclas anteriores dejan de verificar** bajo el pin nuevo
  (`test_cambiar_el_pin_despues_invalida_las_anclas_anteriores`). El pin del invocador (CI) es la
  única fuente fuera de la autoridad del sujeto.
- **Sin durabilidad en concordia** (SPEC §8.4): tras un reinicio total el log empieza en `seq 1`. El
  ancla guardada sigue verificando offline; no se puede volver a pedir. Medido en el E2E real (paso 7).
- **Sin hora ni anclaje Merkle/Rekor**: la primera no existe en el consenso; el segundo es de
  vestigium (INV-E-C).
- **Cambio de membresía y batching**: fuera de fase en concordia; refuto no los usa (`epoch` fijo).
- **`event_class` de `telhar:v1:evidence-event`** no tiene clase para este checkpoint; refuto no emite
  ese contrato en esta fase (`kind = evidence/anchor` en su propio diario). La clase la decide una
  persona por ADR-A1.

## Qué la haría cambiar

Que refuto tenga una identidad distinta de la del sujeto (otro `uid`, otra máquina): entonces el pin
podría vivir fuera del árbol por construcción y el límite del primer punto desaparecería. O que
vestigium exista: el ancla de concordia pasaría a ser una hoja de un árbol con prueba de inclusión.
