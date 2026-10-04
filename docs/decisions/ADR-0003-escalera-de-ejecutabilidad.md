# ADR-0003 · Cinco peldaños de ejecutabilidad, y `which` no es ninguno

**Estado:** aceptado · **Fecha:** 2026-08-27

## Contexto

Todo arnés auditado comprobaba la disponibilidad de un agente con `command -v`.

## Problema, encontrado ejecutando

`@openai/codex@0.103.0` está en el PATH, tiene versión en su `package.json`, y **no arranca**:

```
$ codex --version        → (sin salida)  rc=137  (SIGKILL)
$ codesign -v --verbose=2 <binario nativo>
  → CSSMERR_TP_CERT_REVOKED    TeamIdentifier=2DC432GLL2
```

macOS lo mata porque el certificado de firma está revocado. `command -v codex` dice que sí.

## Decisión

```
NOT_INSTALLED  no se resuelve en el PATH
INSTALLED      se resuelve                    ← el techo de lo que `which` puede afirmar
STARTABLE      arranca y no muere por señal
FUNCTIONAL     responde un handshake estructurado          ← gratis
VERIFIED       completa una tarea mínima con salida verificable   ← cuesta créditos
```

Cada peldaño implica los anteriores. La sonda se detiene en el primero que falla y **declara
dónde y por qué**.

**`FUNCTIONAL` es el umbral operativo, no `VERIFIED`.** Exigir `VERIFIED` en cada corrida y en
CI convertiría la verificación en una factura. `FUNCTIONAL` es gratis, tarda segundos y descarta
el 100 % de los fallos de instalación, firma y arranque observados.

## Por qué la firma es parte de la sonda

Porque es lo que convierte «no arranca y no sé por qué» en «el certificado está revocado, y esto
se arregla reinstalando». Sin ella el diagnóstico es una queja.

Se distinguen cuatro veredictos, no dos: `VALID`, `UNSIGNED`, `INVALID`, `REVOKED`.
Un guion de Node **nunca** lleva firma, y tratar eso como fallo produce ruido en cuatro de cinco
agentes — que es exactamente cómo una comprobación de seguridad se aprende a ignorar.

Y se comprueba el **binario nativo detrás del lanzador**, no el lanzador. La primera versión
eligió el `ripgrep` que Codex empaqueta y declaró la firma válida: comprobar la firma del
binario equivocado es peor que no comprobarla, porque da un verde falso sobre seguridad.

## Consecuencias

- El informe distingue la versión **declarada en el manifiesto de instalación** de la
  **confirmada por el binario**. Para Codex se reporta `0.103.0` con la advertencia de que no
  es ejecutable: saber qué versión es la que no arranca es la mitad del diagnóstico.
- Cinco agentes se sondean en **2,2 s** en paralelo. El coste no es excusa para no hacerlo.
- Un agente que no arranca **no se marca soportado**, por muy bien escrito que esté su adapter.
