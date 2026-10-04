# ADR-0004 · El lock se verifica antes de escribirse, y ancla por commit

**Estado:** aceptado · **Fecha:** 2026-08-27

## Contexto

El espacio SDD materializa su estándar y su verificación desde un repositorio central, y guarda
las huellas en `.nucleo.lock.json`. La puerta V7 las comprueba.

## Problema

La secuencia era:

```
git clone --branch v3.0.1  →  copiar 36 archivos  →  REESCRIBIR el lock  →  comparar
```

Comparar contra un lock que se acaba de fabricar con las huellas de lo que se acaba de traer no
comprueba nada: siempre coincide. Y el ancla era una **etiqueta de git**, que es mutable.

La superficie no es teórica: ese repositorio entrega `verificacion/*.py` — **el juez** — que
después se ejecuta en local y en CI de todas las fábricas. Mover una etiqueta es ejecución de
código arbitrario, con V7 en verde.

## Decisión

```
LOCK CONOCIDO → TRAER ORIGEN → FIJAR COMMIT INMUTABLE → VERIFICAR CONTENIDO
              → COMPARAR CONTRA EL LOCK → FALLAR SI HAY DERIVA
              → ACTUALIZAR EL LOCK SÓLO SI SE PIDE EXPLÍCITAMENTE
```

Tres invariantes, los tres con prueba adversarial:

- **I1** · `verify()` nunca escribe el lock.
- **I2** · el ancla persistida es un SHA de 40 o 64 hex; una etiqueta produce `FAIL`.
- **I3** · una etiqueta que se movió produce `FAIL`, no un lock nuevo.

`refuto lock plan` muestra el diff completo antes de escribir. Un lock que se actualiza solo
no es un lock: es un caché.

## Consecuencias

- Actualizar el estándar deja de ser un efecto secundario de sincronizar. Es una decisión, con
  su diff delante.
- `--check-remote` consulta el origen con `git ls-remote` y detecta la etiqueta movida. Sin él,
  la puerta comprueba deriva **local** y lo dice en sus observaciones, para que nadie lea de más.
- En el espacio SDD real: `v3.0.1` → `ea11fe8c09ee3e6e22735b853d33dd48f212d05f`, 21 archivos
  anclados, 0 desviaciones.

## Lo que sigue faltando

El lock no lleva **firma**. Ancla por contenido y por commit, que impide la sustitución
silenciosa, pero no acredita quién publicó ese commit. Ver riesgo residual RR-01.
