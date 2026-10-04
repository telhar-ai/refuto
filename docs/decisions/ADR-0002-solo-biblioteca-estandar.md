# ADR-0002 · Sólo biblioteca estándar de Python

**Estado:** aceptado · **Fecha:** 2026-08-27

## Contexto

El encargo pedía `harness.manifest.yaml` y validación por JSON Schema. Las dos cosas invitan a
`PyYAML` y `jsonschema`.

## Problema

refuto existe para diagnosticar máquinas donde algo falla. Un `refuto doctor` que necesita
`pip install` para decir qué falta no sirve para lo único que hace falta que sirva. Y añade una
superficie de suministro al programa cuyo trabajo es vigilar la superficie de suministro.

La restricción se hereda del verificador externo auditado el 2026-08-27, que la declaraba así en
su propio código: *«la cadena de verificación no puede depender de una instalación que alguien
tenga que recordar hacer»*. Era correcta y se conserva.

## Decisión

Sólo biblioteca estándar. Python 3.10+.

Dos consecuencias directas:

- **El manifiesto es JSON, no YAML.** JSON está en la biblioteca estándar; YAML no. Se pierde
  legibilidad en los comentarios, y se recupera con la convención de que las claves que empiezan
  por `_` son notas para quien lee el archivo — el validador las permite siempre.
- **Validador de JSON Schema propio** (`core/schema.py`), con un subconjunto declarado. Lo
  importante no es qué soporta, sino qué hace cuando no soporta algo: **lanza**, en vez de
  ignorar la palabra clave. Un validador que valida de menos en silencio es un verde falso.
  `scripts/check_schemas.py` comprueba en CI que todo esquema del repo cae dentro del
  subconjunto.

El frontmatter de `SKILL.md` usa un subconjunto de YAML resuelto por un parser propio, con la
misma regla: una construcción fuera del subconjunto devuelve un error explícito.

## Consecuencias

- Se paga escribir un validador y un parser: ~370 líneas, ambos con pruebas de las formas
  válidas **y** de las inválidas.
- `scripts/check_stdlib_only.py` recorre el árbol. Está declarado en CI, y la CI **nunca ha
  corrido en verde** (`NOT_RUN`): hoy la comprobación que vale es la que usted ejecuta en local
  —`rc=0` el 2026-09-22 en macOS arm64—. Una promesa de diseño se erosiona con
  un `import` distraído; aquí se comprueba en vez de confiarse.
- El parser de frontmatter falló contra el propio ejemplo del repositorio la primera vez.
  Escribir un parser es barato; escribirlo bien, no. Está en el precio.

## Qué la haría cambiar

Que refuto necesite algo genuinamente fuera de la biblioteca estándar —criptografía de
firma, por ejemplo, para verificar procedencia estilo Sigstore—. Entonces la dependencia sería
opcional y su ausencia se declararía como `BLOCKED`, nunca como `PASS`.
