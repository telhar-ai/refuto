# Reglas para cualquier agente que trabaje en este repositorio

Vale igual para Claude Code, Antigravity, Kiro, Codex, Cursor, Gemini CLI o quien venga.
Es la fuente única: `CLAUDE.md` la importa, y Antigravity la carga sola. Si la configuración
de tu herramienta dice otra cosa, gana este fichero.

`refuto` gobierna agentes. Un agente que trabaja sobre él sin gobierno es una contradicción
que ya costó cara: antes de su primera publicación, este repositorio llegó a versionar notas
internas sobre un cliente porque el propio `.gitignore` no las excluía.

## Ábrelo por la raíz

Abre el repositorio en esta carpeta, no en una subcarpeta. Los ganchos de cada agente se
buscan en la raíz (`.claude/`, `.agents/`, `.kiro/`, `.codex/`). Desde una subcarpeta trabajas
sin guardián.

## Lo que no se toca

- `.harness/policy.json`: la política que te gobierna. No te desenganches a ti mismo.
- Los ficheros que instalan los ganchos y la política compilada de cada runtime:
  `.claude/settings*`, `.agents/hooks.json`, `.kiro/hooks/*`, `.codex/hooks.json`,
  `.gemini/hooks/*`, `.gemini/policies/*`, `.aidlc/*`, `opencode.harness.json`. La lista no se
  escribe a mano: la deriva `tests/selftest/test_artefactos_del_guardian.py` de lo que cada
  adaptador declara en `compile_policy`, porque escrita a mano ya divergió —medido el
  2026-10-03, 3 de 7 artefactos eran reescribibles por el agente, uno de ellos el gancho que lo
  vigila—.
- Nada de estado local (`.harness/state/`, `evidence/`, `memory/`, `context/`, `backup/`,
  `bin/`, `binding.json`): está en `.gitignore` por una razón.

Si un cambio los necesita, escribe el bloque exacto y **para** hasta que una persona lo aplique.

## Nada personal, nada de clientes

Este repositorio es público. No entran nombres de clientes o empleadores, rutas `/Users/…`,
correos, hosts internos, direcciones privadas ni mediciones que sólo tengan sentido en la
máquina de alguien. Un ejemplo se escribe `example-org`, `mi-espacio`, `/ruta/al/espacio`.

Para comprobarlo aquí, `grep` no basta: en algunos equipos es una función del shell que
respeta `.gitignore` y se salta justo lo más sensible. Usa la ruta completa:

```sh
/usr/bin/grep -rIn --exclude-dir=__pycache__ -iE 'patron' .
```

## Toda afirmación con su nivel y su estado

Niveles: `E0` dicho · `E1` documentado · `E2` reproducible · `E3` probado · `E4` observado en
ejecución. Estados: `PASS` `FAIL` `BLOCKED` `NOT_RUN` `INCONCLUSIVE` `NOT_APPLICABLE`.
«Pendiente» no es un estado. Una cifra sin su orden, su fecha y su máquina no es una medición.

**Un ámbito vacío nunca aprueba.** Es la regla que este programa existe para aplicar, y se
aplica también a sí mismo: una suite que ejecuta 0 pruebas falla, y una puerta sin nada que
examinar da `NOT_APPLICABLE`, nunca `PASS`.

## Antes de dar algo por terminado

```sh
python3 refuto.py selftest        # suite completa
python3 scripts/check_stdlib_only.py   # sin dependencias fuera de la biblioteca estándar
python3 scripts/check_schemas.py
python3 scripts/check_wiring.py
```

No debilites una prueba para que pase. Si una prueba afirma algo falso, arregla la prueba y
dilo.

## Declárate

Si haces un commit, añade tu trailer (`Co-Authored-By: <agente> <correo>`). Un commit de
agente sin trailer es invisible para cualquier auditoría del historial.
