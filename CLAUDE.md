# refuto — lo específico de Claude Code

Las reglas del repositorio son comunes a todos los agentes y viven en un solo sitio:

@AGENTS.md

## Sólo para Claude

- El guardián se engancha como `PreToolUse` en los ajustes locales de `.claude/`
  (`python3 refuto.py policy wire --agent claude`). La política es una sola:
  `.harness/policy.json`, compilada al dialecto de cada agente.
- `python3 refuto.py chat --agent claude` abre una sesión gobernada: informe de sesión,
  guardián enganchado y rastro en la cadena de evidencia.
