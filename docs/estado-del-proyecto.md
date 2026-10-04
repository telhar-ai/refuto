# Estado del proyecto

Qué está demostrado, a qué nivel, y qué sigue abierto. Este documento existe para que nadie
tenga que deducirlo leyendo el `CHANGELOG`.

**Última revisión:** 2026-09-22. **Máquina de las mediciones:** macOS arm64, Darwin 25.4.0,
Python 3.14.6 y 3.12. Toda cifra sin fecha y sin comando en el resto de la documentación es un
defecto: repórtelo.

## La escala

| Nivel | Significa | Qué hace falta |
|---|---|---|
| `E0` | dicho | nada. Una afirmación sin respaldo se lee como `E0` |
| `E1` | documentado | está escrito en el código o en un documento que se puede citar |
| `E2` | reproducible | hay un comando que cualquiera puede ejecutar y obtiene lo mismo |
| `E3` | probado | lo fija una prueba automática que falla si deja de ser cierto |
| `E4` | verificado en ejecución | se observó ocurrir, con fecha, máquina y versión |

Estados permitidos para una comprobación: `PASS` `FAIL` `BLOCKED` `NOT_RUN` `INCONCLUSIVE`
`NOT_APPLICABLE`. «Pendiente» no es un estado; `NOT_RUN` sí.

## Lo que está demostrado

| Afirmación | Nivel | Evidencia |
|---|---|---|
| La suite completa pasa | `E3` | `python3 refuto.py selftest` → **580/580, 1 omitida** (sólo Windows), 268 s. 2026-09-23, macOS arm64, Python 3.14.6. La cifra anterior, 478/478, es del 2026-09-22 |
| Reparto por suite | `E2` | unit 409 · contract 26 · selftest 72 · adversarial 73 = **580**, contado con `ast` sobre los métodos de clase. `grep -rc "def test_"` da 581: cuenta un `def test_` que vive **dentro de una cadena** en `tests/unit/test_corredor.py:102`, donde esa prueba fabrica una suite desechable. El total del corredor es la autoridad; el `grep` sobrecuenta |
| 13 puertas registradas | `E2` | `gates/base.py::GATES` |
| 22 roles en 9 grupos | `E2` | `roles/registry.json` |
| 13 fases del ciclo | `E2` | `core.lifecycle.PHASES` |
| 5 adapters registrados | `E2` | `adapters/registry.py` |
| Sin dependencias de terceros | `E2` | `python3 scripts/check_stdlib_only.py`, en local, 2026-09-22 |
| `Result` no admite `PASS` con hallazgos | `E3` | `tests/contract/test_result_contract.py` |
| Un adapter sin política no puede declarar `unenforceable: []` | `E3` | `tests/contract/test_result_contract.py` |
| El lock: `verify()` no escribe, el ancla es un SHA, una etiqueta movida da `FAIL` | `E3` | `tests/adversarial/test_attacks.py` |
| 27 pruebas adversariales existen y pasan en local | `E3` | `grep -c "def test_" tests/adversarial/test_attacks.py` → 27; incluidas en el 580/580. La suite adversarial entera son 73: las otras 46 atacan la herencia de política |
| La herencia de política llega al **guardián**, no sólo a un comando de consulta | `E4` | `tests/adversarial/test_herencia_efectiva.py` ejecuta `core.guard` como proceso y lee su decisión: una regla que sólo está en el padre deniega, y dos controles (`allow`) impiden cerrarlo con un «deniega todo». 2026-09-23 |
| Un hijo no puede retirar ni ensanchar lo del padre | `E3` | `tests/adversarial/test_monotonia.py` (10 ataques) y `test_violaciones_refinamiento.py` (5 violaciones encontradas auditando, 3 cerradas y 2 declaradas abiertas) |
| El esquema de política publicado describe lo que el programa produce | `E3` | `tests/contract/test_policy_schema.py`: valida 7+ documentos reales, con control de que el validador no está mudo y guarda contra deriva de campos |
| El guardián bloquea una escritura sobre el juez en dos runtimes con vocabulario incompatible | `E4`, **n=1** | 2026-08-27, macOS arm64, `claude 2.1.247` y `kiro 2.20.0`. [`validation/informe.md`](validation/informe.md) |
| Un agente real escribió una prueba que cita su requisito y pasa, bajo puertas y con tope de gasto | `E4`, **n=1** | 2026-08-27, `claude 2.1.247`, fase `TEST`. [`examples/end-to-end-run.md`](examples/end-to-end-run.md) |

Las dos últimas son `E4` **de un caso**, no de la tesis. Una ejecución con dos agentes el mismo
día en la misma máquina no es evidencia estadística de nada; es la prueba de que el mecanismo
puede ocurrir.

## Lo que no está probado

| Sujeto | Estado | Por qué |
|---|---|---|
| Ejecución en **Linux** | `NOT_RUN` | la suite no se ha ejecutado ahí |
| Ejecución en **Windows** | `NOT_RUN` | hay código de portabilidad; sobre este árbol no hay medición propia. En macOS queda **1 prueba omitida** por ser sólo de Windows |
| **Python 3.10**, el mínimo declarado | `NOT_RUN` | no hay intérprete 3.10 en la máquina de medición. El árbol parsea con `ast.parse(feature_version=(3,10))` (`E2`), que no es lo mismo que ejecutar |
| **CI en GitHub Actions** | `NOT_RUN` | el flujo existe y **nunca ha corrido en verde**. Hasta que lo haga, ninguna afirmación puede decir «comprobado en CI» |
| `codex` conduciendo trabajo | `NOT_RUN` | hay adapter, sonda y compilación de política; no hay ejecución observada |
| `antigravity` en vivo | `NOT_RUN` | el dialecto se derivó de la documentación embebida en el binario 2.15.1, leída el 2026-09-21 con `strings` (`E1`). No se observó ninguna decisión suya |
| `gemini` y `opencode` con guardián | `NOT_RUN` | no hay enganche que verificar: `policy wire` no los cubre |
| Que Gemini lea `.gemini/hooks/harness-guard.json` | `NOT_RUN` | el artefacto se genera; que el agente lo cargue no se ha comprobado |
| Ciclo completo de las 13 fases | `NOT_RUN` | se ejecutó `TEST` |
| Claude Desktop, escritura bloqueada de extremo a extremo | `NOT_RUN` | el lanzador se probó con entorno vacío (`env -i`), que es la condición dura; la escritura desde la aplicación no se llegó a observar |
| Interrogación de servidores MCP por HTTP | `BLOCKED` | necesitan la credencial de la sesión del agente; `refuto` no la pide |
| Coste real del sondeo de Claude Code | `NOT_RUN` | se envía `-p hi` con tope `--max-budget-usd 0.05`; el gasto no se midió |

## Riesgos y divergencias abiertas

> **Revisión del 2026-09-23.** Una auditoría adversarial midió esta lista contra HEAD y la
> encontró **invertida**: los riesgos 1, 2 y 3 estaban ya cerrados y seguían declarados
> abiertos, mientras los que sí estaban abiertos no figuraban. Se reescribe entera. Las
> entradas cerradas se conservan tachadas: perder la constancia de que algo estuvo roto es
> perder justo lo que evita volver a romperlo.

**~~1 · El vocabulario de estados no es el del contrato.~~ CERRADO.** `core/model.py`
implementa seis: `PASS FAIL BLOCKED NOT_EXECUTABLE NOT_APPLICABLE INCONCLUSIVE`. El sexto se
añadió el 2026-09-23 para poder decir «las dos fuentes de verdad no coinciden». Queda la
divergencia menor de uso: varias puertas siguen diciendo `BLOCKED` donde querrían decir
`NOT_APPLICABLE` (`gates/g_sdd.py`, `g_agent.py`, `g_fleet.py`, `g_human.py`, `g_trace.py`).

**~~2 · Un ámbito vacío puede aprobar en dos sitios.~~ CERRADO en los dos declarados, y había
un tercero que no estaba.** `gates/g_mcp.py` da `NOT_APPLICABLE`; `tests/runner.py` sale con 1.
El que faltaba era `gates/g_security.py`, que aprobaba con «0 archivos recorridos» incluso con
una credencial `AKIA…` real bajo `node_modules/`, y `core/lock.py`, que comparaba cero huellas
contra cero huellas. Ver el riesgo 8.

**~~3 · Los códigos de salida colisionan.~~ CERRADO.** Medido el 2026-09-23: todo error de uso
sale con `64` y el bloqueo con `2`. No hay colisión.

**8 · `PASS` exige cobertura, y once puertas todavía no la declaran.** `Result.scope` existe y
`core.evidence.verdict_of` se niega a contar como aprobada una puerta que no declara qué
observó. `core/lock.py` ya la declara. `gates/**` está protegido —el sujeto no puede editar a
su juez— así que el cambio de `g_security.py` va **propuesto** en
[`remediation/gates-cobertura.patch`](remediation/gates-cobertura.patch) y las otras once
puertas están pendientes. Hasta entonces, una corrida con esas puertas no es integrable, que
es el comportamiento honesto y también el incómodo.

**9 · `I6` no es demostrable en esta frontera.** «El agente no puede escribir al juez» exige
decidir el efecto de una orden (no computable) o una frontera de proceso que hoy no existe
(mismo uid, mismo sistema de archivos). Se afirma `I6'` en su lugar: si el juez fue modificado,
ningún veredicto posterior es `PASS`. Ver
[ADR-0013](decisions/ADR-0013-raiz-de-confianza-y-modelo-de-efectos.md).

**10 · Truncar la cola del diario no se detecta sin un ancla publicada.** La cadena de huellas
ve edición, borrado y reordenación; cortar por el final deja los eslabones restantes
consistentes. `NOT_PROVEN` mientras nadie publique la cabeza fuera del árbol.

**4 · `policy unwire` no borra lo que `wire` creó.** Restaura desde `.harness/backup/`, que sólo
contiene lo que ya existía. Un `.claude/settings.local.json` creado por `wire` sobrevive al
`unwire`.

**5 · `G-SDD` es un puente a un componente externo.** La puerta ejecuta
`verificacion/verificar.py --json` del espacio y traduce su vocabulario. Ese verificador **no
forma parte de este repositorio** y puede no ser obtenible por un tercero. Sin él, `G-SDD` no
aplica: hoy lo dice como `BLOCKED`.

**6 · Varios valores por defecto están calibrados sobre un solo corpus.** La búsqueda de
especificaciones, el tratamiento de `.worktrees/` y el registro de capacidades vienen de la
forma que tenía un conjunto de repositorios concreto y privado. Son genéricos en la mecánica y
opinables en los valores; declararlos en el manifiesto está pendiente.

**7 · No hay ninguna etiqueta de git publicada.** `VERSION` y `CHANGELOG` describen trabajo que
puede no coincidir con lo que un `clone` obtiene. Compruebe `VERSION` en su copia antes de citar
una versión.

## Cómo reproducir las cifras de este documento

```bash
python3 refuto.py selftest                              # 580/580, 1 omitida

# Reparto por suite. `grep -rc "def test_"` sobrecuenta: recoge un `def test_` que vive dentro
# de una cadena. Lo que unittest recoge son los métodos de clase, así que se cuentan con `ast`.
python3 -c "
import ast, collections, pathlib
t = collections.Counter()
for p in pathlib.Path('tests').rglob('*.py'):
    for c in ast.parse(p.read_text(encoding='utf-8')).body:
        if isinstance(c, ast.ClassDef):
            t[p.parts[1]] += sum(1 for m in c.body
                                 if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
                                 and m.name.startswith('test_'))
print(dict(t), sum(t.values()))"
python3 -c "from gates.base import GATES; print(len(GATES))"
python3 -c "from core.lifecycle import PHASES; print(len(PHASES))"
python3 -c "import json;print(len(json.load(open('roles/registry.json'))['roles']))"
python3 scripts/check_stdlib_only.py
```

Si alguno devuelve otra cosa, la documentación está mal y no su máquina: ábralo como incidencia
con el sistema, el intérprete y la salida.
