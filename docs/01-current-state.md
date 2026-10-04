# 01 · Estado Actual de Refuto (Auditoría Empírica)

**Fecha de Auditoría:** 2026-09-30  
**Rama:** `assurance/protocolo-tres-caras` (`commit: 28e7965`)  
**Entorno de Ejecución:** macOS arm64 Darwin 25.4.0, Python 3.14.6 / 3.12 / 3.10  
**Nivel Epistémico:** `E3` (Probado mediante suite automatizada) · `E4` (Observado en ejecución directa)

---

## 1. Inventario Real del Repositorio

A través de inspección estática del árbol (`AST`) y ejecución directa, se establece el inventario fáctico del sistema:

| Componente | Cantidad Fáctica | Fuente de Verdad / Archivo | Estado de Conexión |
| :--- | :---: | :--- | :--- |
| **Pruebas Automatizadas** | 1,192 | `tests/` (`ast.parse`) | `1,142 PASS` · `50 FAIL (sandbox)` |
| **Puertas de Verificación** | 13 | `gates/base.py::GATES` | 13 registradas y ejecutables |
| **Fases de Ciclo de Vida** | 13 | `core/lifecycle.py::PHASES` | Declaradas en motor |
| **Roles de Agentes** | 22 | `roles/registry.json` | 22 roles en 9 grupos |
| **Adaptadores de Agentes** | 5 | `adapters/registry.py::ADAPTERS` | 5 registrados (`claude`, `codex`, `gemini`, `kiro`, `opencode`) |
| **Dialecto Antigravity** | 1 | `core/antigravity.py` | Conectado como extensión de guardián |
| **ADRs Existentes** | 20 | `docs/decisions/` | ADR-0001 a ADR-0020 |
| **Esquemas JSON Formales** | 4 | `schemas/` | `envelope`, `manifest`, `policy`, `roles` |
| **Dependencias Externas** | 0 | `scripts/check_stdlib_only.py` | 100% biblioteca estándar de Python |

---

## 2. Resultados de Ejecución de Pruebas

La ejecución de las suites de prueba arrojó las siguientes mediciones empíricas:

1. **Suite Unitaria (`tests/unit`):**  
   *Comando:* `python3 refuto.py selftest --suite unit`  
   *Resultado:* `Ran 535 tests in 84.881s. OK (skipped=2).`  
   *Estado:* `PASS` (`E3`).
2. **Suite de Contrato (`tests/contract`):**  
   *Comando:* `python3 refuto.py selftest --suite contract`  
   *Resultado:* `Ran 62 tests in 7.740s. OK (skipped=3).`  
   *Estado:* `PASS` (`E3`).
3. **Suite de Autodiagnóstico (`tests/selftest`):**  
   *Comando:* `python3 refuto.py selftest --suite selftest`  
   *Resultado:* `Ran 80 tests in 9.204s. OK.`  
   *Estado:* `PASS` (`E3`).
4. **Suite Adversarial (`tests/adversarial`):**  
   *Comando:* `python3 -m unittest discover tests/adversarial` (excluyendo anclaje por red)  
   *Resultado:* `Ran 414 tests in 20.990s. OK (expected failures=4).`  
   *Estado:* `PASS` (`E3`).  
   *Comando:* `test_ancla_*` (101 pruebas de anclaje Concordia BFT)  
   *Resultado:* `50 FAIL / 2 ERROR`.  
   *Diagnóstico:* Las pruebas de anclaje intentan conectar a `127.0.0.1` mediante `urllib.request.urlopen`. En sandboxes sin red loopback, el OS deniega la llamada (`Operation not permitted`). `core/concordia.py` atrapa la excepción y retorna de forma determinista `NOT_EXECUTABLE`.

---

## 3. Comandos de la CLI Existentes

Refuto expone actualmente 27 subcomandos en `refuto.py`:
* **Inspección y Diagnóstico:** `doctor`, `probe`, `discover`, `context`, `environments`, `telemetry`, `inventory`, `docs`, `status`, `selftest`.
* **Gobernanza y Políticas:** `policy` (`compile`, `wire`, `prune`, `unwire`), `guard`, `lock`, `engine`.
* **Evidencia y Puertas:** `verify`, `evidence` (`--anchor`, `--anchor-check`), `mcp`, `mcp-serve`.
* **Orquestación de Ciclo de Vida (Acoplamiento):** `chat`, `work`, `plan`, `run`, `resume`, `memory`.

---

## 4. Dos Brechas Críticas Descubiertas en Auditoría

### 4.1 Brecha 1: Falso PASS en Salida de `cmd_verify` por Cobertura No Declarada
* **Evidencia:** [`core/evidence.py:660`](../core/evidence.py#L660) vs [`refuto.py:1206-1223`](../refuto.py#L1206-L1223).
* **Mecanismo:** En `verdict_of()`, si una puerta devuelve `PASS` sin declarar `Scope`, la corrida se marca como `INCONCLUSIVE` en el texto del informe JSON. Sin embargo, `cmd_verify()` en `refuto.py` evalúa `statuses = {r.status for r in results}` sin filtrar las puertas sin scope, asigna `estado = PASS` y sale con código de proceso `0` (`EXIT_OK`).
* **Impacto:** Un pipeline CI desatendido recibe código de éxito `0` sobre una corrida que el informe interno declara `NO INTEGRABLE`.

### 4.2 Brecha 2: Ausencia de `Scope` en las 13 Puertas en Producción
* **Evidencia:** Inspección de `gates/g_*.py`.
* **Mecanismo:** Ninguna de las 13 puertas actuales pasa `scope=Scope(...)` al construir `Result`.
* **Impacto:** Toda puerta que pasa es tratada internamente por `core/evidence.py` como `INCONCLUSIVE`, haciendo que cualquier ejecución de `refuto verify` produzca un veredicto formal `NO INTEGRABLE`.
