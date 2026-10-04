# 02 · Reconciliación de Trabajo Previo

**Fecha:** 2026-09-30  
**Objetivo:** Contrastar de forma estricta las afirmaciones, auditorías y compromisos previos del repositorio frente al estado fáctico del código actual.

---

## 1. Matriz de Reconciliación Epistémica

| # | Afirmación Previa | Fuente Previa | Estado Fáctico en Código / Tests | Clasificación | Evidencia |
| :- | :--- | :--- | :--- | :--- | :--- |
| **C1** | «La suite completa tiene 580 pruebas y pasa al 100%» | `docs/estado-del-proyecto.md:27` (2026-09-22) | El repositorio creció a 1,192 pruebas. 1,142 pasan; 50 fallan en sandbox por red local loopback. | **SUPERSEDED** | Conteo AST en `tests/`: 1,192 pruebas (`E2`). |
| **C2** | «El sistema opera 100% con biblioteca estándar de Python» | `ADR-0002`, `README.md` | `scripts/check_stdlib_only.py` ejecuta y retorna 0. | **CONFIRMED** | `python3 scripts/check_stdlib_only.py` → `✓ sólo biblioteca estándar` (`E3`). |
| **C3** | «Un ámbito vacío nunca aprueba en `Result`» | `core/model.py:315`, `FORMAL-MODEL.md` | `Result(..., PASS, scope=Scope(examined=0))` levanta `ValueError`. | **CONFIRMED** | Verificado dinámicamente con contraprueba en consola (`E3`). |
| **C4** | «`PASS` sin cobertura declarada no puede ser integrable» | `core/evidence.py:660` | `verdict_of()` marca `INCONCLUSIVE`, pero `cmd_verify` en `refuto.py` sale con código 0. | **CONTRADICTED** | Reproducido: discrepancia entre `verdict_of` y `cmd_verify` (`E4`). |
| **C5** | «El ancla de Concordia se verifica offline en Python puro sin dependencias» | `ADR-0017`, `core/concordia.py` | `core/ed25519.py` implementa RFC 8032 completo con `hashlib` sin `pynacl` ni Rust. | **CONFIRMED** | 414 pruebas de integridad y criptografía pasan (`E3`). |
| **C6** | «Las 13 puertas están migradas a declarar `Scope`» | `remediation/gates-cobertura.patch` | Las 13 puertas en `gates/g_*.py` carecen del parámetro `scope=Scope(...)`. | **OPEN** | El parche existe en documentación pero no ha sido aplicado al árbol (`E2`). |
| **C7** | «La elevación de privilegios se normaliza y clasifica recursivamente» | `ADR-0020`, `core/privilegio.py` | 44 pruebas en `tests/adversarial/test_elevacion.py` pasan en 1.229s. | **CONFIRMED** | `Ran 44 tests in 1.229s. OK` (`E3`). |
| **C8** | «El diario detecta truncación de cola» | `ADR-0017`, `test_ledger_ataques.py` | Detectable únicamente cuando existe ancla publicada (`DESALINEADA`). | **CONFIRMED** | `tests/adversarial/test_ledger_ataques.py` pasa (`E3`). |
| **C9** | «El sistema no tiene acoplamiento a metodologías externas» | `ARCHITECTURE.md` | Comandos `cmd_chat`, `cmd_work`, `cmd_plan` en `refuto.py` introducen acoplamiento de ciclo de vida. | **CONTRADICTED** | Inspección de `refuto.py:1968-2320` (`E2`). |
| **C10** | «CI en GitHub Actions corre en verde» | `docs/estado-del-proyecto.md:55` | Declarado como `NOT_RUN` / pendiente en la auditoría del 2026-09-22. | **OPEN** | No hay registro de corrida pública en verde en el entorno local (`E1`). |

---

## 2. Lecciones Aprendidas de la Reconciliación

1. **La trampa del parche no aplicado:** Disponer de un parche documentado (`gates-cobertura.patch`) no equivale a tener el código protegido. Las 13 puertas en producción continúan sin emitir `Scope`.
2. **Discrepancia Semántica entre Biblioteca y CLI:** Una biblioteca puede ser matemáticamente rigurosa (`verdict_of` genera `INCONCLUSIVE`), pero si la CLI que la envuelve (`cmd_verify`) implementa su propia agregación ad-hoc, el sistema exterior recibe un falso éxito.
3. **El peligro de la orquestación expansiva:** Al intentar resolver la experiencia de usuario, Refuto comenzó a incorporar funciones de gestor de tareas (`work`) y cliente de chat interactivo (`chat`), difuminando su frontera como árbitro de verificación imparcial.
