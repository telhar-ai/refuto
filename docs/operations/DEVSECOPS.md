# DevSecOps — qué está aplicado, qué no, y por qué

> Medido el 2026-09-23 contra `github.com/<owner>/refuto`, repositorio **privado**, plan
> gratuito. Cada fila lleva la orden que la reproduce. Lo que no se pudo aplicar se declara
> `BLOCKED` con su código HTTP: «no está» y «no se pudo» no son lo mismo.

## 1 · Lo aplicado, y con qué se comprueba

| control | estado | evidencia |
|---|---|---|
| Sin dependencias de terceros | `PASS` | `scripts/check_stdlib_only.py`, en CI |
| Acciones de CI ancladas por commit | `PASS` | 8 `uses:` por SHA, no por etiqueta móvil |
| Escáneres anclados y con checksum | `PASS` | gitleaks 8.30.1 · syft 1.52.0 · trivy 0.74.0, verificados contra el fichero de sumas de su propia release |
| Alertas de vulnerabilidad | `PASS` | `PUT /repos/…/vulnerability-alerts` → 204 |
| Dependabot (acciones de GitHub) | `PASS` | `.github/dependabot.yml`, ecosistema `github-actions` |
| Secretos fuera del árbol | `PASS` | `.gitignore` excluye `.claude/settings.local.json` y el estado local de `.harness/` |
| Las citas a código no envejecen | `PASS` | `scripts/check_citas.py`, en CI |
| La suite no deja residuo | `PASS` | `tree_sentinel` huella→suite→verifica, en CI |
| Cobertura semántica del juez | `PASS` | `mutate_probe.py`: 6 mutaciones con testigo declarado + 2 controles de calibración |
| Empujón directo a `main` | `PARCIAL` | `.githooks/pre-push` — local, se salta con `--no-verify` |

## 2 · Lo que NO se pudo aplicar

```
PUT  /repos/<owner>/refuto/branches/main/protection   → HTTP 403
POST /repos/<owner>/refuto/rulesets                   → HTTP 403
     «Upgrade to GitHub Pro or make this repository public to enable this feature.»

PATCH /repos/<owner>/refuto  security_and_analysis.secret_scanning=enabled  → HTTP 422
     «Secret scanning is not available for this repository.»
```

| control | estado | qué lo desbloquearía |
|---|---|---|
| Protección de rama / rulesets | `BLOCKED` | GitHub Pro, **o** hacer el repositorio público |
| Revisión obligatoria en PR | `BLOCKED` | lo mismo: depende de la protección de rama |
| Comprobaciones requeridas para integrar | `BLOCKED` | lo mismo |
| Secret scanning + push protection | `BLOCKED` | GitHub Advanced Security (no disponible en privado gratuito) |
| Verificación en una segunda máquina | `BLOCKED` | sólo existe una · `LIMITATION: single-host` |

**Ninguno de estos cinco se sustituye por un equivalente que finja serlo.** El gancho
`pre-push` para un descuido; no para a quien no quiera pararse. Esa distinción está escrita en
el propio gancho, porque un control que se presenta como barrera cuando es un recordatorio
hace creer que hay una defensa donde hay una costumbre.

Lo que sí es server-side y no depende del plan: **`G-PR` mira la rama al verificar** y pone la
corrida en rojo si se trabajó sobre `main`. Eso corre en CI y no hay que instalarlo.

## 3 · El criterio de CI, y por qué no es «forzar verde»

El trabajo sobre el espacio de ejemplo salía en rojo en **toda** corrida: un ejecutor sin
agentes instalados no puede comprobar `G-AGENT` ni las que dependen de ella. Un rojo
permanente se deja de leer, y entonces el día que haya un rojo de verdad nadie lo mira.

Tres salidas, y sólo una es honesta:

| | |
|---|---|
| forzar verde | convertir `BLOCKED` en `PASS`. El fraude que este repositorio existe para impedir, cometido por su propia tubería. |
| dejarlo en rojo | honesto y **inútil**: la señal deja de significar nada. |
| **declarar el bloqueo** | el trabajo afirma algo más estrecho y comprobable. ← elegida |

Cómo funciona: `scripts/gate_summary.py --bloqueo-esperado` acepta **exactamente** las puertas
declaradas en `BLOQUEO_ESPERADO`, **cada una con su motivo escrito**. Un `BLOCKED` que no esté
en la lista para la integración, porque es información nueva. Un `FAIL` o un `NOT_EXECUTABLE`
no se perdonan nunca. Y si ninguna puerta aprobó, tampoco pasa: ámbito vacío no aprueba.

El veredicto real del espacio se sigue imprimiendo entero y sigue siendo **NO INTEGRABLE**. Lo
que el trabajo afirma es: *no apareció ningún rojo ni ningún bloqueo que no estuviera
declarado*.

Ocho pruebas lo sujetan (`tests/unit/test_ci_criterio.py`), incluida
`test_G_SECURITY_no_esta_perdonada`: si alguien añade esa puerta a la lista en vez de instalar
los escáneres, la suite lo para.

### G-SECURITY: causa eliminada, no excusada

Decía «herramientas: ninguna». Ahora el trabajo instala gitleaks, syft y trivy con versión
anclada y checksum verificado, así que la puerta **se ejecuta de verdad** y su veredicto es
información en vez de ausencia de información. No está en la lista de bloqueos esperados a
propósito.

## 4 · Cómo instalar los ganchos

```sh
sh scripts/install_hooks.sh      # apunta core.hooksPath a .githooks/
```

Se versionan en `.githooks/` y no en `.git/hooks/` para que viajen con el repositorio y se
puedan revisar en un PR como cualquier otro código.

## 5 · Lo que este documento no afirma

- Que el repositorio esté a salvo. Enumera controles aplicados y controles ausentes; ninguna
  de las dos listas es una medida de riesgo.
- Que los cinco `BLOCKED` sean los únicos huecos. Son los que se midieron con este plan, en
  esta máquina y contra esta API, el 2026-09-23.
