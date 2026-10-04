# G-SECURITY aprueba con la herramienta caída, y su `measure` dice que la usó

> Parche listo: [`g-security-herramienta-caida.patch`](g-security-herramienta-caida.patch).
> `gates/**` está protegido por la propia política —«un agente que edita lo que lo evalúa no
> está aprobando: está moviendo la puerta»— así que **lo aplica una persona**:
>
> ```sh
> git apply docs/remediation/g-security-herramienta-caida.patch
> ```
>
> Comprobado el 2026-09-25 con `git apply --check` sobre `69bcd6a`: aplica limpio.

## Lo medido

`gates/g_security.py` ejecutado sobre un espacio limpio de un fichero, con `trivy` instalado y
sin poder descargar su base de datos:

```
status   : PASS
measure  : 1 archivos recorridos · 0 hallazgos · herramientas: gitleaks, syft, trivy
obs      : gitleaks: 0 hallazgos
obs      : SBOM generado: 0 componentes
obs      : trivy presente y falló: … failed to download vulnerability DB: OCI ar…
```

El mismo estado se había medido ya el 2026-09-24 en un espacio real de 38 ficheros
(`ver_6484d1d7a1a148ce.json`). Sigue vivo 25 commits después.

## Tres defectos, y el tercero es el peor

**1 · «Presente y caída» no existe como caso.** El `THRESHOLD` declara *«herramienta ausente =
BLOCKED, nunca PASS»* y el código cumple exactamente eso: `blocked = True` está sólo en la rama
`else` de `shutil.which(...)`. Una herramienta instalada que revienta no escaneó nada, y aprueba
igual.

Que es un olvido y no un criterio lo demuestra el propio fichero: **`syft` sí lo hace bien**
(`syft presente y falló` → `blocked = True`). De las tres herramientas, una sigue el patrón
correcto y dos no. No hay una razón escrita para la diferencia.

**2 · Un SBOM de 0 componentes aprueba.** «0 componentes» no dice «no hay dependencias»: dice
que no se inventarió nada, y ante un CVE las dos cosas se responden distinto. `AGENTS.md`:
*«Un ámbito vacío nunca aprueba… una suite que ejecuta 0 pruebas falla»*.

**3 · `measure` afirma haber usado lo que no usó.** El campo se construye con
`shutil.which()` — por estar **instalada**, no por haber **funcionado**:

```python
f"herramientas: {', '.join(t for t in ('gitleaks','syft','trivy') if shutil.which(t))}"
```

Así que la evidencia que queda escrita en `.harness/evidence/` dice *«herramientas: gitleaks,
syft, trivy»* cuando trivy no produjo ni un resultado. Los otros dos defectos hacen que la
puerta apruebe sin mirar; **éste hace que la evidencia afirme que miró**. Quien audite dentro de
un año leerá el JSON, no la sesión — y el JSON miente sobre su propia cobertura.

## Lo que hace el parche

| # | cambio | efecto |
|---|---|---|
| 1 | `gitleaks presente y falló` → `blocked = True` | iguala a `syft`, que ya lo hacía |
| 2 | `trivy presente y falló` → `blocked = True` | ídem |
| 3 | SBOM con `n == 0` → `blocked = True` | ámbito vacío no aprueba |
| 4 | `measure` enumera `usadas`, no `which()` | la evidencia nombra sólo lo que produjo resultado |

Verificado ejecutando el módulo parcheado sobre el mismo espacio limpio, sin tocar `gates/`:

```
status : BLOCKED            (antes: PASS)
measure: 1 archivos recorridos · 0 hallazgos ·
         herramientas que produjeron resultado: gitleaks, syft
obs    : el SBOM no trae ni un componente: ámbito vacío, no inventario limpio. → BLOCKED, nunca PASS.
obs    : trivy presente y falló: … → BLOCKED.
```

## Qué NO arregla, y hay que decirlo

- **Los 18 falsos positivos del detector propio de secretos** sobre `core/digest.py`,
  `core/policy.py` y las pruebas que comprueban el detector. Son de `e28249c` (en `main`), no de
  este parche, y su arreglo es otro: `_scan_secrets` no debería marcar el código que ENUNCIA la
  regla. Mientras tanto `G-SECURITY` seguirá en `FAIL` por ese motivo, que es distinto de este.
- **Que `gitleaks detect` escanee el historial del repositorio PADRE** en un espacio anidado. Va
  aparte, en [`gitleaks-escanea-el-historial-del-padre.md`](gitleaks-escanea-el-historial-del-padre.md).

Después del parche, `G-SECURITY` pasará de `PASS` a `BLOCKED` en cualquier máquina sin trivy
operativo. **Eso es el arreglo, no una regresión**: hoy el verde no significa «no hay
vulnerabilidades», significa «nadie miró».
