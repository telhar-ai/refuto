# Architecture Decision Records

| ADR | Decisión | Qué la haría cambiar |
|---|---|---|
| [0001](ADR-0001-protocolos-de-facto.md) | Adoptar MCP + ACP + `SKILL.md`, no inventar modelo canónico | que ACP se fragmente o lo retiren dos de los tres agentes que lo hablan |
| [0002](ADR-0002-solo-biblioteca-estandar.md) | Sólo biblioteca estándar de Python | necesitar criptografía de firma; sería dependencia opcional y su ausencia `BLOCKED` |
| [0003](ADR-0003-escalera-de-ejecutabilidad.md) | Cinco peldaños; `which` no es ninguno | que aparezca un handshake más barato que ACP `initialize` |
| [0004](ADR-0004-lock-antes-de-escribir.md) | Verificar antes de escribir; anclar por commit | nada razonable: la alternativa es una tautología |
| [0005](ADR-0005-cuatro-estados.md) | `PASS`/`FAIL`/`BLOCKED`/`NOT_EXECUTABLE` | ya está cambiando: faltan `NOT_RUN`, `INCONCLUSIVE` y `NOT_APPLICABLE`, que hoy se dicen todos con `BLOCKED` |
| [0006](ADR-0006-politica-unica-compilada.md) | Una política, N compilaciones, un guardián | que un runtime ofrezca aplicación de política verificable desde fuera |
| [0007](ADR-0007-puente-no-reescritura.md) | Envolver las puertas del verificador externo, no reescribirlas | que ese verificador deje de mantenerse, o que el contrato del puente pase a declararse en el manifiesto |
| [0008](ADR-0008-documentacion-generada.md) | Generar la matriz de compatibilidad | nada: una matriz escrita a mano miente en la dirección peligrosa |
| [0017](ADR-0017-ancla-certificada-por-consenso.md) | El ancla del diario la certifica un quórum de concordia; refuto la verifica solo (Ed25519 puro, pin de membresía de una persona) · **2026-09-27** | que refuto tenga un `uid` distinto del sujeto, o que exista vestigium |
| [0018](ADR-0018-el-motor-que-juzga-no-es-el-arbol-que-se-edita.md) | El motor que juzga es una copia publicada de un commit, no el árbol de trabajo; y cada decisión dice lo que costó y cómo acabó · **2026-09-28** | que el coste de arrancar un proceso por decisión obligue a un guardián residente |
| [0019](ADR-0019-discontinuidades-declaradas.md) | Una rotura de la cadena que una persona reconoce se declara —con su causa, su línea y sus digests— y la cadena queda `CICATRIZADA`, ni íntegra ni rota · **2026-09-28** | que el ancla aprenda a certificar tramos en vez de la cadena entera |
| [0020](ADR-0020-la-regla-habla-de-la-elevacion.md) | Pedir privilegio se rechaza por lo que la orden HACE, no por el nombre del binario; ceder privilegio no es pedirlo · **2026-09-29** | que el agente deje de correr con el uid del operador |

Todos están fechados el 2026-08-27 salvo donde se diga otra cosa. Un ADR no caduca solo: si una
decisión ya no describe el código, lo que corresponde es una revisión fechada dentro del propio
ADR —como la que lleva el 0005—, no borrarla.

## Decididos pero NO implementados

Estos cuatro son del 2026-09-22 y describen un **destino**, no el código de hoy. Se separan
por eso: un ADR que dice «aceptado» junto a otros que sí describen el árbol induce a creer que
lo que declaran existe. La columna de la derecha es medida, no recordada.

| ADR | Decisión | Implementación, medida el 2026-09-22 |
|---|---|---|
| [0009](ADR-0009-canonical-run-and-event-model.md) | Modelo canónico de corrida y eventos | **`NOT_RUN`** — 0 de 8 identificadores en el árbol (`CanonicalEvent`, `git_tree_hash`, `policy_hash`, `seq`, `ULID`…). El formato que declara (`run-AAAAMMDD-HHMMSS-hex`) no es el que emite `core/model.py::new_run_id` (`run_<hex16>`) |
| [0010](ADR-0010-evidence-graph-and-evaluation-plane.md) | Grafo de evidencia y plano de evaluación | **`NOT_RUN`** — 0 de 4 identificadores (`EvidenceGraph`, `evaluation_plane`…) |
| [0011](ADR-0011-trust-boundaries-and-flow-separation.md) | Fronteras de confianza y separación de flujos | **`NOT_RUN`** — 0 de 2 identificadores (`TrustBoundary`, `trust_boundary`) |
| [0012](ADR-0012-identidad-de-ejecucion.md) | Identidad tipada y correlación entre ejecuciones | **`NOT_RUN`** — refina 0009 con el diagnóstico medido: 4 acuñadores de `run_<hex16>`, 1 enlace de 6 posibles. Sus 5 pruebas están declaradas y ninguna existe |

Cómo se comprueba esta columna, y por qué se puede rehacer:

```sh
for t in CanonicalEvent git_tree_hash policy_hash EvidenceGraph TrustBoundary; do
  printf '%-18s %s\n' "$t" "$(grep -rl "$t" core adapters gates refuto.py tests schemas | wc -l)"
done
```

Mientras esa cuenta no cambie, ninguno de los cuatro puede declararse cumplido. Un ADR aceptado
es una decisión tomada; no es una propiedad del sistema.
