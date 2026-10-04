# -*- coding: utf-8 -*-
"""H-03 · Política canónica. Se escribe una vez y se compila a cada runtime.

El hallazgo que motiva este módulo
----------------------------------
«Proteger al juez» estaba escrito dos veces, en dos vocabularios: `.kiro/hooks/*.json` con
`PreToolUse`/`fsWrite` (del IDE) y `hooks{}` de cada agente con `preToolUse`/`fs_write` (del
CLI). El guardián de rutas sólo estaba enganchado en el primero. Como el orquestador siempre
llama al CLI, **el control declarado nunca corría en la ruta que se usa**.

Una política escrita dos veces no es una política duplicada: es dos políticas, y divergen. Aquí
hay una fuente y N compilaciones, y cada compilación declara qué parte NO puede aplicar.

Las tres capas, y por qué hacen falta las tres
----------------------------------------------
1. **Compilada** al vocabulario del runtime (allow/deny de Claude, Policy Engine de Gemini,
   `allowedTools` de Kiro). Barata, la aplica el agente, y no ve el contenido.
2. **Guardián** (`core.guard`), un solo programa que todos los ganchos invocan. Ve el contenido
   y la ruta resuelta, así que atrapa lo que el patrón no ve: enlaces simbólicos, `..`,
   secretos dentro del texto.
3. **Fuera del alcance del agente**: rama protegida y CI. Es la única capa que el agente no
   puede tocar, y por eso las otras dos se declaran *preventivas*, no *garantías*.

Ninguna de las tres se presenta como suficiente. Declararlo es parte del control.
"""

from __future__ import annotations

import collections
import errno
import fnmatch
import json
import os
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

POLICY_SCHEMA = "harness.policy/v1"

#: El estado con el que `core.refinement.refinar` declara éxito. Se importa por nombre
#: propio para no arrastrar `core.model` entero a este módulo, del que depende el guardián.
PASS_REFINAMIENTO = "PASS"

#: Dónde vive la capa 1 de la cadena `refuto → cliente → proyecto`, relativa a la raíz del
#: espacio. Está protegida —y eso es deliberado, no un estorbo: materializar la norma raíz es un
#: acto de persona. Un agente que pudiera reescribir el documento del que cuelgan todos los
#: clientes no estaría gobernado por él.
#:
#: Se declara ANTES de `DEFAULT_PROTECTED` porque esa lista la DERIVA de aquí. Escribir el
#: nombre dos veces es justo cómo se llegó a proteger un árbol entero para cubrir un fichero.
RUTA_BASE = "policies/base.json"

#: Lo que un agente no puede escribir nunca, porque es lo que lo juzga o lo que prueba lo que
#: hizo. Un agente que puede editar su propia verificación no está pasando la verificación:
#: está moviendo la puerta.
#:
#: Estas rutas son GENÉRICAS a propósito, y ésa es una corrección. La lista llevaba
#: `.nucleo.lock.json` y `nucleo.json`: los ficheros de UN repositorio concreto que no se
#: publica. Fuera de él protegían el vacío, y una regla que no cubre nada se lee en el informe
#: de sesión —donde se enumeran una a una— como una protección que existe. `*.lock.json` ya
#: cubre cualquier lock, incluido aquél. Los nombres en español (`verificacion/`, `evidencia/`,
#: `insumos/`) se quedan porque son la palabra común, no el nombre de nadie; un espacio con
#: otra nomenclatura la declara en su `.harness/policy.json`, que se fusiona con ésta.
#:
#: Todas llevan el prefijo `**/`, y eso no es cosmético: sin él sólo cubrían la RAÍZ. Medido el
#: 2026-09-24 en un espacio multi-repo real, donde la raíz no es repositorio y cada hijo trae su
#: propio `.harness/`:
#:
#:     Write  .harness/bin/guard                     →  deny   («.harness/**»)
#:     Write  repo-hijo/.harness/bin/guard           →  ALLOW  ← el guardián del hijo, reescribible
#:
#: Es decir: desde la raíz se podía reescribir el guardián, la política y la evidencia de cada
#: repositorio hijo. El dueño de ese espacio lo detectó y añadió los `**/` a mano en su política;
#: que un espacio tenga que parchear la norma base para no tener un agujero significa que el
#: agujero era de la norma base. `**/x/**` cubre la raíz Y cualquier profundidad —lo garantiza
#: `_path_matches`, que para un patrón `**/…` prueba también sin el prefijo—, así que esto no
#: añade patrones: corrige el alcance de los que ya había.
#:
#: Por qué `policies/**` se acotó a un solo fichero (2026-10-03)
#: ------------------------------------------------------------
#: El patrón existía para cubrir `RUTA_BASE`, y cubría cualquier directorio llamado `policies/` a
#: cualquier profundidad. Medido en macOS 25.4 sobre un espacio limpio:
#:
#:     Write  security/policies/acceso.rego      →  deny  («**/policies/**»)
#:     Write  apps/web/policies/rate-limit.ts    →  deny  («**/policies/**»)
#:
#: esto es, el código del producto —reglas OPA, IAM, límites de tasa— quedaba fuera del alcance
#: del agente para proteger UN documento. Y el espacio **no podía arreglarlo**, medido el mismo
#: día sobre la misma política:
#:
#:     redeclarar `protected_paths` sin el patrón  →  deny: el efectivo es la UNIÓN (`ACUMULA`)
#:     declarar la excepción en `writable_paths`   →  HerenciaIrresoluble: el guardián deniega TODO
#:
#: Las dos direcciones del error no cuestan lo mismo. Una protección que SOBRA es irreparable
#: desde el espacio: `protected_paths` acumula, así que retirarla es inexpresable, y la excepción
#: que la compensaría es `REDUCE`, así que declararla rompe la cadena entera. Una protección que
#: FALTA la añade su dueño con una línea, porque añadir es la dirección que `ACUMULA` permite.
#: Ante la duda, el error reparable; el irreparable lo paga quien no escribió la norma.
#:
#: Un espacio que guarde más documentos de norma en `policies/` los declara él, y esa declaración
#: sí se propaga a sus hijos. Lo que se pierde a cambio es nombrado, no silencioso.
DEFAULT_PROTECTED = (
    "**/verification/**", "**/verificacion/**",
    "**/.kiro/steering/**", "**/.harness/**",
    "**/.claude/**", "**/.agents/**", "**/.kiro/**", "**/.codex/**",
    # Los runtimes que faltaban. La lista de arriba se escribió a mano y los runtimes que el
    # producto soporta son más. Medido el 2026-10-03 derivando los artefactos de
    # `compile_policy` de cada adaptador y pasándolos por `decide_write` con la política de
    # fábrica: 3 de 7 salían `allow`.
    #
    #     .gemini/hooks/harness-guard.json   allow  ← el fichero que INSTALA el guardián
    #     .aidlc/verification-bridge.json    allow  ← qué puertas exige cada etapa
    #     opencode.harness.json              allow  ← la política compilada de opencode
    #
    # Un agente que puede reescribir el gancho que lo vigila no está vigilado, y el primero de
    # los tres es exactamente ese fichero. Lo vigila ahora
    # `tests/selftest/test_artefactos_del_guardian.py`, que deriva la tabla de los adaptadores
    # en vez de repetirla: un adaptador nuevo que escriba donde no se protege deja la suite en
    # rojo. Repetir la lista a mano es lo que la hizo divergir.
    #
    # `.gemini/**` cubre además `.gemini/policies/harness.json`, que hasta hoy sólo estaba
    # protegido por accidente —coincidía con `policies/**`—. Acotar el patrón sin esto habría
    # convertido una protección incidental en un agujero.
    #
    # NO entran aquí `CLAUDE.md`, `AGENTS.md`, `.mcp.json` ni `opencode.json`: los adaptadores
    # los declaran como configuración del runtime, pero el arnés **no los escribe**. Son
    # ficheros que una persona edita y que el agente tiene motivo legítimo para tocar. El límite
    # se declara en vez de cerrarse: `opencode.json` es el que una persona fusiona a mano con
    # `opencode.harness.json` (`adapters/opencode.py`), así que proteger el artefacto no
    # demuestra que la política de opencode esté aplicada — el propio adaptador la declara
    # `unenforceable`, y sigue siéndolo.
    "**/.gemini/**", "**/.aidlc/**", "**/opencode.harness.json",
    "**/inputs/**", "**/insumos/**",
    "**/evidence/**", "**/evidencia/**",
    "**/gates/**",
    "**/*.lock.json",
    "**/harness.manifest.json", "**/harness.lock.json",
)

#: Artefactos de GOBIERNO, y la diferencia con `DEFAULT_PROTECTED` es el mecanismo, no la lista.
#:
#: Estos patrones NO se comparan contra la ruta relativa al espacio: se comparan contra la ruta
#: relativa a cada **raíz de autoridad** que contenga al objetivo. Una raíz de autoridad es un
#: directorio con `.harness/` dentro —la raíz de un espacio gobernado— y la del propio espacio
#: cuenta siempre, tenga `.harness/` o no.
#:
#: El defecto que obliga a añadir un mecanismo y no sólo a corregir datos
#: ----------------------------------------------------------------------
#: `protected_paths` tenía UN solo vocabulario: un glob sobre la ruta relativa al espacio. Por
#: ahí se estaban forzando dos semánticas que no son la misma:
#:
#:   (a) «este artefacto esté donde esté» — `.harness/`, `.claude/`: nombres que el arnés
#:       reserva, y que por eso se pueden globear con `**/` sin ambigüedad;
#:   (b) «el artefacto de gobierno de un espacio, en SU raíz» — `policies/`: una palabra común
#:       que el producto también usa para su propio código.
#:
#: Con sólo (a) disponible, la norma tenía que elegir entre dos errores, y los dos se midieron:
#:
#:     `**/policies/**`   →  de 61 directorios `policies/` clasificables en un espacio real,
#:                           **46 eran código fuente y 15 gobierno**: ~75 % de error, y el
#:                           espacio NO podía retirarlo (`protected_paths` acumula, y la
#:                           excepción que lo compensaría es `REDUCE`: declararla rompe la
#:                           cadena entera).
#:     `policies/**`      →  sólo cubría la raíz, así que el documento de norma de cada
#:                           repositorio hijo quedaba reescribible. Es el agujero del 2026-09-24.
#:
#: Ninguno de los dos es un problema de datos: los dos son el mismo patrón intentando decir algo
#: que su vocabulario no puede decir. De ahí este campo.
#:
#: Cómo resuelve las dos a la vez, medido el 2026-10-03
#: ---------------------------------------------------
#:     repo-hijo/policies/base.json                       deny   (raíz: repo-hijo)
#:     policies/reglas.rego                               deny   (raíz: el espacio)
#:     ai/…/src/kernel/mk/policies/x.rs                   allow  (ninguna raíz lo ancla)
#:     domain/governance/policies/x.yaml                  allow  (ninguna raíz lo ancla)
#:
#: Por qué se evalúa en TODAS las raíces que contienen al objetivo, y no sólo en la más cercana
#: --------------------------------------------------------------------------------------------
#: Con «la más cercana» el mecanismo se puede evadir plantando una raíz: si alguien crea
#: `policies/.harness/`, la raíz más cercana de `policies/base.json` pasa a ser `policies/`, la
#: ruta relativa queda en `base.json`, y `policies/**` deja de casar. Evaluar en todas las raíces
#: hace la evasión **inexpresable** en vez de improbable: añadir una raíz más profunda sólo puede
#: AÑADIR coincidencias, nunca quitarlas. Es monótono por construcción, que es la única clase de
#: control que no hay que defender caso por caso. La prueba que lo fija está en
#: `tests/adversarial/test_autoridad_por_raiz.py::test_plantar_una_raiz_no_desprotege`.
DEFAULT_AUTHORITY = (
    "policies/**",
)

#: Patrones que la norma RETIRÓ, con el motivo y la fecha. No es historia: es lo que
#: `refuto upgrade` necesita para nombrar el residuo.
#:
#: Una protección retirada del motor **no llega a un espacio ya instalado**, y por el mismo
#: mecanismo que hace que una protección nueva sí llegue: `init`/`install` copiaron la norma
#: entera, `protected_paths` es `ACUMULA` y el efectivo es la unión. El espacio sigue denegando
#: con el patrón viejo, su fichero lo declara, y nada le dice que la norma ya no lo pide.
#:
#: El residuo se MIDE y se nombra (`refuto._deriva_de_norma`); retirarlo es acto de persona,
#: porque `.harness/policy.json` está protegido. Igual que la deriva de la excepción: esta
#: herramienta no se arregla a sí misma el fichero que la gobierna.
RETIRADAS_DE_NORMA = {
    "policies/**": "acotado a `policies/base.json` el 2026-10-03: protegía el código del "
                   "producto (cualquier `policies/` a cualquier profundidad) para cubrir un "
                   "solo documento de norma, y el espacio no podía retirarlo.",
}

#: Excepciones DENTRO de lo protegido. Se comprueban ANTES que `protected_paths`.
#:
#: `.harness/**` protege la evidencia, la política y el estado — y con ellos arrastraba la
#: MEMORIA, que vive en `.harness/memory/` y cuyo contrato es el contrario. `core.memory` lo
#: dice en su primera línea: «memoria no es evidencia, y mezclarlas arruina las dos… la
#: política protege una y no la otra». No lo hacía: el mismo patrón cubría las dos, así que el
#: agente no podía recordar nada. Medido en un espacio real: `.harness/memory/` **no
#: existe** después de una semana de uso, porque toda escritura que lo habría creado se rechazó.
#:
#: Lleva `**/` por SIMETRÍA con `DEFAULT_PROTECTED`, y la simetría aquí es obligatoria, no
#: estética. `protected_paths` ACUMULA y `writable_paths` REDUCE (`core.refinement.REGLAS`): un
#: espacio puede añadir protección pero NO puede añadir la excepción que la acompaña —intentarlo
#: levanta `HerenciaIrresoluble` y el guardián deniega TODO—. Así que cada protección que cubra
#: más profundidad que su excepción produce una denegación colateral **irreparable desde el
#: espacio**. Medido el 2026-09-24, con `**/.harness/**` protegido y `.harness/memory/**`
#: exento:
#:
#:     Write  .harness/memory/nota.md            →  allow
#:     Write  repo-hijo/.harness/memory/nota.md  →  DENY  («**/.harness/**»)
#:
#: es decir: los repositorios hijos quedaban sin memoria, y su dueño no tenía forma legítima de
#: arreglarlo. La asimetría se corrige en la raíz porque es donde nació.
DEFAULT_WRITABLE = (
    "**/.harness/memory/**",
)

#: Raíces FUERA del espacio donde escribir SÍ es legítimo, declaradas una a una.
#:
#: `fuera-del-espacio` existe para atrapar travesía de directorios, y hace bien. Pero un agente
#: tiene dos sitios propios que por definición NO están en el espacio de trabajo: su memoria
#: persistente y su cuaderno de borrador de la sesión. Rechazarlos no impide ningún daño —no son
#: del proyecto— y sí impide justo lo que se le pide al agente: recordar entre sesiones y
#: calcular aparte sin ensuciar el árbol. Medido en un diario real: 39 rechazos por esta
#: regla, y los más repetidos son la memoria del propio agente y su cuaderno.
#:
#: Se declara por patrón y no con un «permite fuera del espacio»: la diferencia entre una
#: excepción nombrada y un agujero es que la excepción se puede leer y discutir.
DEFAULT_EXTERNAL_WRITE = (
    "~/.claude/projects/*/memory/**",     # la memoria persistente de Claude Code
    "/tmp/claude-*/**",                   # el cuaderno de la sesión
    "/private/tmp/claude-*/**",           # el mismo, como lo resuelve macOS
)

#: Rutas cuyo contenido nunca debe leerse, aunque el agente pida.
DEFAULT_SECRET_READ_DENY = (
    "**/.env", "**/.env.*", "**/secrets/**", "**/*.pem", "**/*.key",
    "**/id_rsa", "**/id_ed25519", "**/credentials", "**/.netrc",
    "**/auth.json", "**/.aws/credentials",
)

#: Nombres de variable de entorno con FORMA de credencial. Estructurales, nunca nombres de
#: producto ni de servicio.
#:
#: Se compara el NOMBRE y jamás el valor: mirar el valor de cada variable para decidir si es un
#: secreto obligaría a leer todos los secretos para protegerlos.
#:
#: Por qué estructurales y no una lista de servicios
#: -------------------------------------------------
#: La primera versión de esta tabla enumeraba once nombres concretos de productos y servicios. Se
#: retiraron por dos motivos, y el segundo es el que importa.
#:
#: 1. **Eran redundantes.** Comprobado uno a uno: los once ya los cubría un patrón de forma
#:    —`*_TOKEN`, `*_API_KEY`, `*_PASSWORD`…—, así que retirarlos no quita cobertura. Y el
#:    enfoque estructural alcanza además servicios que no existían al escribir esto, que es
#:    justo lo que una lista de nombres no puede hacer: envejece en cuanto alguien contrata un
#:    proveedor nuevo.
#: 2. **Una lista de servicios en un repositorio público dice de qué servicios hay credenciales.**
#:    No expone ningún valor y expone el mapa, que para alguien hostil es casi tan útil. En un
#:    producto de gobierno esa asimetría es inaceptable: el control estaría publicando parte de
#:    lo que existe para proteger.
#:
#: La misma regla vale para el ejemplo que se escriba en un comentario o en una prueba: se usa
#: una forma inventada (`MI_SERVICIO_API_KEY`), nunca la de un proveedor real y menos la que haya
#: en la máquina de quien lo escribió.
#:
#: Qué NO se marca, y es la mitad del trabajo
#: ------------------------------------------
#: Un sondeo con subcadenas sueltas (`SESSION|AUTH|KEY`) marcaba `SSH_AUTH_SOCK` —la ruta de un
#: socket, y retirarla rompe el agente de ssh—, identificadores de sesión de terminal y la propia
#: variable de refuto. Un detector que marca lo normal enseña a ignorarlo, y entonces deja de
#: proteger de lo que sí. Por eso se enumeran sufijos, no fragmentos.
#:
#: Medido sobre un entorno real de 70 variables: `*_KEY` no añade **ni un** falso positivo, así
#: que subsume a `*_API_KEY`, `*_SECRET_KEY`, `*_ACCESS_KEY` y `*_PRIVATE_KEY` sin coste.
DEFAULT_SECRET_ENV_DENY = (
    "*_KEY", "*KEY",
    "*_TOKEN", "TOKEN",
    "*_SECRET", "SECRET",
    "*_PASSWORD", "PASSWORD", "*_PASSWD", "*_PASSPHRASE",
    "*_CREDENTIAL", "*_CREDENTIALS", "CREDENTIALS",
)

#: Órdenes que nunca se ejecutan. Cada una corresponde a una forma de perder trabajo o datos.
#:
#: Los cuatro elevadores que acompañan a `sudo` se añadieron el 2026-09-29 tras medirlo: la
#: lista nombraba `sudo` y nada más, así que `doas id`, `su root -c id`, `sudoedit /etc/hosts` y
#: `pkexec` pasaban enteros. Nombrar sólo al más común deja el control en función de qué binario
#: tenga instalado la máquina, que no es una propiedad que nadie quisiera.
#:
#: `su:*` NO pone en rojo `su <usuario> -c …`: `decide_command` consulta `core.privilegio` y una
#: regla de elevación no se aplica a una CESIÓN de privilegio. Es la distinción que permite que
#: las 3.405 bajadas medidas sigan pasando mientras la elevación se para.
DEFAULT_COMMAND_DENY = (
    "rm -rf:*", "rm -fr:*", "rm -Rf:*", "rm --recursive --force:*",
    "sudo:*", "su:*", "doas:*", "sudoedit:*", "pkexec:*",
    "chmod -R 777:*", "dd:*", "mkfs:*",
    "git push --force:*", "git push -f:*",
    "curl* | sh", "curl* | bash", "wget* | sh", "wget* | bash",
    "git reset --hard:*", "git clean -fdx:*",
    ":()*",
)

#: Órdenes que requieren confirmación humana: salen del repositorio o cambian algo remoto.
DEFAULT_COMMAND_ASK = (
    "git push:*", "gh pr:*", "glab mr:*", "npm publish:*",
    "docker push:*", "kubectl apply:*", "terraform apply:*", "aws *:*",
)


class PoliticaIlegible(ValueError):
    """El documento de política no es de este motor.

    Se distingue de «falta la política», que es un aviso y se resuelve con los valores por
    omisión, y de «la política está mal formada», que es un error de JSON. Esto es otra cosa:
    un documento bien formado, lleno, y de otro contrato. Tratarlo como ausente sería aplicar
    una política que nadie escribió mientras la escrita se ignora.
    """


class HerenciaIrresoluble(PoliticaIlegible):
    """No se pudo construir la política efectiva a partir de `extends`.

    Subclase a propósito: el guardián ya captura `PoliticaIlegible` y **deniega**. Heredar de
    ella hace que un fallo de herencia falle CERRADO sin tocar una línea del guardián, que es
    el sitio donde un `except` nuevo y mal puesto costaría más caro.

    Las tres razones se distinguen en el mensaje, no en el estado: quien lo recibe necesita
    saber cuál es, pero para el motor las tres significan lo mismo — no se puede afirmar cuál
    es la política, luego no se deja pasar nada.
    """


@dataclass
class Policy:
    """La política canónica. Un documento, N compilaciones."""

    schema: str = POLICY_SCHEMA
    version: str = "1"
    protected_paths: tuple = DEFAULT_PROTECTED
    #: Lo mismo que `protected_paths` pero anclado a cada RAÍZ DE AUTORIDAD que contenga al
    #: objetivo, no a la raíz del espacio. Ver `DEFAULT_AUTHORITY`: es un mecanismo distinto,
    #: no una segunda lista de lo mismo.
    authority_paths: tuple = DEFAULT_AUTHORITY
    #: Se comprueba ANTES que `protected_paths`: es la excepción, y una excepción que se
    #: evaluara después nunca ganaría.
    writable_paths: tuple = DEFAULT_WRITABLE
    #: Lo único escribible fuera del espacio. Vacío significa: nada.
    external_write_allow: tuple = DEFAULT_EXTERNAL_WRITE
    secret_read_deny: tuple = DEFAULT_SECRET_READ_DENY
    #: Nombres de variable de entorno con forma de credencial. Se consultan en el MISMO canal
    #: de lectura que `secret_read_deny`: `printenv X` y `cat .env` son la misma pregunta por
    #: dos caminos, y tratarlas distinto es cómo se queda uno de los dos sin mirar.
    secret_env_deny: tuple = DEFAULT_SECRET_ENV_DENY
    command_deny: tuple = DEFAULT_COMMAND_DENY
    command_ask: tuple = DEFAULT_COMMAND_ASK
    #: Bloquea la escritura si el contenido contiene un secreto reconocible.
    block_secret_content: bool = True
    #: Reglas de red. Hoy vacío: ninguno de los cinco runtimes ofrece allowlist de dominios
    #: verificada, y declarar una regla que no se aplica es peor que no tenerla.
    network_rules: tuple = ()
    #: Excepciones NOMBRADAS en el canal de órdenes: qué rol puede elevar privilegio, para qué
    #: forma de orden, en qué host, con qué efectos verificados y hasta cuándo.
    #:
    #: Es el análogo de `writable_paths` en el canal de órdenes, y se construye igual a propósito:
    #: se evalúa ANTES de `command_deny` —una excepción evaluada después nunca ganaría— y su
    #: monotonía es `REDUCE`, porque abre un agujero y por tanto el hijo sólo puede cerrarlo.
    #:
    #: Lo que impide que sea un agujero: vive en `.harness/policy.json`, que esta misma política
    #: protege, así que **un agente no puede concederse privilegio a sí mismo**. Ver
    #: `core/grants.py`, que explica las cinco propiedades y lo que no demuestra.
    privilege_grants: tuple = ()
    #: Restricciones EXTRA por rol, sobre las que ya declara `roles/registry.json`.
    #:
    #: El registro es la fuente canónica —un rol es lo que su contrato dice que es— y esto sólo
    #: APRIETA: el efectivo es la unión (`core.capabilities.capacidades_de`). Un espacio que
    #: quiera que su `backend-engineer` tampoco use la shell lo declara aquí; uno que quiera lo
    #: contrario **no tiene sintaxis para decirlo**, y ése es el punto — no poder expresar la
    #: relajación es más fuerte que detectarla, igual que en `protected_paths`.
    #:
    #: Los nombres válidos son los de `core.capabilities.CONOCIDAS`. Uno inventado no se ignora
    #: en silencio: `G-CAPABILITY` lo pone en rojo, porque una capacidad que nadie aplica es
    #: exactamente el defecto que ese gate existe para impedir.
    role_capabilities: dict = field(default_factory=dict)
    #: Modo por defecto por runtime. No se homogeneiza: cada uno tiene su vocabulario.
    default_modes: dict = field(default_factory=lambda: {
        "claude": "acceptEdits", "kiro": "declared-in-agent", "gemini": "default",
        "opencode": "ask", "codex": "unknown",
    })

    # ── consultas ────────────────────────────────────────────────────────────────────
    def is_protected(self, rel_path: str) -> str:
        """Devuelve el patrón que protege esa ruta, o cadena vacía."""
        norm = _normalize(rel_path)
        for pattern in self.protected_paths:
            if _path_matches(norm, pattern):
                return pattern
        return ""

    def is_authority(self, rel_path: str, raices=()) -> tuple:
        """`(patrón, raíz)` si la ruta es un artefacto de gobierno, o `("", "")`.

        `raices` son los prefijos relativos al espacio de cada raíz de autoridad que CONTIENE al
        objetivo, de la más externa a la más interna; `""` es la raíz del espacio. Las calcula
        `raices_de_autoridad`, que mira el sistema de archivos; esta función es pura para que se
        pueda probar sin montar un árbol.

        Se recorren TODAS, no la más cercana: ver `DEFAULT_AUTHORITY`. Se devuelve la primera
        coincidencia empezando por la más externa, porque es la autoridad más alta y es la que
        hay que citar en el motivo.
        """
        norm = _normalize(rel_path)
        for raiz in (raices or ("",)):
            raiz = _normalize(raiz)
            if raiz:
                if not (norm == raiz or norm.startswith(raiz + "/")):
                    continue
                dentro = norm[len(raiz) + 1:]
            else:
                dentro = norm
            if not dentro:
                continue
            for pattern in self.authority_paths:
                if _path_matches(dentro, pattern):
                    return pattern, raiz
        return "", ""

    def is_writable(self, rel_path: str) -> str:
        """El patrón de excepción que libera esa ruta, o cadena vacía."""
        norm = _normalize(rel_path)
        for pattern in self.writable_paths:
            if _path_matches(norm, pattern):
                return pattern
        return ""

    def external_allows(self, absolute: Path) -> str:
        """El patrón que autoriza esa ruta ABSOLUTA fuera del espacio, o cadena vacía.

        Se compara contra la ruta ya resuelta, igual que todo lo demás: una excepción que se
        pudiera alcanzar con un enlace simbólico no sería una excepción, sería la puerta.
        """
        target = str(absolute)
        for pattern in self.external_write_allow:
            pat = os.path.expanduser(pattern)
            if fnmatch.fnmatch(target, pat):
                return pattern
            # `raiz/**` cubre además la raíz misma, que `fnmatch` no da por incluida.
            #
            # La comparación literal no bastaba cuando la raíz lleva comodín. Con
            # `/tmp/claude-*/**` el prefijo es `/tmp/claude-*`, y `target == prefijo` no casa
            # nunca contra `/tmp/claude-abc`: el patrón se quedaba cubriendo el CONTENIDO del
            # cuaderno del agente y no el cuaderno. Sin analizar efectos de órdenes el defecto
            # era invisible —`mkdir` no se miraba—; con `core.effects` mirando, `mkdir` sobre
            # la raíz declarada empezó a denegarse. Se compara también por patrón.
            if pat.endswith("/**"):
                raiz = pat[:-3]
                if fnmatch.fnmatch(target, raiz) or target == raiz \
                        or target.startswith(raiz + "/"):
                    return pattern
        return ""

    def is_secret_env(self, nombre: str) -> str:
        """El patrón que marca ese NOMBRE de variable como credencial, o cadena vacía.

        Sin normalizar la ruta —no es una ruta— y sin mirar el valor. La comparación es
        insensible a mayúsculas porque un entorno real mezcla `MI_SERVICIO_TOKEN` y `mi_servicio_token`,
        y un control que distingue por capitalización no controla nada.
        """
        n = (nombre or "").strip().upper()
        if not n:
            return ""
        for pattern in self.secret_env_deny:
            if fnmatch.fnmatch(n, pattern.upper()):
                return pattern
        return ""

    def is_secret_path(self, rel_path: str) -> str:
        norm = _normalize(rel_path)
        for pattern in self.secret_read_deny:
            if _path_matches(norm, pattern):
                return pattern
        return ""

    def default_mode_for(self, runtime: str) -> str:
        return self.default_modes.get(runtime, "default")

    # ── serialización ────────────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        d = asdict(self)
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in d.items()}

    @classmethod
    def from_dict(cls, doc: dict) -> "Policy":
        """La política del documento. Levanta `PoliticaIlegible` si no reconoce NADA.

        El defecto que esto cierra
        --------------------------
        Las claves desconocidas se descartan y las ausentes toman su valor por omisión. Es
        tolerante, y esa tolerancia es correcta para un documento al que le falta un campo.
        Pero un documento del que no se reconoce NI UNA clave producía `Policy()` — es decir,
        exactamente `Policy.default()`, indistinguible de no tener política.

        Medido en un espacio real: su `.harness/policy.json` declaraba nueve secciones de otro
        contrato entero (`client_identifiers`, `pii_patterns`, `credential_shapes`,
        `boundary`…) porque ese fichero lo escribía OTRO programa que reclama la misma ruta. El
        guardián no falló: aplicó los valores de fábrica y siguió. El espacio parecía
        gobernado y lo gobernaba una política que nadie había escrito — y las secciones que sí
        se habían escrito, incluidas las dos que detectan credenciales y datos personales, no
        se aplicaban nunca.

        Un documento vacío `{}` SÍ es válido: dice «acepto lo que venga por omisión», y lo dice
        a propósito. Lo que no puede pasar en silencio es un documento lleno del que no se
        entiende una palabra.
        """
        known = {f for f in cls.__dataclass_fields__}                # noqa: SLF001
        kwargs = {}
        for key, value in doc.items():
            if key not in known:
                continue
            kwargs[key] = tuple(value) if isinstance(value, list) else value

        # `schema` y `version` son METADATOS: los lleva cualquier documento, incluido el de
        # otro programa, así que reconocerlos no es reconocer una política. Contarlos salvaba
        # justo al documento que este control existe para cazar.
        #
        # `extends` SÍ cuenta, y es lo contrario de un metadato: es una declaración
        # sustantiva —«mi política es la de mi padre, con lo que yo añada»— y un documento
        # ajeno no la lleva. Sin esto, un hijo que hereda TODO y no repite nada se rechazaba
        # como documento de otro programa; medido el 2026-09-23 contra el guardián real, que
        # denegaba con el motivo equivocado. `name` acompaña a `extends` en la identidad y no
        # cuenta por sí solo, como `schema`.
        sustantivas = set(kwargs) - {"schema", "version"}
        if doc.get("extends"):
            sustantivas.add("extends")
        # Un documento que declara NUESTRO esquema y nada que no reconozcamos es nuestro, y si
        # no declara más es porque acepta la norma base entera — exactamente lo que significa
        # `{}`, que este mismo método considera válido. Rechazarlo era un defecto medido el
        # 2026-09-24: `{"schema": "harness.policy/v1", "name": "x", "version": "1"}` —la forma
        # mínima y natural de decir «acepto lo que venga»— no cargaba, y el guardián denegaba
        # todo con el motivo equivocado, hablando de «la política de OTRO programa» y
        # enumerando cero campos ajenos.
        #
        # No reabre lo que este control cierra. El caso real que lo motivó era un fichero con
        # nueve secciones de otro contrato (`client_identifiers`, `pii_patterns`…), y ésas SÍ
        # son claves ajenas: con una sola presente la excepción no aplica y se sigue levantando.
        # Lo que se exige es lo que se puede demostrar: esquema nuestro Y nada extraño.
        ajenas_presentes = [k for k in doc if not k.startswith("_") and k not in
                            ("schema", "version", "name", "extends", "extends_digest")
                            and k not in cls.__dataclass_fields__]   # noqa: SLF001
        if doc.get("schema") == POLICY_SCHEMA and not ajenas_presentes:
            return cls(**kwargs)
        if doc and not sustantivas:
            ajenas = sorted(k for k in doc if not k.startswith("_") and k not in
                            ("schema", "version", "name", "extends_digest"))
            raise PoliticaIlegible(
                f"el documento declara {len(ajenas)} campos de política y el motor no reconoce "
                f"ninguno: "
                f"{', '.join(ajenas[:6])}"
                f"{'…' if len(ajenas) > 6 else ''}. "
                f"Parece la política de OTRO programa ocupando esta ruta. "
                f"No se aplican valores por omisión: una política que no se entiende no "
                f"aprueba.")
        return cls(**kwargs)

    @classmethod
    def load(cls, path: Path) -> "Policy":
        """La política EFECTIVA de ese fichero, con `extends` ya resuelto.

        Por qué la resolución vive aquí y no en un comando aparte
        ---------------------------------------------------------
        `Policy.load` es lo que ejecuta el guardián (`core/guard.py`) antes de decidir cada
        escritura y cada orden. Si `extends` se resolviera sólo en un comando de consulta, un
        cliente podría declarar restricciones que **ningún proyecto aplica** mientras la
        herramienta informa de que la herencia está bien.

        No es hipotético: medido el 2026-09-23 contra el guardián real, con un padre que
        denegaba una orden y un hijo que declaraba `extends` sin repetirla:

            permissionDecision: "allow"      ← la orden del cliente se permitía

        Dos interpretaciones de la misma política son dos políticas. Aquí hay una.

        Qué pasa cuando no se puede resolver
        ------------------------------------
        Se levanta `PoliticaIlegible` —o una de sus subclases— y el guardián la trata como ya
        trataba cualquier política que no entiende: **deniega**. No hay valores por omisión,
        no hay política del hijo a secas, no hay `NOT_APPLICABLE`. Un espacio que dice heredar
        y corre sin su padre parece gobernado sin estarlo, y ése es el estado que no puede
        existir.
        """
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not doc.get("extends"):
            # Sin `extends` la cima de la cadena es este documento, y hasta el 2026-09-23
            # nadie vigilaba lo que la cima retiraba: un `.harness/policy.json` con
            # `protected_paths: []` dejaba el espacio sin protecciones y la herramienta no
            # tenía nada que objetar. Ahora TODA política se compone con la raíz del motor,
            # que es su padre implícito. En los campos que acumulan, vaciar deja de ser una
            # violación detectable para volverse INEXPRESABLE: el efectivo es la unión.
            # Ver `core/trust.py` y FORMAL-MODEL §3.2.
            from core.trust import componer_con_raiz

            r = componer_con_raiz(doc)
            if r.status != PASS_REFINAMIENTO:
                raise HerenciaIrresoluble(
                    f"«{path.name}» no atenúa la norma base de refuto: {r.motivo} "
                    f"{' | '.join(r.violaciones)}")
            pol = r.politica
            # También sin herencia lleva identidad: si sólo la llevaran las heredadas, la
            # evidencia podría citar la política en unos espacios y no en otros, y «no hay
            # digest» sería indistinguible de «no se pudo calcular».
            from core.refinement import identidad_de
            pol.identidad_efectiva = identidad_de(doc)
            return pol
        # Tardío a propósito: `refinement` importa de este módulo. Importar aquí evita el
        # ciclo sin partir ninguno de los dos en un tercero artificial.
        from core.refinement import politica_efectiva
        return politica_efectiva(path, doc)

    @classmethod
    def default(cls) -> "Policy":
        return cls()


def documento_base(nombre: str = "refuto") -> dict:
    """El documento de la capa `refuto`: los valores por omisión, materializados.

    Hasta ahora esta capa sólo existía como constantes de este módulo (`DEFAULT_PROTECTED`,
    `DEFAULT_COMMAND_DENY`…), así que ningún cliente podía extenderla: `refuto install`
    escribía una COPIA completa en cada espacio y a partir de ahí divergían en silencio. Un
    documento se puede heredar; una constante de Python, no.

    Se deriva de `Policy.default()` y no se escribe a mano a propósito: dos fuentes para la
    misma norma se separan, y la que se separa sin avisar es siempre la que nadie ejecuta.
    """
    return {**Policy.default().to_dict(), "name": nombre}


# ── decisión ─────────────────────────────────────────────────────────────────────────
def _normalize(rel_path: str) -> str:
    """Normaliza una ruta relativa para compararla contra patrones.

    NO se usa `lstrip("./")`: `str.lstrip` quita CARACTERES, no un prefijo, así que
    `.kiro/steering/metodo.md` se convertía en `kiro/steering/metodo.md` y dejaba de coincidir
    con `.kiro/steering/**`. El estándar quedaba desprotegido por un punto. Encontrado por la
    prueba `tests/unit/test_policy.py::protege_steering`.
    """
    norm = rel_path.replace(os.sep, "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm.lstrip("/")


def _path_matches(norm: str, pattern: str) -> bool:
    """Coincidencia de ruta contra patrón, con las dos correcciones que `fnmatch` no trae.

    1. `dir/**` cubre `dir/a.py` y `dir/a/b.py`. `fnmatch` solo no lo garantiza.
    2. `**/.env` cubre también `.env` en la raíz. Sin esto, el patrón que todo el mundo
       escribe para «los .env, estén donde estén» dejaba fuera el más obvio: el de arriba.
    """
    if fnmatch.fnmatch(norm, pattern):
        return True
    if pattern.endswith("/**"):
        base = pattern[:-3]
        if norm == base or norm.startswith(base + "/"):
            return True
        if base.startswith("**/"):
            root_base = base[3:]
            if norm == root_base or norm.startswith(root_base + "/"):
                return True
    if pattern.startswith("**/"):
        rest = pattern[3:]
        if fnmatch.fnmatch(norm, rest):
            return True
        if rest.endswith("/**"):
            root_base = rest[:-3]
            if norm == root_base or norm.startswith(root_base + "/"):
                return True
    return False


#: Qué convierte un directorio en raíz de autoridad. Es el directorio del arnés: donde viven la
#: política, la evidencia y el estado de un espacio gobernado. No se exige que haya
#: `policy.json` legible dentro, a propósito: un `.harness/` a medias sigue siendo la raíz de un
#: espacio —y si la condición fuera «con política válida», romper la política de un hijo
#: desactivaría la protección de su documento de norma, que es lo contrario de lo que hace falta.
MARCADOR_DE_AUTORIDAD = ".harness"


def raices_de_autoridad(workspace: Path, resolved: Path) -> tuple:
    """Prefijos relativos de cada raíz de autoridad que contiene a `resolved`, de fuera a dentro.

    La raíz del espacio va SIEMPRE, con prefijo `""`, tenga `.harness/` o no: un espacio sin
    instalar sigue estando gobernado por la raíz del motor, y si no se anclara ahí los patrones
    de autoridad no se aplicarían en el único sitio donde hoy se aplican todos.

    Se recorre desde la raíz del espacio hacia el objetivo y NO al contrario: así el orden de
    salida es de autoridad más alta a más baja, que es el orden en que hay que citarlas.

    Mira el sistema de archivos, así que es la frontera impura del mecanismo. Lo que compara es
    la ruta YA RESUELTA (`os.path.realpath`), por lo que un enlace simbólico no puede fabricar
    una raíz que no esté donde el sistema de archivos dice.
    """
    try:
        rel = resolved.relative_to(workspace)
    except ValueError:
        return ("",)
    raices = [""]
    actual = workspace
    # `rel.parts[:-1]`: los ANCESTROS. El propio objetivo no puede ser su raíz de autoridad —si
    # lo fuera, `repo/.harness` se anclaría en sí mismo y la ruta relativa quedaría vacía.
    for parte in rel.parts[:-1]:
        actual = actual / parte
        if (actual / MARCADOR_DE_AUTORIDAD).is_dir():
            raices.append(str(actual.relative_to(workspace)).replace(os.sep, "/"))
    return tuple(raices)


ALLOW, DENY, ASK = "allow", "deny", "ask"


@dataclass
class Decision:
    outcome: str
    reason: str = ""
    rule: str = ""
    #: `True` cuando la orden invoca algo cuyo efecto no se deriva de sus argumentos
    #: (`python3 -c`, `make`, un binario propio). NO significa «peligrosa»: significa que
    #: `Ê` no pudo demostrar qué toca. Viaja hasta el diario para que la atestación de
    #: `core.trust` sepa que hubo una ventana sin demostrar. Ver FORMAL-MODEL §6.
    opaco: bool = False
    motivo_opaco: str = ""
    #: Las escrituras que `Ê` SÍ demostró, para poder auditarlas después.
    escrituras: tuple = ()
    #: En cuál de los cinco estados quedó la derivación del efecto:
    #: `SIN_SUJETO` · `RESUELTO` · `DESCONOCIDO` · `NO_RESOLUBLE` · `AMBIGUO`.
    #: `opaco` es su proyección a un booleano y se conserva por compatibilidad con el esquema
    #: del diario; el estado es lo que permite distinguir «no lo sé» de «creí saberlo».
    resolucion: str = ""
    #: Destinos de escritura VISTOS y no resueltos a una ruta (`$D`, `${V:-x}`). Estar aquí y
    #: no en `escrituras` es la diferencia entre «hay una escritura a destino desconocido» y
    #: «se escribe en un fichero llamado `$D`», que es lo que se afirmaba antes.
    sin_resolver: tuple = ()
    #: IDENTIDAD DEL OBJETO en el instante de decidir: `{estado, dev, ino, tipo, nlink}`.
    #: Sólo la traen las decisiones sobre rutas. No impide que el objeto se sustituya después
    #: —refuto decide y devuelve; quien abre el fichero es otro proceso— pero sin esto la
    #: pregunta «¿lo autorizado en T1 es lo tocado en T5?» no tenía con qué responderse.
    objeto: dict = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.outcome == DENY


def _sale_del_espacio(ws: Path, destino: str) -> bool:
    """¿Esa escritura aterriza fuera del espacio de trabajo?

    Se resuelve antes de comparar, igual que en `decide_write`: un enlace simbólico dentro del
    árbol que apunta afuera sale igual, y preguntarlo sobre la cadena tal como la escribió el
    agente sería preguntarlo sobre la intención en vez de sobre el efecto.
    """
    try:
        clean = str(destino).replace("\\", "/")
        raw = Path(clean).expanduser()
        absoluta = raw if raw.is_absolute() else (ws / raw)
        Path(os.path.realpath(absoluta)).relative_to(ws.resolve())
        return False
    except (ValueError, OSError):
        return True


#: Órdenes que vuelcan el entorno ENTERO, sin nombrar ninguna variable. Se enumeran a mano
#: porque no hay forma de derivarlo: `env` sin argumentos no tiene argumento que analizar.
#:
#: `env VAR=x orden` NO vuelca nada —usa `env` como envoltorio— y por eso se exige que la orden
#: no lleve más que banderas. Marcarla sería marcar la mitad de los lanzamientos con entorno
#: ajustado, y un detector que marca lo normal enseña a ignorarlo.
_VUELCA_ENTORNO = {"env", "printenv", "set", "export", "declare"}


def _vuelca_el_entorno(orden: str) -> bool:
    """¿Alguno de los segmentos de la orden imprime el entorno completo?"""
    for seg in _segmentos(orden or ""):
        t = seg.split()
        if not t or t[0] not in _VUELCA_ENTORNO:
            continue
        resto = []
        for x in t[1:]:
            # La redirección y sus destinos no son argumentos de `env`: son de la shell. Sin
            # cortar aquí, `env > /tmp/claude-x/todo` no se veía como volcado —`>` no empieza por
            # `-`— y salía `allow`, que es exactamente el volcado del entorno entero a un fichero
            # que la política abre. La vía más fácil de todas, y la última en cerrarse.
            if x in (">", ">>", "|", "2>", "&>", "1>") or x.startswith(">"):
                break
            if x != "-":
                resto.append(x)
        # Sólo banderas (`printenv -0`, `declare -p`) sigue siendo un volcado; un nombre de
        # variable o una asignación, no: eso ya lo cubre la comparación por nombre.
        if all(x.startswith("-") for x in resto):
            return True
    return False


def _lecturas_secretas(policy: Policy, ws: Path, lecturas, orden_cruda: str = "") -> list:
    """Las lecturas de la orden que exponen una ruta de credencial: `[(ruta, patrón)]`.

    Dos niveles, y el segundo es donde está el matiz
    ------------------------------------------------
    1. **Coincidencia directa.** La lectura casa con un patrón de `secret_read_deny`. Cubre
       `cat .env`, `head secrets/clave.pem`, `cp ~/.aws/credentials …`.
    2. **Lectura de directorio.** `grep -rn AKIA .` no lee `.env`: lee `.`, y ningún patrón de
       ruta casa con `.`. Medido el 2026-09-25:

           grep -rn AKIA .  →  lecturas={'.', 'AKIA'}  ·  is_secret_path('.') = False

       Así que se mira si ese directorio CONTIENE, en su primer nivel, un fichero que case. Un
       nivel y no recursivo a propósito: recorrer el árbol entero en cada decisión del guardián
       lo volvería lento justo en el camino caliente, y un control lento se desactiva.

    Lo que esta función NO cubre, y se declara en vez de fingirse
    -------------------------------------------------------------
    - Una credencial ANIDADA bajo un directorio que se lee recursivamente (`sub/dir/.env` con
      `grep -r .`) no se detecta. Es incompleta, como `Ê ⊆ Effects`.
    - `tar czf t.tgz .` sale `opaco` del modelo de efectos: no declara lecturas, así que aquí no
      hay nada que mirar. La decisión llevará `opaco=True` y el diario lo registra.
    - Una credencial en el ENTORNO (`printenv MI_SERVICIO_API_KEY`) no es una ruta y no la ve
      esto. Hoy el agente hereda `os.environ` completo (`core/session.py`), así que el entorno es
      el hueco grande que queda — y es otra capa, no un olvido de ésta.

    Incompleta y sólida: lo que afirma, lo afirma. Ante la duda no inventa una coincidencia.
    """
    fuera = []
    # Un volcado del entorno ENTERO. `printenv MI_SERVICIO_API_KEY` se atrapa por el nombre, y `env` a
    # secas no declara ninguna lectura —medido: `efectos("env").lecturas == set()`— porque no hay
    # argumento que derivar. Es la vía más fácil de las dos, así que cerrar sólo la nombrada
    # habría sido cerrar la puerta y dejar la ventana.
    #
    # Se mira si el entorno de ESTA sesión tiene de verdad alguna variable con forma de
    # credencial. En una máquina sin ninguna, `env` es inofensivo y preguntarlo sería ruido — y
    # un control ruidoso se desactiva. Medido el 2026-09-25 en una sesión real: 70 variables, 7
    # credenciales.
    if _vuelca_el_entorno(orden_cruda):
        expuestas = sorted(n for n in os.environ if policy.is_secret_env(n))
        if expuestas:
            fuera.append((f"el entorno entero ({len(expuestas)} variables con forma de "
                          f"credencial: {', '.join(expuestas[:4])}"
                          f"{'…' if len(expuestas) > 4 else ''})",
                          "secret_env_deny"))
    for lectura in sorted(lecturas or ()):
        if not lectura or lectura in ("-", "*"):
            continue
        patron = policy.is_secret_path(lectura)
        if patron:
            fuera.append((lectura, patron))
            continue
        # Una variable de ENTORNO con forma de credencial. `printenv MI_SERVICIO_API_KEY` y
        # `cat .env` son la misma pregunta por dos caminos, y tratarlas distinto es cómo se
        # queda uno de los dos sin mirar. Medido el 2026-09-25 en una sesión real: 70 variables
        # y 7 credenciales de verdad, todas legibles, mientras `.env` estaba protegido.
        #
        # Se compara el NOMBRE. Mirar el valor para decidir si es un secreto obligaría a leer
        # todos los secretos para protegerlos.
        patron_env = policy.is_secret_env(lectura)
        if patron_env:
            fuera.append((f"${lectura}", patron_env))
            continue
        # Nivel 2: ¿es un directorio cuyo contenido inmediato incluye una credencial?
        try:
            raw = Path(lectura).expanduser()
            base = raw if raw.is_absolute() else (ws / raw)
            if not base.is_dir():
                continue
            for hijo in sorted(base.iterdir()):
                try:
                    rel = str(hijo.resolve().relative_to(ws.resolve()))
                except ValueError:
                    rel = hijo.name
                p2 = policy.is_secret_path(rel) or policy.is_secret_path(hijo.name)
                if p2:
                    fuera.append((f"{lectura} (contiene {hijo.name})", p2))
                    break
        except (OSError, ValueError):
            continue        # no se pudo mirar: no se inventa una coincidencia
    return fuera


def _motivo_protegida(rel: str, pattern: str, existe: bool) -> str:
    """Por qué se deniega, y son DOS cosas distintas que se respondían con un solo mensaje.

    Modificar el juez y colisionar con su NOMBRE no son el mismo acto. El mensaje único decía
    «un agente que edita lo que lo evalúa está moviendo la puerta» — verdad cuando el fichero
    existe y el agente lo reescribe; acusación falsa y, peor, consejo inútil cuando el agente
    está creando un fichero nuevo que sólo cae dentro de un nombre reservado.

    De lo segundo hay caso medido, el 2026-09-24. Un espacio cuyo ENTREGABLE era un dossier de
    auditoría llamado `evidence/` —la misma palabra que refuto reserva para el diario que lo
    juzga, contrato opuesto— produjo esto: el agente leyó en su informe de sesión que
    `**/evidence/**` estaba protegido y que `/tmp/claude-*/**` era escribible, y se llevó el
    trabajo a `/tmp`. 9,2 GB, 6 dossiers, 197 ficheros, fuera de git y en un directorio que
    `/usr/libexec/tmp_cleaner` borra a los 3 días. Nunca intentó escribir dentro del espacio:
    no hubo ninguna denegación que lo empujara, sólo un nombre reservado y ninguna indicación
    de que renombrar era la salida. El espacio estaba escribible en todo lo demás.

    Un control que deniega sin nombrar la alternativa no protege: desvía. Y adonde desvía no lo
    elige quien escribió la regla.
    """
    if existe:
        return (f"«{rel}» está protegida por «{pattern}». Es el estándar, el juez, el insumo "
                f"del cliente o la evidencia. Un agente que edita lo que lo evalúa no está "
                f"aprobando: está moviendo la puerta. El cambio se propone, no se aplica.")
    reservado = pattern.removeprefix("**/").split("/", 1)[0].rstrip("*").rstrip("/")
    return (f"«{rel}» no existe todavía, así que esto no es editar el juez: es CREAR algo "
            f"dentro de un nombre reservado. «{reservado or pattern}» le pertenece a lo que "
            f"evalúa tu trabajo —la evidencia, las puertas, la política, el insumo del "
            f"cliente—, y el nombre está reservado incluso donde aún no hay nada, para que "
            f"nadie lo ocupe. Si esto es producto TUYO, no hay que abrir la regla: hay que "
            f"cambiarle el nombre al destino. Escríbelo en un directorio que no esté "
            f"reservado —`dossier/`, `auditorias/`, `informes/`— y se permite sin tocar la "
            f"política. No lo saques a `/tmp`: ahí no está en git y el sistema lo borra.")


#: Estado de la IDENTIDAD DEL OBJETO en el instante de decidir.
#:
#:     EXISTE         el objeto está: se atestigua su `(dev, ino, tipo, nlink)`
#:     AUSENTE        no está, y su directorio padre sí: se atestigua el PADRE, que es lo que
#:                    determina dónde aterrizará la escritura
#:     SIN_PADRE      ni el objeto ni su padre existen: no hay nada que atestiguar
#:     INDETERMINADO  no se pudo mirar (permisos, carrera). No es «no está»
#:
#: La cuarta existe por la misma razón que en el diario y en la admisión: «no pude mirarlo» y
#: «no está» se arreglan distinto, y colapsarlas es como se fabrica una certeza falsa.
EXISTE, AUSENTE, SIN_PADRE, INDETERMINADO = (
    "EXISTE", "AUSENTE", "SIN_PADRE", "INDETERMINADO")


def _nacimiento(st) -> int | None:
    """La hora de CREACIÓN del objeto en microsegundos, o `None` si el sistema no la da.

    `st_birthtime` es lo único de `lstat` que distingue «otro objeto con el mismo inodo» sin
    cambiar cuando sólo se reescribe el contenido. `ctime_ns` no sirve: cambia también al
    escribir, y la identidad responde «¿es este fichero?», no «¿tiene el mismo contenido?» —
    usarlo convertiría la atestación en una alarma que salta siempre.

    Microsegundos y no nanosegundos porque `st_birthtime` es un `float` de segundos en las
    plataformas que sólo tienen ése, y a la escala de la época actual su precisión real no llega
    al nanosegundo: fingirla daría dos valores distintos para el mismo instante.
    """
    ns = getattr(st, "st_birthtime_ns", None)
    if ns is not None:
        return int(ns) // 1000
    seg = getattr(st, "st_birthtime", None)
    if seg is not None:
        return int(round(float(seg) * 1_000_000))
    return None


#: ¿Puede esta identidad distinguir una sustitución que REUTILIZA el inodo?
#:
#: Es una retractación, y hay que decirla entera. R-04 se declaró cerrada el 2026-09-25 midiendo
#: en macOS, donde APFS no reutiliza números de inodo: borrar y recrear con el mismo nombre daba
#: otro `ino` y la identidad lo notaba. En **ext4 el inodo liberado se reutiliza de inmediato**, y
#: entonces `(dev, ino, tipo, nlink)` es IDÉNTICO antes y después. Medido el 2026-09-30 en CI
#: (ubuntu-latest, Python 3.10 y 3.13): cuatro pruebas de R-04 en rojo, con el mismo `ino`
#: —`9180471`— a los dos lados de la sustitución.
#:
#: Es exactamente el fallo que este repositorio advierte de sí mismo: **una propiedad medida en
#: una plataforma y afirmada para todas.** Diseño ≠ implementación ≠ despliegue.
#:
#: Y no se puede cerrar con `lstat`: Linux no expone la hora de creación por `os.stat` —está en
#: `statx`, que CPython no enlaza—, así que en ext4 **no hay campo que consultar**. Lo honesto no
#: es fingir la capacidad: es declarar dónde no existe, para que nadie construya encima de ella.
#: Cerrarlo de verdad pide otro instrumento (`statx`, o un descriptor retenido entre decisión y
#: ejecución, que un gancho `PreToolUse` no tiene).
IDENTIDAD_DISTINGUE_REUSO_DE_INODO = _nacimiento(os.lstat(__file__)) is not None


def identidad_de(ruta: Path) -> dict:
    """Sobre QUÉ OBJETO se está decidiendo, hasta donde el sistema de archivos lo diga.

    Qué resuelve y qué NO
    ---------------------
    La política protege RUTAS; el sistema de archivos ejecuta sobre OBJETOS. Una ruta es un
    nombre, y un nombre se puede reapuntar. Hasta el 2026-09-25 la `Decision` no llevaba
    ninguna identidad de objeto, así que la pregunta «¿lo que se autorizó en T1 es lo que se
    tocó en T5?» **no tenía con qué responderse, ni después ni nunca**.

    Esto NO impide la sustitución. refuto es un gancho `PreToolUse`: decide y devuelve, y
    quien abre el fichero es otro proceso, más tarde. Lo que esto hace es dejar la identidad
    ATESTIGUADA en la evidencia, que es la precondición para que alguien pueda detectarla
    después. Prevención y detección no son lo mismo y aquí sólo se alcanza la segunda — ver
    el registro de remediación, §R-04.

    Por qué `lstat` y no `stat`
    ---------------------------
    `stat` sigue el enlace y devolvería la identidad del DESTINO, con lo que un enlace y su
    objetivo serían indistinguibles — justo la sustitución que interesa ver. `lstat` da la
    identidad del nombre tal como está. La ruta que llega aquí ya viene resuelta por
    `realpath`, así que en el camino feliz las dos coinciden; cuando no coinciden, es
    exactamente lo que hay que poder mirar después.
    """
    def _campos(st, prefijo: str = "") -> dict:
        import stat as _stat
        tipo = ("symlink" if _stat.S_ISLNK(st.st_mode) else
                "dir" if _stat.S_ISDIR(st.st_mode) else
                "file" if _stat.S_ISREG(st.st_mode) else "otro")
        campos = {f"{prefijo}dev": st.st_dev, f"{prefijo}ino": st.st_ino,
                  f"{prefijo}tipo": tipo, f"{prefijo}nlink": st.st_nlink}
        nac = _nacimiento(st)
        if nac is not None:
            campos[f"{prefijo}nacimiento_us"] = nac
        return campos

    try:
        return {"estado": EXISTE, **_campos(os.lstat(ruta))}
    except OSError as exc:
        if exc.errno not in (errno.ENOENT, errno.ENOTDIR):
            # Permisos, E/S, ruta demasiado larga: NO es «no está».
            return {"estado": INDETERMINADO, "motivo": f"{type(exc).__name__}: {exc.strerror}"}
    try:
        # No existe: lo que acota dónde aterrizará la escritura es el directorio que la
        # recibirá. Sustituir ESE directorio es la forma de TOCTOU que aplica a una creación.
        return {"estado": AUSENTE, **_campos(os.lstat(ruta.parent), "padre_")}
    except OSError:
        return {"estado": SIN_PADRE}


def decide_write(policy: Policy, workspace: Path, target: str, content: str = "") -> Decision:
    """Decide si una escritura se permite, y ATESTIGUA sobre qué objeto se decidió.

    Se resuelve la ruta ANTES de compararla. Comparar la ruta tal como la escribió el agente es
    lo que hace que `verificacion/../verificacion/v1.py` y un enlace simbólico a `verificacion/`
    pasen por debajo del patrón. Se compara lo que el sistema de archivos va a tocar.

    La identidad se adjunta en UN solo sitio —aquí, sobre la decisión que salga— y no en cada
    `return`. Repartirla por las cuatro ramas garantizaba que la siguiente rama que alguien
    añadiera saliera sin ella, y una identidad que falta sólo en algunos casos es peor que no
    tenerla: parece que está.
    """
    if not isinstance(target, (str, Path)) or isinstance(target, bool):
        raise TypeError(f"target debe ser str o Path, no {type(target).__name__}")
    target = str(target).replace("\\", "/")
    d = _decidir_escritura(policy, workspace, target, content)
    if not d.objeto:
        ws = workspace.resolve()
        raw = Path(target).expanduser()
        d.objeto = identidad_de(Path(os.path.realpath(
            raw if raw.is_absolute() else (ws / raw))))
    return d


def _decidir_escritura(policy: Policy, workspace: Path, target: str,
                       content: str = "") -> Decision:
    """La decisión en sí. Separada para que la atestación no tenga que repetirse por rama."""
    target = str(target).replace("\\", "/")
    ws = workspace.resolve()
    raw = Path(target).expanduser()
    absolute = raw if raw.is_absolute() else (ws / raw)
    # `resolve()` sigue enlaces simbólicos: es justo lo que hace falta. Un enlace dentro del
    # espacio que apunta al juez es un ataque, no una comodidad.
    resolved = Path(os.path.realpath(absolute))

    try:
        rel = str(resolved.relative_to(ws))
    except ValueError:
        # Fuera del espacio. Se rechaza, salvo las raíces que el espacio declara suyas: la
        # memoria del agente y su cuaderno no son del proyecto y nunca van a estar dentro.
        externo = policy.external_allows(resolved)
        if externo:
            return _revisar_contenido(policy, content, donde=str(resolved),
                                      contexto=f"fuera del espacio, autorizado por «{externo}»")
        return Decision(DENY, rule="fuera-del-espacio",
                        reason=f"la escritura resuelve a {resolved}, fuera del espacio de "
                               f"trabajo {ws}. Una ruta relativa que sale del árbol es "
                               f"travesía de directorios, se haya pretendido o no. "
                               f"Si es un sitio propio del agente y debe poder escribirlo, "
                               f"decláralo en `external_write_allow`; no se abre por defecto.")

    # La excepción va PRIMERO: evaluada después nunca podría ganarle a lo protegido.
    libre = policy.is_writable(rel)
    if not libre:
        pattern = policy.is_protected(rel)
        if pattern:
            return Decision(DENY, rule=pattern,
                            reason=_motivo_protegida(rel, pattern, resolved.exists()))
        # Gobierno: el mismo veredicto por un mecanismo distinto. Va DESPUÉS de
        # `protected_paths` porque éste no toca el sistema de archivos y aquél sí: cuando las
        # dos denegarían, se cita la más barata y la que no depende del estado del disco.
        patron_aut, raiz = policy.is_authority(rel, raices_de_autoridad(ws, resolved))
        if patron_aut:
            donde = f"la raíz de autoridad «{raiz}»" if raiz else "la raíz del espacio"
            return Decision(
                DENY, rule=patron_aut,
                reason=f"«{rel}» es un artefacto de GOBIERNO: coincide con «{patron_aut}» "
                       f"relativo a {donde}. Lo que se protege no es el nombre del directorio "
                       f"—código fuente en un `policies/` anidado se escribe sin problema— sino "
                       f"la autoridad del documento: ahí cuelga la norma de la que depende este "
                       f"espacio y los que hereden de él. Si esto es código y no gobierno, no "
                       f"vive en la raíz de un espacio gobernado.")

    secret_pat = policy.is_secret_path(rel)
    if secret_pat:
        return Decision(DENY, rule=secret_pat,
                        reason=f"«{rel}» coincide con «{secret_pat}»: es una ruta de credencial.")

    return _revisar_contenido(policy, content, donde=rel)


def _revisar_contenido(policy: Policy, content: str, *, donde: str,
                       contexto: str = "") -> Decision:
    """Lo último que se mira: si el TEXTO lleva un secreto.

    Se distingue prueba de indicio, y se responde distinto a cada una. Antes no: cualquier
    coincidencia rechazaba, y como la coincidencia más frecuente era «algo llamado `secret`
    recibe un valor», la regla bloqueaba justo el código que maneja secretos bien —
    `let secret = std::env::var("JWT_SECRET")?` entre otros 27 casos medidos en un espacio real.

    Una prueba rechaza. Un indicio lo decide una persona: eso es lo que se hace con una
    ambigüedad, en vez de resolverla siempre para el mismo lado.
    """
    from core.digest import classify

    if not (policy.block_secret_content and content):
        return Decision(ALLOW, reason=contexto)
    pruebas, indicios = classify(content)
    if pruebas:
        return Decision(DENY, rule="contenido-con-secreto",
                        reason=f"el contenido de «{donde}» contiene {', '.join(pruebas)}: eso "
                               f"tiene la forma de una credencial emitida, no de una referencia "
                               f"a ella. Lo que entra al árbol, sale. El control es que el dato "
                               f"no esté.")
    if indicios:
        return Decision(ASK, rule="posible-secreto-literal",
                        reason=f"en «{donde}» hay {', '.join(indicios)}. No tiene forma de "
                               f"credencial conocida, así que puede ser un ejemplo o una prueba "
                               f"— o puede ser real. No lo adivino: lo decide una persona.")
    return Decision(ALLOW, reason=contexto)


#: Órdenes cuyo trabajo es ejecutar OTRA orden. La regla tiene que mirar lo ENVUELTO: en
#: `xargs sudo rm` el token de cabeza es `xargs`, y `sudo:*` no casaba con nada.
_ENVOLTORIOS = {"env", "nohup", "time", "nice", "ionice", "xargs", "command", "builtin",
                "exec", "stdbuf", "timeout", "setsid", "sudo", "doas"}

#: Intérpretes que reciben la orden real como argumento de `-c`.
_INTERPRETES = {"sh", "bash", "zsh", "dash", "ksh", "fish"}

#: Tope de segmentos que `_segmentos` expande de una cadena. Existe porque la expansión es una
#: cola y no un recorrido: un segmento puede producir otro, y sin tope una carga construida a
#: propósito convertiría al guardián —que corre en el camino crítico de CADA orden— en la manera
#: de colgar la sesión.
#:
#: 400 se eligió midiendo, no a ojo: sobre las **161** órdenes del corpus de pruebas de este
#: repositorio —el único corpus real disponible, porque el diario guarda CLAVES y no valores y
#: por tanto no contiene ninguna orden— la mediana es **1** segmento y el máximo **4**
#: (`echo hola; sudo rm -rf /var`). El tope queda dos órdenes de magnitud por encima del máximo
#: observado, así que no recorta nada real. Medido el 2026-09-29.
_TOPE_EXPANSION = 400

_ASIGNACION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def _partir(command: str, *, tuberia: bool = True) -> list:
    """Parte la cadena por los separadores que están FUERA de comillas.

    Con `tuberia=False` corta sólo donde empieza una SENTENCIA nueva (`;`, `&&`, `||`, `&`,
    salto de línea) y deja las tuberías dentro. Hacen falta las dos vistas: hay reglas que
    describen una orden suelta (`rm -rf:*`) y reglas que describen precisamente la unión de dos
    por una tubería (`curl* | bash`). Cortar siempre por el `|` volvía inaplicables las segundas.

    Respetar las comillas no es cosmético. La primera versión partía a lo bruto, y entonces una
    BÚSQUEDA como `grep -rn "rm -rf" .` —que no ejecuta nada— se rechazaba por llevar el texto
    detrás de un separador imaginario. Se midió en el acto y de la peor manera: el parche que
    arreglaba esto no se pudo aplicar, porque su propio texto disparaba la regla. Un control que
    salta con el texto y no con la acción se desactiva en una semana, y entonces no protege de
    nada.
    """
    partes, actual = [], []
    simple = doble = False
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\" and i + 1 < n:
            actual.append(c)
            actual.append(command[i + 1])
            i += 2
            continue
        if c == "'" and not doble:
            simple = not simple
        elif c == '"' and not simple:
            doble = not doble
        if not simple and not doble:
            if command.startswith("&&", i) or command.startswith("||", i):
                partes.append("".join(actual))
                actual = []
                i += 2
                continue
            if c in (";\n|&" if tuberia else ";\n&"):
                partes.append("".join(actual))
                actual = []
                i += 1
                continue
        actual.append(c)
        i += 1
    partes.append("".join(actual))
    return partes


def _sin_literales(command: str) -> str:
    """La cadena con el contenido de las comillas SIMPLES en blanco, conservando la longitud.

    Sirve para buscar sustituciones de orden sin confundir texto con ejecución.
    """
    out, simple = [], False
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "\\\\" and i + 1 < n and not simple:
            out.append(c)
            out.append(command[i + 1])
            i += 2
            continue
        if c == "'":
            simple = not simple
            out.append(c)
        else:
            out.append(" " if simple else c)
        i += 1
    return "".join(out)


#: El operador de documento aquí y su delimitador. Tres formas, y la diferencia entre ellas es
#: justo lo que decide si el cuerpo se ejecuta: `<<'EOF'` y `<<"EOF"` lo dejan literal, `<<EOF`
#: lo expande.
_HEREDOC = re.compile(r"<<-?[ \t]*(?:'([^']*)'|\"([^\"]*)\"|([A-Za-z_][A-Za-z0-9_]*))")


def _dentro_de_comillas(linea: str) -> list:
    """Por cada posición, si está dentro de comillas. Para no leer texto citado como sintaxis."""
    dentro, simple, doble = [], False, False
    i, n = 0, len(linea)
    while i < n:
        c = linea[i]
        if c == "\\" and i + 1 < n:
            dentro += [simple or doble, simple or doble]
            i += 2
            continue
        if c == "'" and not doble:
            simple = not simple
        elif c == '"' and not simple:
            doble = not doble
        dentro.append(simple or doble)
        i += 1
    return dentro


def _sin_cuerpos_citados(command: str) -> str:
    """La orden sin los cuerpos de documento aquí que el shell NO expande.

    El defecto que esto cierra
    --------------------------
    `_segmentos` extrae órdenes de `$(…)` y de acentos invertidos, y `_partir` corta por saltos
    de línea. Las dos cosas son correctas para shell — y el cuerpo de un documento aquí citado
    **no es shell**: es texto. Con `<<'EOF'` el shell no expande NADA, ni sustituciones ni
    acentos invertidos; es literal por definición.

    La consecuencia, medida el 2026-09-24 contra el guardián real, con un agente que documentaba
    en markdown la frontera de lo que NO había ejecutado:

        cat > 00_AUTHORIZATION.md <<'EOF'
        ## NO ejecutado (fuera de la frontera)
        `adb root`, fastboot, flashing, `dd`, escritura de particiones…
        EOF
                                    →  deny  («dd:*»)

    Cada `` `orden` `` de la prosa se convertía en un segmento ejecutable. Se midió también con
    `` `sudo` `` (deny «sudo:*») y con `` `rm -rf /` ``, que además salía como
    «fuera-del-espacio» porque el modelo de efectos leía el `/` del texto como un destino real.
    Y no es una hipótesis de laboratorio: **esta función no se pudo medir en su primera versión
    porque la orden que la medía contenía el texto que disparaba la regla**, igual que ya le
    pasó a `_partir` con las comillas —lo cuenta su propio docstring—. Aquello se arregló sólo
    para comillas en línea; el documento aquí, cuya cita es el delimitador y no una comilla,
    quedó fuera.

    Un control que salta con el TEXTO y no con la ACCIÓN se rodea, y aquí el rodeo medido fue
    dejar de usar el shell para escribir ficheros. Entonces deja de mirar el canal entero.

    Lo que NO se toca
    -----------------
    - `<<EOF` **sin citar** sí expande: su cuerpo se conserva y se sigue analizando.
    - La línea del operador se conserva siempre, así que la redirección (`cat > destino`) sigue
      viéndose y `core.effects` sigue derivando la escritura. Esto es lo que impide que el
      arreglo se convierta en una vía de escape: el cuerpo deja de leerse como órdenes, pero el
      fichero que se escribe se sigue juzgando.
    - Sin línea terminadora no hay documento aquí (el shell fallaría), así que no se descarta
      nada: una coincidencia falsa del operador no puede tragarse las órdenes que vengan detrás.
    """
    if "<<" not in command:
        return command
    lineas = command.split("\n")
    salida: list = []
    i = 0
    while i < len(lineas):
        linea = lineas[i]
        salida.append(linea)
        i += 1
        mascara = _dentro_de_comillas(linea)
        pendientes = []
        for m in _HEREDOC.finditer(linea):
            if m.start() < len(mascara) and mascara[m.start()]:
                continue            # el operador venía dentro de comillas: es texto
            delim = m.group(1) if m.group(1) is not None else \
                m.group(2) if m.group(2) is not None else m.group(3)
            pendientes.append((delim, m.group(3) is None, m.group(0).startswith("<<-")))
        for delim, literal, sangria in pendientes:
            cuerpo, j, cerrado = [], i, False
            while j < len(lineas):
                cierre = lineas[j].lstrip("\t") if sangria else lineas[j]
                if cierre == delim:
                    cerrado = True
                    break
                cuerpo.append(lineas[j])
                j += 1
            if not cerrado:
                break               # sin terminador no es un documento aquí: no se traga nada
            if not literal:
                salida += cuerpo    # `<<EOF` sin citar SÍ expande: se sigue mirando
            i = j + 1
    return "\n".join(salida)


def _ordenes_internas(seg: str) -> list:
    """Las órdenes que ESTE segmento va a lanzar a su vez, por los dos canales que existen.

    **Canal 1 — el cuerpo de `-c`.** La regla anterior cubría `sh -c` y exigía dos cosas que
    dejaban fuera los casos reales: que el intérprete fuera el primer token literal, y que el
    `-c` estuviera en la posición 1 ó 2. Medido el 2026-09-29 con la política de fábrica, todos
    éstos pasaban enteros:

        su persona -c 'rm -rf /'          sudo -u persona -c 'rm -rf /'
        su - persona -c 'rm -rf /'        doas -u persona -c 'rm -rf /'
        xargs -I{} sh -c 'rm -rf /'

    Aquí el programa se busca **en posición de mando** —tras pelar envoltorios y sus opciones,
    que es lo que `core.privilegio` ya sabe hacer— y el `-c` en cualquier posición posterior.

    **Canal 2 — la orden POSICIONAL de un elevador.** Un elevador no necesita `-c` para ejecutar
    algo: se lo pasa como argumentos. Medido el 2026-09-29, con el canal 1 ya cerrado y la
    política de fábrica, estas seis salían `allow` mientras la misma orden desnuda salía `deny`:

        sudo -u persona rm -rf /                    sudo -u persona chmod -R 777 /
        su persona rm -rf /                         sudo -u persona git push --force
        doas -u persona rm -rf /                    sudo -u persona dd if=/dev/zero of=/dev/sda

    Es el mismo agujero que el canal 1 y **más barato de usar**, porque no hace falta escribir
    `-c` ni comillas. `clasificar` ya calculaba esa orden en `resto` y nadie la miraba.

    No se expande nada más: sólo intérpretes y elevadores tratan sus argumentos como una orden.
    Quien llama vuelve a pasar cada resultado por aquí —ver `_segmentos`—, porque un nivel de
    anidamiento no puede ser lo que decida si el canal se mira.
    """
    from core.privilegio import (ELEVADORES, _saltar_envoltorios, _tokenizar, clasificar,
                                 clave_de_programa)

    toks = _saltar_envoltorios(_tokenizar(seg))
    if len(toks) < 2:
        return []
    if clave_de_programa(toks[0]) not in (_INTERPRETES | ELEVADORES):
        return []

    crudas: list = []
    if "-c" in toks[1:]:
        cuerpo = " ".join(toks[toks.index("-c") + 1:]).strip()
        if cuerpo:
            crudas.append(cuerpo)
    else:
        # Sin `-c`, lo que ejecuta un elevador es su `resto`: los argumentos que quedan tras sus
        # banderas y su usuario destino. `clasificar` es quien sabe dónde acaban unas y otro.
        resto = " ".join(clasificar(seg).resto).strip()
        if resto:
            crudas.append(resto)

    salida: list = []
    for cruda in crudas:
        salida += [" ".join(x.split()) for x in _partir(cruda) if x.strip()]
    return salida


def _segmentos(command: str) -> list:
    """Cada orden que esta cadena va a ejecutar, no sólo la primera.

    `decide_command` normalizaba la cadena entera y la comparaba contra prefijos, así que
    decidía por el PRIMER token y nada más. Medido: `sudo lanzador` → deny, pero
    `echo hola; sudo lanzador` → allow, y `cd /tmp && git push --force` → allow. Las 16 reglas de
    rechazo se rodeaban anteponiendo cualquier cosa inofensiva.

    Esto NO es un analizador de shell y no pretende serlo: una ofuscación decidida (armar el
    nombre de la orden en una variable, o codificarla) lo atraviesa. Es una barandilla contra el
    resbalón, no una caja de arena contra un adversario. Lo que sí cubre es lo que de verdad
    pasa a diario: encadenar, envolver, sustituir e interpretar.
    """
    # El cuerpo de un documento aquí citado es TEXTO, no órdenes. Se descarta antes de partir:
    # después ya es indistinguible de una cadena de órdenes separadas por saltos de línea.
    # Ver `_sin_cuerpos_citados`, que explica el defecto que esto cierra.
    command = _sin_cuerpos_citados(command)
    # Dos vistas: la sentencia con sus tuberías intactas, y cada orden suelta dentro de ella.
    sentencias = _partir(command, tuberia=False)
    pendientes = list(sentencias)
    for sent in sentencias:
        pendientes += _partir(sent)
    # Lo que va dentro de `$( … )` y de comillas invertidas también se ejecuta —salvo dentro de
    # comillas SIMPLES, donde el shell no expande nada y el texto es sólo texto. Sin esta
    # distinción, escribir `'$(algo)'` en un argumento se trataba como ejecutarlo.
    for a, b in re.findall(r"\$\(([^()]*)\)|`([^`]*)`", _sin_literales(command)):
        pendientes += _partir(a) + _partir(b)

    # La cadena ENTERA, además de sus trozos: hay reglas que describen precisamente la unión
    # —`curl* | bash`— y partir por el `|` las volvía inaplicables. Partir añade candidatos; no
    # puede quitar el que ya había.
    # Cola, y no un recorrido de una pasada: lo que sale de un segmento vuelve a la cola y se
    # expande igual. Sin esto, UN nivel más de anidamiento vaciaba el control entero. Medido el
    # 2026-09-29, con la expansión de una pasada y la política de fábrica:
    #
    #     deny   sh -c 'rm -rf /'                     allow  sh -c 'sh -c "rm -rf /"'
    #     deny   su persona -c 'rm -rf /'             allow  su persona -c 'bash -c "rm -rf /"'
    #                                                 allow  su p1 -c 'su p2 -c "sudo id"'
    #
    # «Cuántas capas escribió quien lo lanzó» no es una propiedad que nadie quisiera que decidiera
    # si una orden se examina. El conjunto `vistos` cierra los ciclos y el tope de pasos acota el
    # coste: los dos hacen falta, porque un segmento puede expandirse a sí mismo.
    # La cadena ENTERA entra por la cola como un segmento más, y de primera: así sale de `out`
    # en cabeza —hay reglas que describen precisamente la unión, `curl* | bash`— y, a diferencia
    # de sembrarla en `vistos`, no impide que se EXPANDA. Sembrarla dejaba fuera justo el caso
    # más común: una orden de una sola sentencia, cuyo único segmento es ella misma.
    out: list = []
    vistos: set = set()
    cola = collections.deque([" ".join(command.split()), *pendientes])
    pasos = 0
    while cola and pasos < _TOPE_EXPANSION:
        pasos += 1
        seg = " ".join(cola.popleft().split())
        if not seg or seg in vistos:
            continue
        vistos.add(seg)
        out.append(seg)
        tokens = seg.split()
        # Se pela envoltorio a envoltorio, y se mira DESPUÉS DE CADA CAPA. Pelarlos todos de
        # golpe y mirar sólo el fondo perdía la capa intermedia: de `xargs sudo rm` salía `rm`,
        # que no casa con nada, y la escalada del medio no la veía nadie.
        i = 0
        while i < len(tokens) and (tokens[i] in _ENVOLTORIOS or _ASIGNACION.match(tokens[i])):
            i += 1
            if i < len(tokens):
                cola.append(" ".join(tokens[i:]))
        if i and i < len(tokens):
            tokens = tokens[i:]
        # `sh -c "…"`: la orden de verdad va dentro, y ahí sí hay que mirar. Se conserva la vista
        # por TEXTO además de la de `_ordenes_internas`, que tokeniza: `shlex` normaliza comillas
        # y hay cargas donde el texto crudo conserva lo que la tokenización pierde.
        if len(tokens) >= 3 and tokens[0] in _INTERPRETES and "-c" in tokens[1:3]:
            dentro = seg.split("-c", 1)[1].strip().strip("'\"")
            cola += [" ".join(x.split()) for x in _partir(dentro) if x.strip()]
        cola += _ordenes_internas(seg)
    return out


def decide_command(policy: Policy, command: str, workspace: Path | None = None) -> Decision:
    """Decide si una orden de consola se ejecuta, se pregunta o se rechaza.

    Dos comprobaciones, y la primera es la que faltaba
    ---------------------------------------------------
    1. **Efectos.** `Ê(orden)` (`core.effects`) da las escrituras que se pueden DEMOSTRAR
       desde la sintaxis. Cada una pasa por la MISMA regla de rutas protegidas que aplica
       `decide_write`. Sin esto, la política de rutas no cubría el canal de órdenes:
       `Write gates/base.py` daba `deny` y `Bash echo x > gates/base.py` daba `allow`
       sobre la misma ruta y la misma política (medido el 2026-09-23).
    2. **Patrones de orden.** Las listas `command_deny`/`command_ask` de siempre, sobre
       todos los segmentos de la cadena. Gana el más restrictivo: un rechazo en cualquier
       posición rechaza la llamada entera, porque la herramienta ejecuta la cadena entera.

    Lo que esto NO es. `Ê ⊆ Effects` por construcción — el efecto exacto de una orden no es
    computable (FORMAL-MODEL §6.1). Una orden opaca se marca `opaco=True` y se deja pasar:
    denegar todo `python3` haría inusable la herramienta, y un control inusable se desactiva.
    La garantía del producto descansa en `I6'` —si el juez fue modificado, ningún veredicto
    posterior es PASS—, no en esta función.
    """
    from core.effects import efectos

    ws = workspace or Path.cwd()
    ef = efectos(command)
    for destino in sorted(ef.escrituras):
        d = decide_write(policy, ws, destino)
        if d.outcome == DENY:
            return Decision(DENY, rule=d.rule,
                            reason=f"la orden escribe en «{destino}», y {d.reason}",
                            opaco=ef.opaco, motivo_opaco=ef.motivo_opaco,
                            escrituras=tuple(sorted(ef.escrituras)),
                            resolucion=ef.resolucion,
                            sin_resolver=tuple(sorted(ef.sin_resolver)))

    # ── el canal de LECTURA, que estaba sin mirar ────────────────────────────────────
    #
    # El defecto que esto cierra, medido el 2026-09-25 con el guardián real y la política de
    # fábrica:
    #
    #     Write  .env                  →  deny   («**/.env»)
    #     Bash   cat .env              →  ALLOW
    #     Bash   cp .env /tmp/claude-x/robado                      →  ALLOW
    #     Bash   cp .env ~/.claude/projects/p/memory/nota.md       →  ALLOW  ← sobrevive la sesión
    #
    # `secret_read_deny` se aplicaba en dos sitios y ninguno era el guardián sobre `Bash`:
    # `decide_write` (que gobierna ESCRITURAS) y `adapters/claude.py`, que lo compila a
    # `Read(**/.env)` en la capa de permisos del agente. `core/wire.py` declara que `Read` no se
    # engancha a propósito —denegaría leer `.harness/**`, que el agente necesita— y esa decisión
    # sigue siendo correcta; lo que faltaba es preguntar por las lecturas en el canal que SÍ
    # está enganchado. Es exactamente el defecto que `core/wire.py` documenta haber arreglado
    # para escrituras: «una orden cualquiera por Bash rodeaba el control entero».
    #
    # Y el dato ya estaba: `Efectos.lecturas` se pobla desde siempre y `decide_command` tenía
    # tres referencias a `escrituras` y cero a `lecturas`. Se calculaba y se descartaba.
    #
    # `ask` y no `deny`, y la razón es operativa: leer un `.env` para depurar configuración es
    # legítimo a menudo, y un rechazo duro se rodea en un día con `python3 -c` —que es opaco—.
    # Entonces el canal deja de mirarse, que es peor que mirarlo y preguntar. El mismo patrón se
    # midió dos veces en este repositorio con `_partir` y con `dd:*`.
    lecturas_secretas = _lecturas_secretas(policy, ws, ef.lecturas, command)
    marca = {"opaco": ef.opaco, "motivo_opaco": ef.motivo_opaco,
             "escrituras": tuple(sorted(ef.escrituras)),
             "resolucion": ef.resolucion,
             "sin_resolver": tuple(sorted(ef.sin_resolver))}
    if lecturas_secretas:
        ruta, patron = lecturas_secretas[0]
        # La COMBINACIÓN sí se deniega: leer una credencial Y escribir fuera del espacio en la
        # misma orden no tiene lectura legítima — es exfiltración, y da igual que el destino sea
        # una ruta que la política abre a propósito. `external_write_allow` existe para el
        # cuaderno y la memoria del agente, no para que un secreto sobreviva a la sesión.
        fuera = [d for d in sorted(ef.escrituras) if _sale_del_espacio(ws, d)]
        if fuera:
            return Decision(DENY, rule=f"{patron} → fuera-del-espacio",
                            reason=f"la orden LEE «{ruta}» (credencial, por «{patron}») y ESCRIBE "
                                   f"en «{fuera[0]}», fuera del espacio. Las dos cosas por "
                                   f"separado pueden ser legítimas; juntas son exfiltración, y "
                                   f"que el destino esté declarado escribible no lo cambia: "
                                   f"`external_write_allow` abre el cuaderno del agente, no una "
                                   f"salida para credenciales.", **marca)
        return Decision(ASK, rule=patron,
                        reason=f"la orden LEE «{ruta}», que coincide con «{patron}»: es una ruta "
                               f"de credencial. Leerla puede ser legítimo —depurar una "
                               f"configuración lo es— y por eso no se rechaza; lo decide una "
                               f"persona. Si sólo necesita saber si la variable está definida, "
                               f"compruebe su presencia sin volcar el valor.", **marca)

    from core import privilegio as PRIV

    segmentos = _segmentos(command) or [" ".join(command.split())]
    peor_ask = None
    indeterminados = []
    for cmd in segmentos:
        # Quién va a ejecutar ESTE segmento. Dos cosas salen de aquí, y las dos faltaban:
        #
        #  · `forma_normalizada` reduce el programa a su nombre, así que `/usr/bin/sudo id`,
        #    `su'do' id` y `\sudo id` casan la misma regla que `sudo id`. Medido el 2026-09-29:
        #    de 23 formas de invocar privilegio, 12 pasaban sin freno, y ocho eran exactamente
        #    el mismo programa escrito de otra manera.
        #  · la CLASIFICACIÓN distingue elevar de bajar. De 3.624 invocaciones reales, 3.405
        #    eran `su <usuario> -c …`: una sesión con privilegios ejecutando el trabajo como la
        #    persona para no dejar ficheros de root. Aplicarles una regla de elevación pondría
        #    en rojo el camino correcto, que es como se desactiva un control.
        clas = PRIV.clasificar(cmd)
        normalizado = PRIV.forma_normalizada(cmd)
        if clas.tipo == PRIV.INDETERMINADO:
            indeterminados.append((cmd, clas.motivo))
        for pattern in policy.command_deny:
            if _patron_de_elevacion(pattern) and clas.tipo == PRIV.BAJA:
                continue            # una regla de elevación no habla de una cesión de privilegio
            if _matches_command(cmd, pattern) or _matches_command(normalizado, pattern):
                # La excepción NOMBRADA va antes del rechazo, igual que `writable_paths` va antes
                # de `protected_paths`: evaluada después nunca podría ganarle. Ver `core/grants.py`.
                #
                # Se consulta AQUÍ y no arriba a propósito: una concesión no autoriza órdenes en
                # general, autoriza órdenes que de otro modo se rechazarían. Preguntar antes de
                # saber que hay rechazo convertiría la tabla en una lista de permisos, que es otra
                # cosa y más ancha.
                from core.grants import buscar
                v = buscar(policy, cmd, rol=os.environ.get("HARNESS_ROLE", ""), efectos=ef)
                if v.concesion is not None:
                    if v.concesion.human_approval == "once-per-grant":
                        return Decision(ALLOW, rule=f"concesion:{v.concesion.id}",
                                        reason=f"«{pattern}» se rechaza por omisión y esta orden "
                                               f"está {v.motivo}. La concesión vive en la política, "
                                               f"que el agente no puede escribir: por eso vale "
                                               f"como aprobación.", **marca)
                    return Decision(ASK, rule=f"concesion:{v.concesion.id}",
                                    reason=f"«{pattern}» se rechaza por omisión y esta orden está "
                                           f"{v.motivo}, con aprobación por instancia: lo decide "
                                           f"una persona cada vez.", **marca)
                extra = ""
                if v.descartes:
                    # El diagnóstico que faltaba. «No hay concesión» y «la hay y caducó ayer» se
                    # arreglan distinto, y sin esto el agente no puede distinguirlos ni pedirlo.
                    extra = (" Hay concesión(es) que describen esta orden y no aplican: "
                             + " · ".join(v.descartes[:3]))
                return Decision(DENY, rule=pattern,
                                reason=f"la orden coincide con la regla de rechazo «{pattern}»"
                                       f" (en «{cmd[:60]}»).{extra}", **marca)
        if peor_ask is None:
            for pattern in policy.command_ask:
                if _patron_de_elevacion(pattern) and clas.tipo == PRIV.BAJA:
                    continue
                if _matches_command(cmd, pattern) or _matches_command(normalizado, pattern):
                    peor_ask = Decision(ASK, rule=pattern,
                                        reason=f"«{pattern}» sale del repositorio o cambia algo "
                                               f"remoto: lo decide una persona.", **marca)
                    break
    # ── eleva, y ningún patrón lo nombraba ───────────────────────────────────────────
    #
    # Una lista de nombres deja el control en función de qué binario tenga instalado la máquina.
    # Medido el 2026-09-29: con `sudo` nombrado y nada más, pasaban `doas`, `su root`, `sudoedit`
    # y `osascript … with administrator privileges` — el último sin escribir «sudo» en ninguna
    # parte, así que ampliar la lista de nombres tampoco lo habría cazado.
    #
    # Aquí la regla se lee por lo que DICE: si la política rechaza pedir privilegio, rechaza
    # pedirlo. No abre nada — sólo se llega con una política que ya tiene alguna regla de
    # elevación— y no toca las cesiones, que `clasificar` distingue.
    if not peor_ask:
        for cmd in segmentos:
            clas = PRIV.clasificar(cmd)
            if not clas.eleva:
                continue
            elevacion = next((p for p in policy.command_deny if _patron_de_elevacion(p)), "")
            if not elevacion:
                break
            if any(_matches_command(cmd, p) or _matches_command(PRIV.forma_normalizada(cmd), p)
                   for p in policy.command_deny):
                break                                    # ya lo dijo un patrón, con su nombre
            # Y una concesión vale aquí igual que en el bucle de arriba. Sin esto, un elevador
            # NOMBRADO se podría conceder y uno no nombrado no: la misma orden, autorizable o no
            # según qué binario use, que es justo la dependencia que este bloque quita.
            from core.grants import buscar
            v = buscar(policy, cmd, rol=os.environ.get("HARNESS_ROLE", ""), efectos=ef)
            if v.concesion is not None:
                if v.concesion.human_approval == "once-per-grant":
                    return Decision(ALLOW, rule=f"concesion:{v.concesion.id}",
                                    reason=f"pedir privilegio se rechaza por omisión y esta orden "
                                           f"está {v.motivo}.", **marca)
                return Decision(ASK, rule=f"concesion:{v.concesion.id}",
                                reason=f"pedir privilegio se rechaza por omisión y esta orden está "
                                       f"{v.motivo}, con aprobación por instancia.", **marca)
            # El mismo diagnóstico que ofrece el bucle de arriba: «no hay concesión» y «la hay y
            # no se pudo verificar» se arreglan distinto, y sin decirlo nadie puede pedirla.
            extra = ""
            if v.descartes:
                extra = (" Hay concesión(es) que describen esta orden y no aplican: "
                         + " · ".join(v.descartes[:3]))
            return Decision(DENY, rule=f"elevacion:{clas.programa}",
                            reason=f"{clas.motivo}, y esta política rechaza pedir privilegio "
                                   f"(lo declara con reglas como «{elevacion}»). Ninguna nombra "
                                   f"a «{clas.programa}»: la regla habla de la elevación, no del "
                                   f"binario, porque si no el control dependería de qué tenga "
                                   f"instalado la máquina.{extra}", **marca)

    if peor_ask:
        return peor_ask

    # ── el programa que se va a ejecutar no está escrito ─────────────────────────────
    #
    # `$(which sudo) id`, `` `command -v doas` `` : el nombre se construye al ejecutar, así que
    # no se puede comprobar contra ninguna tabla. Hasta el 2026-09-29 esto salía `allow` — una
    # certeza falsa sobre un programa que nadie conocía, y el rodeo más corto de los doce que
    # se midieron.
    #
    # `ask` y no `deny`, por el mismo motivo que `destino-sin-resolver`: resolver un binario con
    # `$(command -v algo)` es legítimo a diario, y un rechazo duro se rodea con `python3 -c`
    # —que es opaco— y entonces el canal deja de mirarse.
    if indeterminados:
        cmd, motivo = indeterminados[0]
        return Decision(ASK, rule="programa-sin-resolver",
                        reason=f"{motivo}. No se rechaza —resolver un binario así es legítimo— "
                               f"pero tampoco se aprueba como si se hubiera comprobado: lo "
                               f"decide una persona.", **marca)

    # ── una escritura cuyo destino no se resolvió ────────────────────────────────────
    #
    # `AMBIGUO` no es lo mismo que `NO_RESOLUBLE`, y tratarlos igual desperdicia información
    # que sí se tiene. Con `python3 -c` no se sabe **si** escribe; con `echo x > $D` se sabe
    # QUE escribe y no se sabe ADÓNDE. Lo segundo es estrictamente más: hay una operación
    # observada cuyo destino no se pudo examinar.
    #
    # Es el mismo hecho que `campo-ilegible` en la admisión, un canal más abajo, y se responde
    # igual: `ask`. No `deny`, porque `D=$(mktemp); echo x > $D` es legítimo a diario y un
    # rechazo duro se rodea con `python3 -c` —que es opaco— y entonces el canal deja de
    # mirarse. No `allow`, porque hasta el 2026-09-25 esto salía `allow` con `opaco=False`:
    # una certeza falsa sobre un destino que nadie conocía.
    if ef.sin_resolver:
        return Decision(ASK, rule="destino-sin-resolver",
                        reason=f"la orden escribe en «{sorted(ef.sin_resolver)[0]}», que "
                               f"conserva expansión del shell: el destino real lo decide el "
                               f"entorno en tiempo de ejecución, así que no se puede comprobar "
                               f"contra las rutas protegidas. No se rechaza —construir un "
                               f"destino con una variable es legítimo— pero tampoco se aprueba "
                               f"como si se hubiera examinado: lo decide una persona.", **marca)
    if ef.resolucion == "AMBIGUO" and ("dinámica" in ef.motivo_opaco or "codificación" in ef.motivo_opaco):
        return Decision(ASK, rule="interprete-eval-dinamica",
                        reason=f"{ef.motivo_opaco}: su efecto exacto sobre el sistema de archivos no se puede "
                               f"verificar estáticamente; lo decide una persona.", **marca)
    return Decision(ALLOW, **marca)


_GLOB_CHARS = re.compile(r"[*?\[]")


def _patron_de_elevacion(pattern: str) -> bool:
    """¿Esta regla habla de PEDIR privilegio?

    Se mira el PROGRAMA que el patrón nombra, no el texto: hace falta para poder decir que
    `sudo:*` no habla de `sudo -u persona …`, que cede privilegio en vez de pedirlo. Sin esta
    distinción sólo quedan dos salidas, y las dos son malas: dejar pasar la elevación para no
    romper la bajada, o poner en rojo el camino correcto.

    Y se clasifica el patrón ENTERO, no su primer token. La primera versión miraba sólo la
    cabeza, así que leía como «regla de elevación» a cualquier patrón que empezara por el nombre
    de un elevador — incluido uno que nombra a un usuario concreto. Medido el 2026-09-29: con
    `sudo -u nadie:*` añadido a `command_deny`, la orden `sudo -u nadie id` salía **`allow`**.
    La regla estaba en la política, se compilaba al dialecto del agente, se leía en el informe
    de sesión… y no hacía nada. Una regla que se ignora en silencio es peor que no tenerla: quien
    la escribió cree que está protegido.
    """
    from core.privilegio import clasificar

    # Sólo `ELEVA` califica. `BAJA` describe una cesión CONCRETA —y de ésas el patrón sí puede
    # hablar—; `NINGUNO` (`rm -rf:*`) e `INDETERMINADO` no son reglas de privilegio en absoluto.
    return clasificar(pattern.split(":", 1)[0].strip()).eleva


def _matches_command(cmd: str, pattern: str) -> bool:
    """Vocabulario de patrón de orden compartido con Claude Code: `prefijo:*` o glob.

    El prefijo puede llevar comodines (`aws *:*`). La primera versión hacía `startswith` con el
    prefijo literal, así que `aws *:*` no cubría `aws s3 ls` — una regla que parecía puesta y
    no lo estaba, que es el peor tipo de regla.
    """
    if pattern.endswith(":*"):
        prefix = pattern[:-2].strip()
        if _GLOB_CHARS.search(prefix):
            return fnmatch.fnmatch(cmd, prefix + "*") or fnmatch.fnmatch(cmd, prefix)
        if cmd == prefix or cmd.startswith(prefix + " "):
            return True
        # Más allá del espacio, lo que vale como continuación depende de QUÉ termina el prefijo,
        # y son dos casos que no se comportan igual:
        #
        #   nombre de programa  `mkfs` → `mkfs.ext4` SÍ (misma familia, mismo daño)
        #                       `dd`   → `ddev`      NO (otro programa que empieza igual)
        #   bandera corta       `rm -rf` → `rm -rfv` SÍ (las banderas cortas se agrupan)
        #
        # El `cmd.startswith(prefix)` suelto que había antes daba SÍ a los tres, así que `dd:*`
        # rechazaba `ddev up` y `ddgr python`. Un rechazo por parecido tipográfico enseña a
        # desconfiar del guardián, y un guardián del que se desconfía se rodea.
        if not cmd.startswith(prefix):
            return False
        siguiente = cmd[len(prefix)]
        if prefix.rsplit(" ", 1)[-1].startswith("-"):
            return True                       # agrupación de banderas: -rf ⊂ -rfv
        return not (siguiente.isalnum() or siguiente in "_-")
    return fnmatch.fnmatch(cmd, pattern)


# ── compilación ──────────────────────────────────────────────────────────────────────
def compile_for(policy: Policy, spec) -> dict:
    """Compila la política al runtime de `spec`. Delegado al adapter, que es quien sabe."""
    out = spec.compile_policy(policy)
    out.setdefault("supported", False)
    out.setdefault("artifacts", {})
    out.setdefault("unenforceable", [])
    out.setdefault("notes", [])
    return out
