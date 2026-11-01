# -*- coding: utf-8 -*-
"""`external_never`: lo que no se escribe fuera del espacio ni estando declarado.

Qué defecto cierra, y cómo se midió
-----------------------------------
Hasta el 2026-10-31, `decide_write` resolvía así una ruta fuera del espacio
(`core/policy.py`, rama `except ValueError`): si `external_allows()` casaba, devolvía
`_revisar_contenido(...)` **ahí mismo**. El bloque de `protected_paths` / `authority_paths`
vive después y sólo se alcanza para rutas DENTRO del espacio. Consecuencia medida con
`external_write_allow = ["/**"]`: **9 de 9** objetivos salían `allow`, incluidos
`~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.codex/config.toml` —donde vive el gancho que
gobierna al agente— y el `.harness/policy.json` de OTRO espacio.

Lo único que seguía en pie era la guardia de secretos por CONTENIDO: escribir algo con
forma de `AKIA…` se bloqueaba, pero sobrescribir una clave privada con texto cualquiera no.

Por qué no bastaba con invertir el orden: el orden era intencional. `**/.claude/**` está en
`protected_paths` y la memoria del agente vive en `~/.claude/projects/*/memory/**`; la
excepción existe justamente para ganarle. Hacía falta una tercera lista —ni protegido ni
excepción— que `external_write_allow` no pueda levantar. Eso es `external_never`.

Estas pruebas son adversariales: no comprueban que el camino bueno funcione, sino que la
concesión más amplia que la política admite (`/**`) **no** alcanza lo que nunca debe tocarse.
"""

from __future__ import annotations

import unittest

from core.policy import (
    ALLOW,
    DENY,
    HerenciaIrresoluble,
    Policy,
    decide_command,
    decide_write,
)
from tests.fixtures import Workspace

#: La concesión más amplia expresable. Si algo sobrevive a esto, sobrevive a todo.
TODO = ("/**",)


class NuncaFueraDelEspacio(unittest.TestCase):
    """Una familia por cada cosa que la raíz abierta NO debe alcanzar."""

    def _decidir(self, ws, relativa_al_home: str, contenido: str = "x"):
        objetivo = ws.home / relativa_al_home
        objetivo.parent.mkdir(parents=True, exist_ok=True)
        pol = Policy(external_write_allow=TODO)
        return decide_write(pol, ws.root, str(objetivo), contenido)

    def test_A_la_clave_privada_de_ssh_no_se_sobrescribe(self):
        """El contenido es inocuo a propósito: la guardia de secretos mira lo que se ESCRIBE,
        y aquí lo que importa es el destino. Sin `external_never` esto salía `allow`."""
        with Workspace() as ws:
            d = self._decidir(ws, ".ssh/id_rsa", contenido="texto cualquiera")
            self.assertEqual(DENY, d.outcome, f"regla={d.rule!r} motivo={d.reason!r}")

    def test_B_las_credenciales_de_aws_no_se_sobrescriben(self):
        with Workspace() as ws:
            d = self._decidir(ws, ".aws/credentials")
            self.assertEqual(DENY, d.outcome, f"regla={d.rule!r}")

    def test_C_el_agente_no_desengancha_su_propio_guardian(self):
        """`~/.codex/config.toml` lleva el `trusted_hash` del gancho `pre_tool_use`. Si el
        agente puede escribirlo, puede quitarse el vigilante y seguir operando."""
        with Workspace() as ws:
            d = self._decidir(ws, ".codex/config.toml")
            self.assertEqual(DENY, d.outcome, f"regla={d.rule!r}")

    def test_D_no_se_reescriben_los_ajustes_de_claude_code(self):
        with Workspace() as ws:
            d = self._decidir(ws, ".claude/settings.json")
            self.assertEqual(DENY, d.outcome, f"regla={d.rule!r}")

    def test_E_no_se_reescribe_el_gobierno_de_otro_espacio(self):
        """El guardián del espacio ACTIVO no protege los demás: su `protected_paths` se
        compara contra su propio árbol. Fuera, el único que queda es `external_never`."""
        with Workspace() as ws:
            d = self._decidir(ws, "otro-espacio/.harness/policy.json")
            self.assertEqual(DENY, d.outcome, f"regla={d.rule!r}")

    def test_F_no_se_reescribe_el_binario_del_guardian_ajeno(self):
        with Workspace() as ws:
            d = self._decidir(ws, "otro-espacio/.harness/bin/guard")
            self.assertEqual(DENY, d.outcome, f"regla={d.rule!r}")

    def test_G_no_se_reescribe_la_evidencia_de_otro_espacio(self):
        """Reescribir el diario ajeno es borrar el rastro de lo que se hizo allí."""
        with Workspace() as ws:
            d = self._decidir(ws, "otro-espacio/.harness/evidence/ledger.jsonl")
            self.assertEqual(DENY, d.outcome, f"regla={d.rule!r}")

    def test_H2_la_configuracion_del_sistema_no_se_escribe(self):
        """En macOS `/etc` es un enlace a `/private/etc` y `decide_write` resuelve con
        `realpath` (`core/policy.py`), así que el objetivo llega como `/private/etc/...` y
        un patrón `/etc/**` no casa NUNCA. Es la misma trampa que el módulo ya documentaba
        para `/tmp` y `/private/tmp`, y la cazó `T21` escribiendo en `sudoers`."""
        pol = Policy(external_write_allow=TODO)
        d = decide_write(pol, __import__("pathlib").Path("/tmp"), "/etc/sudoers", "all")
        self.assertEqual(DENY, d.outcome, f"regla={d.rule!r}")

    def test_H_un_env_cualquiera_sigue_protegido(self):
        with Workspace() as ws:
            d = self._decidir(ws, "proyecto/.env")
            self.assertEqual(DENY, d.outcome, f"regla={d.rule!r}")


class LoQueSiSigueAbierto(unittest.TestCase):
    """El control negativo. Sin esto, `external_never` podría estar cerrándolo TODO y las
    ocho pruebas de arriba pasarían por el motivo equivocado."""

    def _decidir(self, ws, relativa_al_home: str):
        objetivo = ws.home / relativa_al_home
        objetivo.parent.mkdir(parents=True, exist_ok=True)
        pol = Policy(external_write_allow=TODO)
        return decide_write(pol, ws.root, str(objetivo), "contenido corriente")

    def test_I_un_fichero_de_trabajo_cualquiera_se_escribe(self):
        with Workspace() as ws:
            d = self._decidir(ws, "Documents/Github/otro/src/x.ts")
            self.assertEqual(ALLOW, d.outcome, f"regla={d.rule!r} motivo={d.reason!r}")

    def test_J_la_memoria_del_agente_sigue_escribible(self):
        """Es el caso para el que `external_write_allow` existe. `**/.claude/**` está en
        `protected_paths`, así que si `external_never` se hubiera escrito con esa brocha,
        el agente perdería su memoria — el arreglo habría roto lo que venía a preservar."""
        with Workspace() as ws:
            d = self._decidir(ws, ".claude/projects/un-espacio/memory/nota.md")
            self.assertEqual(ALLOW, d.outcome, f"regla={d.rule!r} motivo={d.reason!r}")


class LaPosturaPorDefecto(unittest.TestCase):
    """Qué puede un agente fuera de su espacio SIN que nadie declare nada.

    El 2026-10-31 el operador decidió que Codex y Claude Code trabajaran entre repositorios.
    Eso no se podía conceder desde la política de un espacio —`external_write_allow` es
    REDUCE y añadir una raíz da `HerenciaIrresoluble`—, así que la postura cambió en la
    constante del motor, que es donde vive la raíz de confianza. Estas dos pruebas fijan el
    canje exacto: se abrió el disco de trabajo, no las credenciales.
    """

    def test_L_se_escribe_en_un_repositorio_hermano(self):
        with Workspace() as ws:
            objetivo = ws.home / "Documents" / "Github" / "otro" / "src" / "x.ts"
            objetivo.parent.mkdir(parents=True, exist_ok=True)
            d = decide_write(Policy(), ws.root, str(objetivo), "const a = 1;")
            self.assertEqual(ALLOW, d.outcome, f"regla={d.rule!r} motivo={d.reason!r}")

    def test_M_pero_no_en_la_clave_privada(self):
        """Se afirma también la REGLA, no sólo el veredicto: mientras el default era
        restrictivo esto ya daba `deny`, pero por «fuera-del-espacio». Si la prueba mirara
        sólo el `outcome`, seguiría verde aunque el canje se hubiera hecho mal."""
        with Workspace() as ws:
            objetivo = ws.home / ".ssh" / "id_rsa"
            objetivo.parent.mkdir(parents=True, exist_ok=True)
            d = decide_write(Policy(), ws.root, str(objetivo), "texto cualquiera")
            self.assertEqual(DENY, d.outcome)
            self.assertIn(".ssh", d.rule,
                          f"denegada, pero no por `external_never`: regla={d.rule!r}")


class UnHijoNoLaRetira(unittest.TestCase):
    """`external_never` no sirve de nada si el espacio gobernado puede vaciarla."""

    def test_K_vaciar_external_never_en_el_hijo_no_abre_la_clave(self):
        """Dos desenlaces son correctos y la prueba acepta los dos: que la política se
        rechace por relajar la norma, o que se cargue y el efectivo conserve la protección.
        Lo que NO puede pasar es que la escritura salga `allow`."""
        import json

        with Workspace() as ws:
            base = ws.root / ".harness"
            base.mkdir(parents=True, exist_ok=True)
            padre = base / "padre.json"
            padre.write_text(json.dumps({
                "schema": "harness.policy/v1", "name": "padre", "version": "1",
            }), encoding="utf-8")
            hijo = base / "policy.json"
            hijo.write_text(json.dumps({
                "schema": "harness.policy/v1", "name": "hijo", "version": "1",
                "extends": "padre.json",
                "external_never": [],
            }), encoding="utf-8")

            objetivo = ws.home / ".ssh" / "id_rsa"
            objetivo.parent.mkdir(parents=True, exist_ok=True)
            try:
                pol = Policy.load(hijo)
            except HerenciaIrresoluble:
                return  # rechazada por relajar: la protección no se pudo retirar
            # Cualquier OTRA excepción es un defecto, no una defensa. Capturarlas todas
            # hacía esta prueba vacua: pasaba con un `RuntimeError` de configuración
            # —`external_never` sin regla de monotonía— que no protegía nada.
            d = decide_write(pol, ws.root, str(objetivo), "texto cualquiera")
            self.assertEqual(DENY, d.outcome,
                             f"un hijo vació `external_never` y la clave quedó escribible; "
                             f"regla={d.rule!r}")


class ElCanalDeOrdenes(unittest.TestCase):
    """Una protección de escritura que sólo mira `Write` se rodea con `>` el primer día.

    Cada prueba lleva su CONTROL PORTANTE: se neutraliza `external_never` en memoria —sin
    tocar el fichero— y se comprueba que entonces la orden SÍ pasaría. Sin eso, estas
    pruebas podrían estar verdes porque la orden se deniega por otro motivo cualquiera, y
    el día que alguien rompa `external_never` seguirían verdes.
    """

    def _ambos(self, ws, orden: str):
        """Se abre `external_write_allow` a `/**` en LAS DOS políticas a propósito. Con el
        default —raíces concretas— la orden se denegaría por «fuera-del-espacio» y el
        control portante no mediría `external_never` sino la postura por defecto."""
        import dataclasses
        abierta = dataclasses.replace(Policy(), external_write_allow=TODO)
        duro = decide_command(abierta, orden, ws.root)
        sin_lista = decide_command(
            dataclasses.replace(abierta, external_never=()), orden, ws.root)
        return duro, sin_lista

    def test_N_una_redireccion_no_alcanza_la_configuracion_de_ssh(self):
        """El objetivo es `~/.ssh/config`, no `id_rsa`, y la diferencia es el hallazgo:
        `id_rsa` ya se denegaba por `**/id_rsa`, que nombra FICHEROS de credencial. Medido
        el 2026-10-31, esa lista dejaba `~/.ssh/config` y `~/.ssh/id_rsa.bak` en `allow` —y
        quien escribe el `config` añade un `ProxyCommand` y no necesita la clave—. Por eso
        `external_never` cierra el DIRECTORIO (`**/.ssh/**`) y no una lista de nombres."""
        with Workspace() as ws:
            (ws.home / ".ssh").mkdir(parents=True, exist_ok=True)
            duro, sin_lista = self._ambos(ws, f"echo x > {ws.home}/.ssh/config")
            self.assertEqual(DENY, duro.outcome, f"regla={duro.rule!r}")
            self.assertEqual(ALLOW, sin_lista.outcome,
                             "sin `external_never` la orden también se deniega: esta prueba "
                             "no está midiendo `external_never` sino otra cosa")

    def test_O_un_cp_no_desengancha_el_guardian_del_runtime(self):
        with Workspace() as ws:
            (ws.home / ".codex").mkdir(parents=True, exist_ok=True)
            duro, sin_lista = self._ambos(ws, f"cp /etc/hosts {ws.home}/.codex/config.toml")
            self.assertEqual(DENY, duro.outcome, f"regla={duro.rule!r}")
            self.assertEqual(ALLOW, sin_lista.outcome,
                             "sin `external_never` la orden también se deniega: la prueba "
                             "no es portante")


if __name__ == "__main__":
    unittest.main()
