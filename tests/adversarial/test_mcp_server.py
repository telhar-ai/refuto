# -*- coding: utf-8 -*-
"""La boca MCP de refuto no puede convertirse en una puerta trasera al arnés.

Por qué estas pruebas son adversariales y no de integración
----------------------------------------------------------
Un servidor MCP es una superficie que un MODELO invoca. Lo que hay que demostrar no es que
funcione —eso lo ve cualquiera en un cliente— sino que **no hace tres cosas**:

    1. ejecutar una orden arbitraria,
    2. escribir lo que gobierna,
    3. gastar dinero.

La primera es la clásica. Las otras dos son propias de este producto: un agente que pudiera
lanzar `upgrade --apply` o `policy unwire` sobre su propio espacio estaría modificando al juez
que lo evalúa, que es la regla de la que se deriva todo lo demás. Y `--deep` envía un prompt de
pago, así que exponerlo sería dejar que un agente facture en bucle sin decirlo.

La mitad positiva está aquí también, y sin ella lo anterior se satisface con un servidor que
rechaza todo: el cliente de refuto tiene que poder interrogarlo y obtener los siete nombres, su
revisión de protocolo y su identidad.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

from core.mcp import LEGACY_PROTOCOL_VERSION, PROTOCOL_VERSION
from core.mcp_server import (HERRAMIENTAS, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND,
                             _argv_de, catalogo, invocar, responder, serve)
from core.model import STATUSES

REPO = Path(__file__).resolve().parents[2]

#: Todo lo que, si apareciera en un `argv` construido por esta superficie, sería un defecto de
#: seguridad y no una molestia. Se enumera aquí y no sólo en el módulo para que la prueba falle
#: si alguien relaja la lista del módulo.
PROHIBIDO = ("--apply", "--force", "--deep", "--execute",
             "wire", "unwire", "install", "init", "chat", "run")


class TestNoEjecutaOrdenesArbitrarias(unittest.TestCase):
    def test_ninguna_herramienta_construye_una_bandera_de_escritura(self):
        """Sobre el `argv` COMPLETO de las siete, no sobre los argumentos de entrada."""
        for h in HERRAMIENTAS:
            argv = _argv_de(h["name"], {}, raiz=REPO)
            with self.subTest(herramienta=h["name"]):
                colision = [p for p in PROHIBIDO if p in argv]
                self.assertEqual([], colision, f"{h['name']} construye {colision}: {argv}")

    def test_el_modelo_no_puede_colar_una_bandera(self):
        for basura in ({"workspace": str(REPO), "apply": True},
                       {"workspace": str(REPO), "deep": True},
                       {"extra": "--apply"},
                       {"workspace": str(REPO), "gate": "G-POLICY; rm -rf /"},
                       {"workspace": str(REPO), "gate": "--apply"}):
            with self.subTest(args=basura), self.assertRaises(ValueError):
                _argv_de("refuto_verify", basura, raiz=REPO)

    def test_un_espacio_inexistente_se_rechaza(self):
        with self.assertRaises(ValueError):
            _argv_de("refuto_doctor", {"workspace": "/no/existe/este/espacio"}, raiz=REPO)

    def test_el_espacio_tiene_que_ser_una_cadena(self):
        with self.assertRaises(ValueError):
            _argv_de("refuto_doctor", {"workspace": 42}, raiz=REPO)

    def test_no_se_expone_ninguna_orden_mutadora(self):
        """El catálogo entero, contrastado contra los verbos que escriben."""
        expuestos = {h["argv"][0] for h in HERRAMIENTAS}
        mutadores = {"install", "init", "bind", "chat", "run", "resume", "policy", "lock",
                     "memory", "docs"}
        self.assertEqual(set(), expuestos & mutadores,
                         f"se expone un verbo que escribe: {expuestos & mutadores}")

    def test_upgrade_se_expone_solo_como_plan(self):
        argv = _argv_de("refuto_upgrade_plan", {}, raiz=REPO)
        self.assertIn("upgrade", argv)
        self.assertNotIn("--apply", argv)


class TestElCatalogoEsHonesto(unittest.TestCase):
    def test_siete_herramientas_con_esquema_cerrado(self):
        cat = catalogo()
        self.assertEqual(len(HERRAMIENTAS), len(cat))
        for t in cat:
            with self.subTest(herramienta=t["name"]):
                self.assertTrue(t["description"].strip(), "una herramienta sin descripción no "
                                                          "la puede elegir un modelo")
                esquema = t["inputSchema"]
                self.assertFalse(esquema["additionalProperties"],
                                 "un esquema abierto deja pasar argumentos no validados")
                self.assertIn("workspace", esquema["properties"])

    def test_los_nombres_no_colisionan(self):
        nombres = [t["name"] for t in catalogo()]
        self.assertEqual(sorted(set(nombres)), sorted(nombres))


class TestIsErrorEsDelProtocoloNoDelVeredicto(unittest.TestCase):
    """Un `verify` que devuelve FAIL es una llamada que FUNCIONÓ.

    Marcarla `isError` haría que el cliente la tratara como un fallo del servidor y, según el
    cliente, la reintentara o la ocultara. Es el mismo error que colapsar «no se pudo comprobar»
    sobre «falló» en un código de salida: se pierde la distinción que el producto mantiene.
    """

    def test_un_veredicto_negativo_no_es_un_error_de_protocolo(self):
        res = invocar("refuto_status", {"workspace": str(REPO)}, raiz=REPO)
        self.assertFalse(res["isError"])
        self.assertIn(res["structuredContent"]["status"], STATUSES)

    def test_el_resultado_lleva_el_sobre_entero(self):
        res = invocar("refuto_status", {"workspace": str(REPO)}, raiz=REPO)
        sobre = res["structuredContent"]
        self.assertEqual("harness.envelope/v1", sobre["schema"])
        for clave in ("command", "status", "exit", "workspace", "provenance", "payload", "next"):
            self.assertIn(clave, sobre)

    def test_el_texto_para_el_modelo_dice_el_estado_y_el_turno(self):
        res = invocar("refuto_status", {"workspace": str(REPO)}, raiz=REPO)
        texto = res["content"][0]["text"]
        self.assertIn(res["structuredContent"]["status"], texto)


class TestElProtocoloRespondeLoQueLaEspecificacionPide(unittest.TestCase):
    def _responder(self, metodo, params=None, ident=1):
        return responder({"jsonrpc": "2.0", "id": ident, "method": metodo,
                          "params": params or {}}, raiz=REPO)

    def test_discover_declara_las_dos_revisiones_y_su_identidad(self):
        """Las claves son las que lee el cliente de refuto, medido: `supportedVersions`.

        La primera versión emitía `protocolVersions` y un `serverInfo` suelto. El cliente lo
        alcanzaba y listaba las siete herramientas, y devolvía `protocol_versions: []` y
        `server_info: {}` — un servidor que responde y del que no se puede afirmar qué revisión
        habla. Se corrigió contra `docs/research/mcp.md`, que documenta la forma.
        """
        r = self._responder("server/discover")["result"]
        self.assertEqual([PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION], r["supportedVersions"])
        self.assertEqual("refuto",
                         r["_meta"]["io.modelcontextprotocol/serverInfo"]["name"])
        self.assertEqual("complete", r["resultType"])

    def test_initialize_acuerda_la_version_que_el_cliente_pide(self):
        r = self._responder("initialize",
                            {"protocolVersion": LEGACY_PROTOCOL_VERSION})["result"]
        self.assertEqual(LEGACY_PROTOCOL_VERSION, r["protocolVersion"])

    def test_una_version_desconocida_no_se_afirma_soportada(self):
        r = self._responder("initialize", {"protocolVersion": "1999-01-01"})["result"]
        self.assertNotEqual("1999-01-01", r["protocolVersion"])

    def test_una_notificacion_no_lleva_respuesta(self):
        self.assertIsNone(responder({"jsonrpc": "2.0", "method": "notifications/initialized"},
                                    raiz=REPO))

    def test_una_herramienta_inexistente_es_metodo_no_encontrado(self):
        r = responder({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                       "params": {"name": "refuto_borra_todo"}}, raiz=REPO)
        self.assertEqual(METHOD_NOT_FOUND, r["error"]["code"])

    def test_un_argumento_invalido_es_parametros_invalidos(self):
        r = responder({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                       "params": {"name": "refuto_verify",
                                  "arguments": {"gate": "no-es-una-puerta"}}}, raiz=REPO)
        self.assertEqual(INVALID_PARAMS, r["error"]["code"])

    def test_un_mensaje_que_no_es_jsonrpc_se_rechaza(self):
        r = responder({"method": "tools/list", "id": 1}, raiz=REPO)
        self.assertEqual(INVALID_REQUEST, r["error"]["code"])

    def test_un_metodo_desconocido_no_se_atiende_en_silencio(self):
        r = self._responder("resources/list")
        self.assertEqual(METHOD_NOT_FOUND, r["error"]["code"])


class TestElBucleNoSeCaeYStdoutEsSoloProtocolo(unittest.TestCase):
    def _servir(self, lineas: str) -> list:
        salida = io.StringIO()
        serve(REPO, entrada=io.StringIO(lineas), salida=salida)
        return [json.loads(l) for l in salida.getvalue().splitlines() if l.strip()]

    def test_una_linea_ilegible_no_mata_al_servidor(self):
        """Un servidor que muere ante el primer mensaje malo obliga al cliente a distinguir
        «se cerró» de «no entendió», y no puede: lo que ve es un descriptor cerrado."""
        salidas = self._servir(
            "esto no es json\n"
            + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}) + "\n")
        self.assertEqual(2, len(salidas), "el servidor dejó de atender tras la línea mala")
        self.assertEqual(-32700, salidas[0]["error"]["code"])
        self.assertEqual(len(HERRAMIENTAS), len(salidas[1]["result"]["tools"]))

    def test_todo_lo_que_sale_por_stdout_es_jsonrpc(self):
        salida = io.StringIO()
        serve(REPO, entrada=io.StringIO(
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "refuto_status",
                                   "arguments": {"workspace": str(REPO)}}}) + "\n"),
            salida=salida)
        for linea in salida.getvalue().splitlines():
            if not linea.strip():
                continue
            doc = json.loads(linea)      # revienta si se colara texto humano
            self.assertEqual("2.0", doc["jsonrpc"])

    def test_una_linea_vacia_no_produce_respuesta(self):
        self.assertEqual([], self._servir("\n\n\n"))


class TestElClientePropioLoInterroga(unittest.TestCase):
    """La mitad positiva. Sin ella, todo lo anterior lo cumple un servidor que rechaza todo."""

    def test_interrogate_stdio_lo_alcanza_y_lee_las_siete(self):
        from core.mcp import interrogate_stdio

        rep = interrogate_stdio("refuto", {"command": sys.executable,
                                           "args": ["refuto.py", "mcp-serve"]},
                                cwd=str(REPO), timeout=90.0)
        self.assertTrue(rep.reachable, f"no se alcanzó: {rep.error}")
        self.assertEqual("server/discover", rep.discovery_method)
        self.assertEqual([PROTOCOL_VERSION, LEGACY_PROTOCOL_VERSION], rep.protocol_versions)
        self.assertEqual("refuto", (rep.server_info or {}).get("name"))
        self.assertEqual(sorted(h["name"] for h in HERRAMIENTAS), sorted(rep.tools))


if __name__ == "__main__":
    unittest.main()
