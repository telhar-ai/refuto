# -*- coding: utf-8 -*-
"""Firma Ed25519 y un concordia FALSO, sólo para las pruebas.

Aquí, y no en `core/`: refuto no firma nada (`core/ed25519.py` sólo verifica). Estas piezas
existen para poder fabricar certificados genuinos y adversariales con claves SINTÉTICAS y
comprobar que `core.concordia` sólo acepta los genuinos.

La firma se contrasta contra la referencia de dos formas (`tests/unit/test_ed25519.py`): el vector
RFC 8032 §7.1 TEST 1 y la REGENERACIÓN byte a byte de las firmas del vector 01 de concordia desde
la semilla de `testkit.rs` (`secret_i = SHA-256(seed:u64 BE ‖ i:u16 BE)`, `seed = 0x5EED_0001`).
Si esto firma igual que `ed25519-dalek`, la verificación de `core.ed25519` está contrastada por
las dos puntas.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from core import concordia as C
from core import ed25519 as E

VECTOR_SEED = 0x5EED_0001


def clave_publica(secret: bytes) -> bytes:
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return E.encode_point(E._mul(a, E.BASE))


def firmar(secret: bytes, mensaje: bytes) -> bytes:
    """RFC 8032 §5.1.6."""
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pk = E.encode_point(E._mul(a, E.BASE))
    r = int.from_bytes(hashlib.sha512(prefix + mensaje).digest(), "little") % E.L
    R = E.encode_point(E._mul(r, E.BASE))
    k = int.from_bytes(hashlib.sha512(R + pk + mensaje).digest(), "little") % E.L
    s = (r + k * a) % E.L
    return R + s.to_bytes(32, "little")


def secreto_sintetico(seed: int, i: int) -> bytes:
    return hashlib.sha256(seed.to_bytes(8, "big") + i.to_bytes(2, "big")).digest()


def membresia_sintetica(*, n: int = 4, red: str = "test-net", epoch: int = 1, seed: int = VECTOR_SEED,
                        prefijo: str = "member-") -> tuple:
    """`(export, secretos)`: el export EXACTO de `hicon membership --export` para esas claves, y los
    secretos por índice. `member-0000…` ordena igual por bytes que por índice."""
    secretos = [secreto_sintetico(seed, i) for i in range(n)]
    miembros = sorted(((f"{prefijo}{i:04d}", clave_publica(s)) for i, s in enumerate(secretos)),
                      key=lambda t: t[0].encode("utf-8"))
    ms = C.Membresia(hashlib.sha256(red.encode("utf-8")).digest(), epoch, miembros)
    export = {
        "protocol_version": C.PROTOCOL_VERSION,
        "network_id": ms.network.hex(),
        "membership_version": epoch,
        "members": [{"index": i, "member_id": mid, "public_key_hex": pk.hex()} for i, (mid, pk) in enumerate(miembros)],
        "quorum_rule": {"n": ms.n, "f": ms.f, "q": ms.q, "formula": C.QUORUM_FORMULA},
        "membership_digest": ms.digest,
    }
    return export, secretos


def certificar(export: dict, secretos: list, *, seq: int, carga: bytes, prev: bytes | None = None,
               firmantes: list | None = None, con_carga: bool = True) -> dict:
    """Una `EntryCertificate` genuina para `carga` (ya con `client_id‖nonce` delante si procede)."""
    ms = C.reconstruir_membresia(export)
    prev = prev if prev is not None else bytes(32)
    pd = hashlib.sha256(carga).digest()
    firmantes = list(range(ms.q)) if firmantes is None else firmantes
    ats = []
    for i in firmantes:
        msg = C.sujeto(ms.network, ms.epoch, i, seq, pd, prev, bytes.fromhex(ms.digest))
        ats.append({"replica": i, "member_id": ms.members[i][0],
                    "signature_b64": base64.b64encode(firmar(secretos[i], msg)).decode("ascii")})
    e = {
        "protocol_version": C.PROTOCOL_VERSION,
        "network_id": ms.network.hex(),
        "membership_version": ms.epoch,
        "membership_digest": ms.digest,
        "seq": seq,
        "payload_digest": pd.hex(),
        "prev_entry_digest": prev.hex(),
        "entry_digest": C.entry_digest(prev, pd),
        "attestations": ats,
    }
    if con_carga:
        e["payload_b64"] = base64.b64encode(carga).decode("ascii")
    return e


class ConcordiaFalso:
    """Un clúster de mentira en un hilo: `GET /v1/membership`, `POST /v1/order`, `GET /v1/log`.

    `modo` cambia el comportamiento para las pruebas adversariales:
        normal              ordena, ejecuta y certifica con `q` firmas genuinas
        caido               no arranca (la URL no contesta)
        lento               duerme más que el plazo del cliente
        goteo               sirve `/v1/log` byte a byte, con pausas MENORES que el plazo: cada
                            byte reinicia el temporizador del socket, así que un plazo por
                            petición nunca vence. Es el ataque que midió el 2026-09-28 que
                            `timeout_s` no acotaba nada (34,4 s declarando 2 s)
        vacio               responde 200 con cuerpo vacío
        basura              responde 200 con bytes que no son JSON
        parcial             sirve la entrada con q−1 atestaciones (certificado incompleto)
        sin_quorum          igual que parcial pero en TODAS las réplicas (sólo hay una)
        firma_rota          una de las q firmas con un bit cambiado
        firmante_ajeno      una atestación de una clave que no está en la membresía
        duplicado           q−1 genuinas + una repetida
        otra_membresia      sirve otra membresía (coherente) y firma con ella
        membresia_manipulada  export con una clave sustituida y el digest original
        carga_distinta      certifica OTRA carga (payload_digest distinto del pedido)
        no_ordena           acepta pero nunca aparece en el log
        acepta_pero_502     `/v1/order` responde 502
        replay              sirve una entrada de una época anterior (nonce viejo) como si fuera la nueva
        campo_extra         añade un campo desconocido a la entrada
        payload_ajeno       payload_b64 que no casa con payload_digest
    """

    def __init__(self, export: dict, secretos: list, *, modo: str = "normal", ajena: tuple | None = None,
                 comparte_log_con: "ConcordiaFalso | None" = None, pausa: float = 0.2):
        self.export, self.secretos, self.modo = export, secretos, modo
        self.pausa = pausa           # segundos por byte en modo `goteo`
        self.ajena = ajena           # (export, secretos) de otra membresía
        # Dos réplicas falsas del MISMO clúster comparten log y tabla de peticiones (el consenso
        # real hace que todas ejecuten lo mismo); lo que cambia por réplica es cómo lo SIRVEN.
        if comparte_log_con is not None:
            self.log = comparte_log_con.log
            self.peticiones = comparte_log_con.peticiones
            self._lock = comparte_log_con._lock
        else:
            self.log = []            # entradas ya certificadas, por seq
            self.peticiones = []
            self._lock = threading.Lock()
        self._srv = None
        self._hilo = None
        self.url = ""

    # ── servidor ────────────────────────────────────────────────────────────────────
    def __enter__(self):
        if self.modo == "caido":
            self.url = "http://127.0.0.1:9"    # puerto discard: nadie escucha
            return self
        padre = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):        # silencio
                pass

            def _enviar(self, codigo: int, cuerpo: bytes, goteo: bool = False):
                self.send_response(codigo)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(cuerpo)))
                self.end_headers()
                if not goteo:
                    return self.wfile.write(cuerpo)
                import time as _t
                for i in range(len(cuerpo)):
                    try:
                        self.wfile.write(cuerpo[i:i + 1])
                        self.wfile.flush()
                    except OSError:
                        return          # el cliente cortó: es justo lo que la prueba espera
                    _t.sleep(padre.pausa)

            def do_GET(self):
                if padre.modo == "lento":
                    import time
                    time.sleep(3)
                if padre.modo == "vacio":
                    return self._enviar(200, b"")
                if padre.modo == "basura":
                    return self._enviar(200, b"\xff\xfe no soy json {")
                u = urlparse(self.path)
                if u.path == "/v1/membership":
                    return self._enviar(200, json.dumps(padre.membresia_servida()).encode())
                if u.path == "/v1/log":
                    q = parse_qs(u.query)
                    desde = int(q.get("from", ["1"])[0])
                    entradas = [padre.entrada_servida(e) for e in padre.log if e["seq"] >= desde]
                    return self._enviar(200, json.dumps({"contract": "telhar:v1:ordered-evidence-entry",
                                                         "last_executed": len(padre.log),
                                                         "entries": entradas}).encode(),
                                        goteo=padre.modo == "goteo")
                return self._enviar(404, b"{}")

            def do_POST(self):
                n = int(self.headers.get("content-length") or 0)
                cuerpo = self.rfile.read(n)
                if padre.modo == "acepta_pero_502":
                    return self._enviar(502, b"{}")
                try:
                    req = json.loads(cuerpo)
                    payload = base64.b64decode(req["payload_b64"])
                    accepted = padre.ordenar(int(req["client_id"]), int(req["nonce"]), payload)
                except (ValueError, KeyError, TypeError):
                    return self._enviar(400, b'{"error":"bad"}')
                return self._enviar(202, json.dumps({"accepted": accepted}).encode())

        # Con hilos y en modo demonio: una réplica en modo `goteo` que sigue escribiendo cuando el
        # cliente ya cortó bloqueaba el `shutdown()` del servidor de un solo hilo, y con él la
        # prueba entera. El estado compartido (`log`, `peticiones`) ya estaba bajo `self._lock`.
        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self._srv.daemon_threads = True
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}"
        self._hilo = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._hilo.start()
        return self

    def __exit__(self, *a):
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()

    # ── comportamiento ──────────────────────────────────────────────────────────────
    def membresia_servida(self) -> dict:
        if self.modo == "otra_membresia" and self.ajena:
            return self.ajena[0]
        if self.modo == "membresia_manipulada":
            t = json.loads(json.dumps(self.export))
            t["members"][0]["public_key_hex"] = "11" * 32
            return t
        return self.export

    def ordenar(self, client_id: int, nonce: int, payload: bytes) -> bool:
        with self._lock:
            self.peticiones.append((client_id, nonce, payload))
            if any(p[0] == client_id and p[1] == nonce for p in self.peticiones[:-1]):
                return False
            if self.modo == "no_ordena":
                return True
            carga = C.carga_ordenada(client_id, nonce, payload)
            if self.modo == "carga_distinta":
                carga = C.carga_ordenada(client_id, nonce, payload + b"!")
            seq = len(self.log) + 1
            prev = bytes.fromhex(self.log[-1]["entry_digest"]) if self.log else bytes(32)
            export, secretos = self.export, self.secretos
            if self.modo == "otra_membresia" and self.ajena:
                export, secretos = self.ajena
            ms = C.reconstruir_membresia(export)
            firmantes = list(range(ms.q))
            if self.modo in ("sin_quorum", "duplicado"):
                firmantes = list(range(ms.q - 1))
            e = certificar(export, secretos, seq=seq, carga=carga, prev=prev, firmantes=firmantes)
            if self.modo == "firma_rota":
                sig = bytearray(base64.b64decode(e["attestations"][0]["signature_b64"]))
                sig[7] ^= 0x10
                e["attestations"][0]["signature_b64"] = base64.b64encode(bytes(sig)).decode()
            if self.modo == "firmante_ajeno":
                ajeno = secreto_sintetico(0xBAD, 0)
                pd, prev_b, md = bytes.fromhex(e["payload_digest"]), prev, bytes.fromhex(ms.digest)
                msg = C.sujeto(ms.network, ms.epoch, ms.q - 1, seq, pd, prev_b, md)
                e["attestations"][-1]["signature_b64"] = base64.b64encode(firmar(ajeno, msg)).decode()
            if self.modo == "duplicado":
                e["attestations"].append(dict(e["attestations"][0]))
            if self.modo == "campo_extra":
                e["timestamp"] = "2026-09-27T00:00:00Z"
            if self.modo == "payload_ajeno":
                e["payload_b64"] = base64.b64encode(carga + b"x").decode()
            if self.modo == "replay" and self.log:
                # devuelve la PRIMERA entrada disfrazada: mismo payload_digest pedido, firmas viejas
                viejo = json.loads(json.dumps(self.log[0]))
                viejo["payload_digest"] = e["payload_digest"]
                e = viejo
            self.log.append(e)
            return True

    def entrada_servida(self, e: dict) -> dict:
        """Cómo ESTA réplica sirve una entrada del log común. `parcial`: le faltan atestaciones
        (llegaron fuera de su ventana, SPEC §8.6): sirve q−1."""
        if self.modo == "parcial":
            q = C.reconstruir_membresia(self.export).q
            return dict(e, attestations=e["attestations"][:q - 1])
        return e
