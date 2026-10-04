# -*- coding: utf-8 -*-
"""Ancla certificada del diario: el checkpoint de refuto ordenado y certificado por concordia.

El problema que cierra (medido el 2026-09-25, `tests/adversarial/test_ledger_ataques.py`)
--------------------------------------------------------------------------------------
Seis de los doce ataques al diario —reescribirlo coherente, sustituirlo por otro válido, truncar la
cola, cadena alternativa desde cero, rollback a una copia, vaciarlo— sólo se detectan **con un ancla
publicada fuera del árbol**, y `verificar_cadena(ws, esperado, eventos_minimos)` la aceptaba desde
C-02 sin que ninguna orden la produjera. Un ancla en un fichero del mismo `uid` la mueve el mismo
`uid`; un ancla en un servidor único traslada la confianza a su operador. Aquí el ancla es una
**entrada ordenada y certificada por `≥ q` réplicas de concordia** (`telhar:v1:ordered-evidence-entry`,
`ai/concordia/docs/CERTIFICATE-SPEC.md`), verificable OFFLINE con una membresía cuyo digest refuto
tiene **fijado fuera de banda** (el pin, §Pin).

Qué es un checkpoint (`refuto.checkpoint/v1`)
--------------------------------------------
    { schema, origin, size, root, engine_digest, policy_digest, membership_digest, run_id }

`root` es la cabeza `hₙ` del diario y `size` es `n`: **las dos mitades del ancla en un solo objeto**
(la lección de los transparency logs, `docs/research/sistemas-de-frontera.md §1`). `engine_digest` y
`policy_digest` atan `I6'` (FORMAL-MODEL §6.3) a terceros: si tocaron al juez, ningún checkpoint
posterior lleva la misma huella. `membership_digest` es el pin bajo el que se ancló: cambiar el pin
después deja todos los anclajes anteriores sin verificar, es decir, **visible**.

La frontera de confianza, en una línea
--------------------------------------
refuto NO se cree nada de lo que concordia le devuelve: ni un `200`, ni un `accepted: true`, ni un
JSON con forma de certificado. Lo único que cuenta es que **`≥ q` firmas Ed25519 de miembros
distintos de una membresía cuyo digest coincide con el pin** verifiquen, con `core.ed25519`, sobre el
sujeto de 140 bytes que refuto reconstruye desde la especificación, y que la carga certificada sea
byte a byte el checkpoint que refuto envió. Todo lo demás es transporte.

Estados (los de refuto, `core.model`; no se inventa ninguno)
-----------------------------------------------------------
    PASS            certificado válido bajo el pin y la carga es el checkpoint enviado
    FAIL            hay un HECHO en contra: membresía ≠ pin, firma inválida, quórum insuficiente,
                    carga distinta, digest que no casa, ancla que ya no está en el diario
    NOT_EXECUTABLE  se intentó y no se pudo: clúster caído, plazo vencido, respuesta ilegible o
                    incompleta en todas las réplicas. «No pude» no es «está bien»
    BLOCKED         falta una dependencia declarada: no hay pin, o no hay configuración de anclaje
    INCONCLUSIVE    el ancla existe pero no se puede establecer su relación con el diario actual
                    (ancla ilegible, checkpoint que no se puede decodificar, diario ausente)

El pin de membresía (§7 del encargo)
------------------------------------
- **Quién lo fija:** una persona, al instalar (`pinned_by`, `pinned_at`). Refuto no lo deduce nunca
  de lo que sirve el clúster: hacerlo sería aceptar la membresía de quien presenta el certificado.
- **Dónde vive:** `harness.manifest.json → anchoring.membership_digest`. El manifiesto es una ruta
  PROTEGIDA por la política (el guardián deniega escribirla al sujeto) y su esquema es cerrado.
- **Segunda fuente, opcional:** `--membership-digest` / `REFUTO_MEMBERSHIP_DIGEST`, para que CI o una
  persona lo aporte desde fuera del árbol. Si las dos fuentes discrepan → `FAIL`: dos autoridades
  que no coinciden no se resuelven eligiendo una.
- **Sin pin → `BLOCKED`, nunca PASS.** Y **no** se «corrige» tomando el digest que sirva concordia.
- **Límite declarado:** con `uid(S) = uid(J)` (FORMAL-MODEL §6.2) el pin del manifiesto es
  tamper-EVIDENTE, no tamper-proof: quien reescriba el manifiesto por fuera del guardián y a la vez
  controle un clúster falso obtiene anclas que verifican. Lo que queda visible es la discontinuidad:
  todos los anclajes anteriores dejan de verificar bajo el pin nuevo. La fuente externa (CI) es la
  que saca el pin de la autoridad del sujeto; el manifiesto solo no lo hace.

Lo que este módulo NO afirma (Límites de Confianza y Modelo Operativo)
----------------------------------------------------------------------
1. Refuto actúa exclusivamente como un CLIENTE NOTARIAL EXTERNO (External Notary Client).
   No implementa ni aloja el clúster de consenso Bizantino (BFT); consume certificados emitidos
   por una red notarial externa e independiente.
2. El mecanismo de despacho directo (`_DIRECT_SERVERS` / `socketpair()`) es estrictamente un
   mecanismo de transporte para pruebas unitarias y de integración en sandboxes del sistema
   operativo donde el binding/connect de sockets TCP loopback está restringido.
3. Las pruebas in-process con `socketpair()` NO constituyen tolerancia a fallos bizantinos (BFT)
   real: dentro del mismo espacio de direcciones y `uid`, la corrupción de memoria o la coacción
   de proceso no están aisladas. Las garantías BFT solo son reales cuando los nodos de concordia
   corren en procesos y máquinas físicamente independientes.
4. Nada sobre la hora (concordia no tiene reloj), nada sobre anclaje Merkle/Rekor (vestigium),
   nada sobre la durabilidad del log de concordia (declarada inexistente en SPEC §8.4: si todas las
   réplicas reinician, el certificado sigue verificando OFFLINE desde el ancla guardada, pero ya
   no se puede volver a pedir). El verificador sigue siendo el mismo `uid` que el sujeto: esto
   convierte la tamper-evidencia en verificable por terceros, no en prevención.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from pathlib import Path

from core import ed25519, regla_validez
from core.model import BLOCKED, FAIL, INCONCLUSIVE, NOT_EXECUTABLE, PASS, now

# Clasificaciones de estado de adaptadores externos (Section 19)
AVAILABLE = "AVAILABLE"
UNAVAILABLE = "UNAVAILABLE"
INVALID = "INVALID"
STALE = "STALE"
VALID = "VALID"

# ── Modo directo en proceso (transporte de pruebas cuando el sandbox del SO bloquea sockets loopback) ──
# ADVERTENCIA DE SEGURIDAD Y CONFIANZA: Este mecanismo existe exclusivamente para suites de prueba
# en entornos de sandbox herméticos. No ofrece aislamiento de proceso ni garantías de tolerancia
# bizantina a fallos (BFT). En producción, Refuto es cliente de un clúster notarial externo real.
_DIRECT_SERVERS: dict = {}

def registrar_servidor_directo(puerto: int, srv) -> None:
    _DIRECT_SERVERS[puerto] = srv

def desregistrar_servidor_directo(puerto: int) -> None:
    _DIRECT_SERVERS.pop(puerto, None)

try:
    from http.server import HTTPServer as _HTTPServer
    if not hasattr(_HTTPServer, "_refuto_direct_patched"):
        _orig_http_init = _HTTPServer.__init__
        _orig_http_close = _HTTPServer.server_close

        def _patched_http_init(self, server_address, RequestHandlerClass, bind_and_activate=True):
            _orig_http_init(self, server_address, RequestHandlerClass, bind_and_activate)
            if hasattr(self, "server_address") and self.server_address and len(self.server_address) == 2:
                host, port = self.server_address[0], self.server_address[1]
                if host in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):  # nosec B104
                    registrar_servidor_directo(port, self)

        def _patched_http_close(self):
            if hasattr(self, "server_address") and self.server_address and len(self.server_address) == 2:
                desregistrar_servidor_directo(self.server_address[1])
            _orig_http_close(self)

        _HTTPServer.__init__ = _patched_http_init
        _HTTPServer.server_close = _patched_http_close
        _HTTPServer._refuto_direct_patched = True
except Exception:
    pass

# ── constantes del contrato (CERTIFICATE-SPEC §2-§4) ────────────────────────────────────
PROTOCOL_VERSION = "concordia/pbft/v1"
DOMAIN = b"concordia/pbft/v1"                       # 17 bytes
MEMBERSHIP_DOMAIN = b"concordia/membership/v1"      # 23 bytes
ATTEST_TYPE = 9
QUORUM_FORMULA = ("f = floor((n-1)/3); q = floor((n+f)/2)+1; "
                  "certificate requires >= q distinct members")
ZERO32 = "00" * 32
_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{7,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: Claves que el contrato `telhar:v1:ordered-evidence-entry` admite (`additionalProperties: false`).
CAMPOS_ENTRADA = frozenset({"protocol_version", "network_id", "membership_version", "membership_digest",
                            "seq", "payload_digest", "prev_entry_digest", "entry_digest", "payload_b64",
                            "attestations"})
CAMPOS_ATESTACION = frozenset({"replica", "member_id", "signature_b64"})
CAMPOS_MEMBRESIA = frozenset({"protocol_version", "network_id", "membership_version", "members",
                              "quorum_rule", "membership_digest"})

#: Esquemas propios de refuto para lo que se guarda.
SCHEMA_CHECKPOINT = "refuto.checkpoint/v1"
SCHEMA_ANCLA = "refuto.anchor/v1"
#: `kind` del evento del diario que deja constancia del anclaje.
KIND_ANCLA = "evidence/anchor"
#: Dónde se guardan los anclajes, dentro de la evidencia y fuera del `glob("*.json")` de
#: `latest_verification`/`_hay_artefactos`, que no es recursivo.
DIR_ANCLAS = ("evidence", "anchors")

#: Variable de entorno por la que el invocador (CI, una persona) aporta el pin desde fuera del árbol.
ENV_PIN = "REFUTO_MEMBERSHIP_DIGEST"


class Invalido(Exception):
    """Un motivo de invalidez del contrato (§5) o del pin. `codigo` es la variante de la
    especificación (`BadMembership`, `WrongNetwork`, …) o `PinMismatch`/`PinMissing` (refuto)."""

    def __init__(self, codigo: str, detalle: str = ""):
        super().__init__(f"{codigo}" + (f": {detalle}" if detalle else ""))
        self.codigo = codigo
        self.detalle = detalle


class NoDisponible(Exception):
    """El clúster no contestó, tardó de más o contestó basura. Se intentó y no se pudo:
    `NOT_EXECUTABLE`, nunca PASS."""


# ── membresía ───────────────────────────────────────────────────────────────────────────
def quorum_de(n: int) -> tuple:
    """`f = ⌊(n−1)/3⌋`, `q = ⌊(n+f)/2⌋+1` (SPEC §2.4). Recomputado, nunca leído."""
    f = (n - 1) // 3
    return f, (n + f) // 2 + 1


def _hex32(valor, que: str) -> bytes:
    if not isinstance(valor, str) or not _HEX64.match(valor):
        raise Invalido("Malformed", f"{que}: no es hex de 32 bytes en minúsculas")
    return bytes.fromhex(valor)


class Membresia:
    """La membresía reconstruida y validada. Inmutable en la práctica: se construye o se rechaza."""

    __slots__ = ("network", "epoch", "members", "n", "f", "q", "digest")

    def __init__(self, network: bytes, epoch: int, members: list):
        self.network, self.epoch, self.members = network, epoch, members
        self.n = len(members)
        self.f, self.q = quorum_de(self.n)
        self.digest = hashlib.sha256(self.canonico()).hexdigest()

    def canonico(self) -> bytes:
        """Forma canónica (SPEC §2.2): inyectiva, big-endian, longitudes prefijadas."""
        out = bytearray(MEMBERSHIP_DOMAIN)
        out += self.network
        out += self.epoch.to_bytes(8, "big")
        out += self.n.to_bytes(2, "big") + self.f.to_bytes(2, "big") + self.q.to_bytes(2, "big")
        for member_id, pk in self.members:
            ident = member_id.encode("utf-8")
            out += len(ident).to_bytes(2, "big") + ident + pk
        return bytes(out)

    def miembro(self, indice) -> tuple | None:
        if isinstance(indice, bool) or not isinstance(indice, int) or indice < 0 or indice >= self.n:
            return None
        return self.members[indice]


def reconstruir_membresia(export: dict) -> Membresia:
    """`MembershipExport` → `Membresia`, o `Invalido("BadMembership", …)`. Nada se corrige.

    Las restricciones son las de SPEC §2.1, todas: `n ≥ 4`; `member_id` únicos y con la forma
    `^[A-Za-z][A-Za-z0-9-]{7,63}$`; claves únicas de 32 bytes; miembros en orden canónico (bytes
    del `member_id`) con `index == posición`; `quorum_rule` igual a la derivada de `n`;
    `membership_digest` igual al recomputado. Y los campos extra se rechazan: el contrato
    `telhar:v1:concordia-membership-export` es cerrado.
    """
    def mal(det: str):
        raise Invalido("BadMembership", det)

    if not isinstance(export, dict):
        mal("el export no es un objeto")
    extra = set(export) - CAMPOS_MEMBRESIA
    if extra:
        mal(f"campos fuera del contrato: {sorted(extra)}")
    if export.get("protocol_version") != PROTOCOL_VERSION:
        mal(f"protocol_version {export.get('protocol_version')!r} ≠ {PROTOCOL_VERSION}")
    try:
        network = _hex32(export.get("network_id"), "network_id")
    except Invalido as exc:
        mal(exc.detalle)
    epoch = export.get("membership_version")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0 or epoch >= 2**64:
        mal("membership_version no es un entero u64")
    members = export.get("members")
    if not isinstance(members, list):
        mal("members no es una lista")
    if len(members) < 4:
        mal(f"n={len(members)} < 4: f=0, no es tolerante a fallos")
    if len(members) > 65535:
        mal("n > u16::MAX")
    vistos_id: set = set()
    vistas_pk: set = set()
    lista: list = []
    for i, m in enumerate(members):
        if not isinstance(m, dict) or set(m) != {"index", "member_id", "public_key_hex"}:
            mal(f"miembro en posición {i}: forma incorrecta")
        if isinstance(m["index"], bool) or m["index"] != i:
            mal(f"miembro {m.get('member_id')!r} declara índice {m.get('index')!r} en posición {i}")
        mid = m["member_id"]
        if not isinstance(mid, str) or not _ID_RE.match(mid):
            mal(f"member_id {mid!r} no cumple ^[A-Za-z][A-Za-z0-9-]{{7,63}}$")
        if mid in vistos_id:
            mal(f"member_id duplicado: {mid}")
        pk_hex = m["public_key_hex"]
        if not isinstance(pk_hex, str) or not _HEX64.match(pk_hex):
            mal(f"clave de {mid}: no es hex de 32 bytes")
        pk = bytes.fromhex(pk_hex)
        if pk in vistas_pk:
            mal(f"clave pública duplicada en {mid}")
        vistos_id.add(mid)
        vistas_pk.add(pk)
        lista.append((mid, pk))
    orden = sorted(lista, key=lambda t: t[0].encode("utf-8"))
    if orden != lista:
        mal("los miembros no están en orden canónico (por bytes de member_id)")
    ms = Membresia(network, epoch, lista)
    regla = export.get("quorum_rule")
    derivada = {"n": ms.n, "f": ms.f, "q": ms.q, "formula": QUORUM_FORMULA}
    if regla != derivada:
        mal(f"quorum_rule publicada {regla!r} ≠ derivada {derivada!r}")
    if export.get("membership_digest") != ms.digest:
        mal(f"membership_digest publicado {str(export.get('membership_digest'))[:16]}… ≠ "
            f"recomputado {ms.digest[:16]}…")
    return ms


# ── sujeto y certificado ────────────────────────────────────────────────────────────────
def sujeto(network: bytes, epoch: int, replica: int, seq: int, payload_digest: bytes,
           prev: bytes, membership_digest: bytes) -> bytes:
    """Los 140 bytes que firma una réplica (SPEC §3). Construido desde la especificación, no
    desde el código de concordia; `tests/contract/test_concordia_vectores.py` lo contrasta."""
    ext = hashlib.sha256(prev + membership_digest).digest()
    return (DOMAIN + network + epoch.to_bytes(8, "big") + bytes([ATTEST_TYPE])
            + replica.to_bytes(2, "big") + (0).to_bytes(8, "big") + seq.to_bytes(8, "big")
            + payload_digest + ext)


def entry_digest(prev: bytes, payload_digest: bytes) -> str:
    return hashlib.sha256(prev + payload_digest).hexdigest()


def _u64(valor, que: str) -> int:
    if isinstance(valor, bool) or not isinstance(valor, int) or valor < 0 or valor >= 2**64:
        raise Invalido("Malformed", f"{que} no es un entero u64")
    return valor


def _b64(valor, que: str) -> bytes:
    if not isinstance(valor, str):
        raise Invalido("Malformed", f"{que} no es texto")
    try:
        return base64.b64decode(valor, validate=True)
    except (ValueError, TypeError) as exc:
        raise Invalido("Malformed", f"{que}: {exc}") from None


def verificar_certificado(export: dict, entry: dict, *, pin: str | None = None) -> dict:
    """Verificación OFFLINE (SPEC §5) más el pin de refuto. Sin red, sin reloj, sin secretos.

    Devuelve `{"valido": bool, "codigo", "motivo", "signers", "required", "rejected", "entry_digest"}`.
    `valido=True` sólo si: la membresía reconstruye (1), su digest coincide con `pin` (si se dio),
    y las comprobaciones 2–9 pasan con **conteo**: cada atestación que no cuenta queda en
    `rejected` con su motivo; hacen falta `≥ q` firmantes VÁLIDOS y DISTINTOS.

    Nunca lanza por la forma de la entrada: toda malformación es un `Malformed` en el resultado.
    """
    def invalido(codigo: str, detalle: str = "", **extra) -> dict:
        return {"valido": False, "codigo": codigo,
                "motivo": codigo + (f": {detalle}" if detalle else ""),
                "signers": [], "required": extra.get("required", 0),
                "rejected": extra.get("rejected", []), "entry_digest": ""}

    try:
        ms = reconstruir_membresia(export)
    except Invalido as exc:
        return invalido(exc.codigo, exc.detalle)
    if pin is not None and ms.digest != pin:
        return invalido("PinMismatch", f"la membresía servida tiene digest {ms.digest[:16]}… y el pin "
                                       f"fijado fuera de banda es {str(pin)[:16]}…: no es la membresía "
                                       f"en la que se confía")
    if not isinstance(entry, dict):
        return invalido("Malformed", "la entrada no es un objeto")
    extra = set(entry) - CAMPOS_ENTRADA
    if extra:
        return invalido("Malformed", f"campos fuera del contrato: {sorted(extra)}")
    faltan = (CAMPOS_ENTRADA - {"payload_b64"}) - set(entry)
    if faltan:
        return invalido("Malformed", f"faltan campos: {sorted(faltan)}")
    if entry["protocol_version"] != PROTOCOL_VERSION:
        return invalido("UnknownProtocol", repr(entry["protocol_version"]))
    try:
        network = _hex32(entry["network_id"], "network_id")
        if network != ms.network:
            return invalido("WrongNetwork")
        mdigest = _hex32(entry["membership_digest"], "membership_digest")
        epoch = _u64(entry["membership_version"], "membership_version")
        if epoch != ms.epoch or mdigest.hex() != ms.digest:
            return invalido("WrongMembership")
        payload_digest = _hex32(entry["payload_digest"], "payload_digest")
        prev = _hex32(entry["prev_entry_digest"], "prev_entry_digest")
        ed = _hex32(entry["entry_digest"], "entry_digest")
        seq = _u64(entry["seq"], "seq")
        if seq == 0:
            return invalido("Malformed", "seq debe ser ≥ 1")
        if seq == 1 and prev != bytes(32):
            return invalido("BrokenChain")
        if entry_digest(prev, payload_digest) != ed.hex():
            return invalido("BrokenChain")
        if "payload_b64" in entry and entry["payload_b64"] is not None:
            carga = _b64(entry["payload_b64"], "payload_b64")
            if hashlib.sha256(carga).digest() != payload_digest:
                return invalido("PayloadMismatch")
        atestaciones = entry["attestations"]
        if not isinstance(atestaciones, list):
            return invalido("Malformed", "attestations no es una lista")
    except Invalido as exc:
        return invalido(exc.codigo, exc.detalle)

    signers: list = []
    rejected: list = []
    for a in atestaciones:
        try:
            if not isinstance(a, dict) or set(a) != CAMPOS_ATESTACION:
                raise Invalido("Malformed", "atestación con forma incorrecta")
            replica = a["replica"]
            if isinstance(replica, bool) or not isinstance(replica, int):
                raise Invalido("Malformed", "replica no es entero")
            miembro = ms.miembro(replica)
            if miembro is None or miembro[0] != a["member_id"]:
                raise Invalido("UnknownMember", f"replica {replica} member_id {a['member_id']!r}")
            if replica in signers:
                raise Invalido("DuplicateSigner", f"replica {replica}")
            firma = _b64(a["signature_b64"], "signature_b64")
            if len(firma) != 64:
                raise Invalido("InvalidSignature", f"replica {replica}: {len(firma)} bytes")
            msg = sujeto(network, ms.epoch, replica, seq, payload_digest, prev, mdigest)
            if not ed25519.verify(miembro[1], msg, firma):
                raise Invalido("InvalidSignature", f"replica {replica}")
        except Invalido as exc:
            rejected.append(str(exc))
            continue
        signers.append(replica)
    if len(signers) < ms.q:
        return invalido("InsufficientQuorum", f"{len(signers)} firmante(s) válido(s) < q={ms.q}",
                        required=ms.q, rejected=rejected)
    return {"valido": True, "codigo": "VALID", "motivo": "", "signers": sorted(signers),
            "required": ms.q, "rejected": rejected, "entry_digest": ed.hex()}


def verificar_equivocacion(export: dict, proof: dict) -> dict:
    """SPEC §6: dos atestaciones del mismo miembro, misma red/membresía/seq, sujetos distintos, las
    dos válidas ⇒ equivocación DEMOSTRADA del índice devuelto."""
    def invalido(codigo: str, detalle: str = "") -> dict:
        return {"valido": False, "codigo": codigo, "motivo": codigo + (f": {detalle}" if detalle else ""),
                "culpable": None}

    try:
        ms = reconstruir_membresia(export)
    except Invalido as exc:
        return invalido(exc.codigo, exc.detalle)
    if not isinstance(proof, dict) or set(proof) != {"a", "b"}:
        return invalido("Malformed", "la prueba no tiene la forma {a, b}")
    a, b = proof["a"], proof["b"]
    campos = {"network_id", "membership_version", "membership_digest", "seq", "payload_digest",
              "prev_entry_digest", "attestation"}
    for s in (a, b):
        if not isinstance(s, dict) or set(s) != campos or not isinstance(s["attestation"], dict) \
                or set(s["attestation"]) != CAMPOS_ATESTACION:
            return invalido("Malformed", "sujeto atestado con forma incorrecta")
    if (a["attestation"]["replica"] != b["attestation"]["replica"] or a["seq"] != b["seq"]
            or a["membership_digest"] != b["membership_digest"] or a["network_id"] != b["network_id"]):
        return invalido("Malformed", "las dos atestaciones no son del mismo miembro, seq y membresía")
    if a["payload_digest"] == b["payload_digest"] and a["prev_entry_digest"] == b["prev_entry_digest"]:
        return invalido("Malformed", "las dos atestaciones dicen lo mismo: no hay equivocación")
    for s in (a, b):
        try:
            network = _hex32(s["network_id"], "network_id")
            if network != ms.network:
                return invalido("WrongNetwork")
            md = _hex32(s["membership_digest"], "membership_digest")
            if _u64(s["membership_version"], "membership_version") != ms.epoch or md.hex() != ms.digest:
                return invalido("WrongMembership")
            replica = s["attestation"]["replica"]
            miembro = ms.miembro(replica) if not isinstance(replica, bool) and isinstance(replica, int) else None
            if miembro is None:
                return invalido("UnknownMember", f"replica {replica!r}")
            firma = _b64(s["attestation"]["signature_b64"], "signature_b64")
            msg = sujeto(network, ms.epoch, replica, _u64(s["seq"], "seq"),
                         _hex32(s["payload_digest"], "payload_digest"),
                         _hex32(s["prev_entry_digest"], "prev_entry_digest"), md)
            if len(firma) != 64 or not ed25519.verify(miembro[1], msg, firma):
                return invalido("InvalidSignature", f"replica {replica}")
        except Invalido as exc:
            return invalido(exc.codigo, exc.detalle)
    return {"valido": True, "codigo": "EQUIVOCATION", "motivo": "", "culpable": a["attestation"]["replica"]}


# ── configuración y pin ─────────────────────────────────────────────────────────────────
def configuracion(manifest: dict | None) -> dict | None:
    """La sección `anchoring` del manifiesto, o `None` si el espacio no declara anclaje."""
    if not isinstance(manifest, dict):
        return None
    cfg = manifest.get("anchoring")
    return cfg if isinstance(cfg, dict) else None


def resolver_pin(cfg: dict | None, *, externo: str | None = None) -> dict:
    """De dónde sale el pin y si las fuentes coinciden.

    Devuelve `{"pin", "fuente", "estado", "motivo"}` con `fuente ∈ {manifiesto, invocador, ambas}`.
    `estado` es `PASS` si hay un pin fiable, `BLOCKED` si no hay ninguno, `FAIL` si las dos fuentes
    discrepan o alguna está malformada. El pin NUNCA se toma de lo que sirva el clúster.
    """
    del_manifiesto = (cfg or {}).get("membership_digest") if cfg else None
    fuentes = {}
    for nombre, valor in (("manifiesto", del_manifiesto), ("invocador", externo)):
        if valor is None or valor == "":
            continue
        if not isinstance(valor, str) or not _HEX64.match(valor):
            return {"pin": None, "fuente": nombre, "estado": FAIL,
                    "motivo": f"el pin de membresía del {nombre} no es hex de 32 bytes en minúsculas"}
        fuentes[nombre] = valor
    if not fuentes:
        return {"pin": None, "fuente": "", "estado": BLOCKED,
                "motivo": "no hay pin de membresía: ni `anchoring.membership_digest` en el manifiesto "
                          f"ni `{ENV_PIN}`/`--membership-digest`. Sin pin, cualquier membresía que "
                          "sirva el clúster sería aceptada, y eso es aceptar la del atacante"}
    if len(set(fuentes.values())) > 1:
        return {"pin": None, "fuente": "ambas", "estado": FAIL,
                "motivo": f"el manifiesto fija {fuentes['manifiesto'][:16]}… y el invocador "
                          f"{fuentes['invocador'][:16]}…: dos autoridades que no coinciden no se "
                          f"resuelven eligiendo una"}
    return {"pin": next(iter(fuentes.values())), "fuente": "ambas" if len(fuentes) == 2 else next(iter(fuentes)),
            "estado": PASS, "motivo": ""}


#: Hosts admitidos mientras el anclaje sea SÓLO LOCAL (previo a la publicación). Literales, sin
#: normalizar: exactamente los que admite el patrón de `schemas/manifest.schema.json`.
HOSTS_LOCALES = frozenset({"127.0.0.1", "localhost", "[::1]"})


def es_local(endpoint: str) -> bool:
    """`True` sólo si el endpoint es http(s) contra loopback. Cualquier otra cosa —otro host, otro
    esquema, una URL que no se puede analizar— es `False`: la duda no abre una conexión."""
    from urllib.parse import urlsplit
    try:
        u = urlsplit(endpoint)
    except ValueError:
        return False
    if u.scheme not in ("http", "https") or not u.hostname:
        return False
    # Sin normalizar mayúsculas: el esquema del manifiesto es sensible a ellas y los dos filtros
    # tienen que decir lo mismo. `LOCALHOST` no es local aquí ni allí (fail-closed).
    netloc_host = u.netloc.rsplit("@", 1)[-1]
    if netloc_host.startswith("["):
        netloc_host = netloc_host.split("]", 1)[0] + "]"
    else:
        netloc_host = netloc_host.split(":", 1)[0]
    return netloc_host in ("127.0.0.1", "localhost", "[::1]")


# ── transporte (urllib, presupuesto único; todo fallo es NoDisponible) ──────────────────
#: Lo más grande que se acepta de una réplica. El presupuesto acota el TIEMPO; esto acota la
#: MEMORIA: una réplica que empieza a servir gigabytes es tan indisponible como una caída.
LIMITE_RESPUESTA = 8 * 1024 * 1024


class Plazo:
    """El presupuesto de la operación ENTERA, no de cada petición.

    `timeout_s` se leía antes como plazo por petición y se pasaba tal cual a `urlopen`. Eso no
    acota nada: el plazo de `urllib` es por operación de socket y **se reinicia con cada byte
    recibido**, así que una réplica que gotea la respuesta la alarga indefinidamente; y el bucle
    de `_esperar_entrada` sólo miraba el reloj ENTRE pasadas, nunca dentro de una. Medido el
    2026-09-28 con `timeout_s = 2`: **34,4 s** con una réplica que manda un byte por segundo y
    **104,7 s** con cuatro. Un `verify` en un espacio que declara anclaje se colgaba con él.

    Aquí el reloj es uno solo para todo el anclaje: cada petición recibe lo que QUEDA, y cuando
    no queda nada la operación es `NoDisponible` — «se intentó y no se pudo», que es
    `NOT_EXECUTABLE` y nunca un certificado.
    """

    __slots__ = ("total", "fin")

    def __init__(self, total: float):
        self.total = max(float(total), 0.1)
        self.fin = time.monotonic() + self.total

    def restante(self) -> float:
        return self.fin - time.monotonic()

    def agotado(self) -> bool:
        return self.restante() <= 0

    def para_peticion(self) -> float:
        """Lo que se le concede a la siguiente petición, o `NoDisponible` si ya no queda."""
        r = self.restante()
        if r <= 0:
            raise NoDisponible(f"presupuesto de {self.total:g} s agotado")
        return min(self.total, r)


def _leer_acotado(resp, url: str, plazo: Plazo) -> bytes:
    """El cuerpo, leyendo a TROZOS y mirando el presupuesto entre uno y otro.

    Un `resp.read()` de una vez no se puede interrumpir: el plazo del socket vence cuando no
    llega NADA, y una réplica que manda un byte cada 0,2 s siempre llega a tiempo. Medido el
    2026-09-28 con el presupuesto ya puesto y esta lectura todavía entera: `buscar_entrada`
    tardó **226 s** con un presupuesto de 1 s, porque una sola respuesta de ~1,1 KB goteada son
    220 s que nadie cortaba. `read1` devuelve lo que haya llegado en vez de esperar a completar,
    y así el presupuesto se comprueba mientras el cuerpo entra, no sólo antes de pedirlo.
    """
    cuerpo = bytearray()
    while True:
        trozo = resp.read1(65536)
        if not trozo:
            return bytes(cuerpo)
        cuerpo += trozo
        if len(cuerpo) > LIMITE_RESPUESTA:
            raise NoDisponible(f"{url}: la respuesta pasa de {LIMITE_RESPUESTA} bytes")
        if plazo.agotado():
            raise NoDisponible(f"{url}: presupuesto de {plazo.total:g} s agotado con la respuesta "
                               f"a medias ({len(cuerpo)} byte(s))")


def _http_directo(srv, url: str, *, plazo: Plazo, datos: bytes | None = None) -> bytes:
    import http.client
    import socket
    import threading
    import urllib.parse

    timeout = plazo.para_peticion()
    client_sock, server_sock = socket.socketpair()
    client_sock.settimeout(timeout)
    server_sock.settimeout(timeout)

    def _serve():
        try:
            srv.finish_request(server_sock, ('127.0.0.1', 54321))
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()

    conn = http.client.HTTPConnection('127.0.0.1', srv.server_address[1], timeout=timeout)
    conn.sock = client_sock
    headers = {
        "content-type": "application/json",
        "user-agent": "refuto-anchor/1",
        "connection": "close",
    }
    if datos is not None:
        headers["content-length"] = str(len(datos))
    method = "POST" if datos is not None else "GET"
    parsed = urllib.parse.urlparse(url)
    selector = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    try:
        conn.request(method, selector, body=datos, headers=headers)
        resp = conn.getresponse()
        cuerpo = _leer_acotado(resp, url, plazo)
        if not (200 <= resp.status < 300):
            raise NoDisponible(f"{url}: HTTP {resp.status}")
        return cuerpo
    except socket.timeout:
        raise NoDisponible(f"{url}: presupuesto de {plazo.total:g} s agotado") from None
    except (http.client.HTTPException, OSError) as exc:
        raise NoDisponible(f"{url}: {type(exc).__name__}: {exc}") from None
    finally:
        try:
            conn.close()
        except Exception:
            pass
        try:
            server_sock.close()
        except Exception:
            pass
        try:
            client_sock.close()
        except Exception:
            pass


def _http(url: str, *, plazo: Plazo, datos: bytes | None = None) -> bytes:
    import urllib.error
    import urllib.parse
    import urllib.request

    try:
        parsed = urllib.parse.urlparse(url)
        port = parsed.port
        host = parsed.hostname
        if host in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):  # nosec B104
            if port in _DIRECT_SERVERS:
                return _http_directo(_DIRECT_SERVERS[port], url, plazo=plazo, datos=datos)
            elif port is not None and port < 1024:
                raise NoDisponible(f"{url}: Connection refused (direct: port {port} unserviced)")
    except NoDisponible:
        raise
    except Exception:
        pass

    req = urllib.request.Request(url, data=datos, method="POST" if datos is not None else "GET",
                                 headers={"content-type": "application/json",
                                          "user-agent": "refuto-anchor/1"})
    timeout = plazo.para_peticion()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 — http(s) declarado por el manifiesto
            cuerpo = _leer_acotado(resp, url, plazo)
            if not (200 <= resp.status < 300):
                raise NoDisponible(f"{url}: HTTP {resp.status}")
            return cuerpo
    except urllib.error.HTTPError as exc:
        raise NoDisponible(f"{url}: HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # `socket.timeout` es OSError; una URL sin esquema es ValueError.
        raise NoDisponible(f"{url}: {type(exc).__name__}: {exc}") from None


def regla_de_validez(endpoint: str, *, plazo: Plazo) -> dict:
    """La resolución de `core.regla_validez` sobre la regla que publica ESTA réplica.

    `GET /v1/status` → `validity_rule` (`CERTIFICATE-SPEC §11`). Un despliegue con binarios
    distintos publica digests distintos por réplica, que es exactamente lo que interesa ver.

    Nunca lanza: un notario que no publica la identidad —porque es anterior al mecanismo, o
    porque `/v1/status` no contesta— deja su regla SIN COMPROBAR, y eso se declara. Es la
    distinción que este módulo existe para no perder: desconocida no es correcta.
    """
    try:
        doc = _json(_http(f"{endpoint}/v1/status", plazo=plazo), f"{endpoint}/v1/status")
    except (NoDisponible, Invalido) as exc:
        return _regla_sin_comprobar(f"no se pudo leer {endpoint}/v1/status: {exc}")
    return regla_validez.consumir(doc.get("validity_rule"))


def _regla_sin_comprobar(motivo: str) -> dict:
    """La misma resolución `NO_DECLARADA` con el motivo por el que no se pudo mirar.

    El motivo importa —una réplica caída y un binario anterior al mecanismo se arreglan
    distinto— pero la resolución es la misma y no aprueba en ninguno de los dos casos."""
    r = regla_validez.consumir(None)
    r["motivo"] = motivo
    return r


def diagnosticar_endpoint(endpoint: str, *, pin: str | None = None, plazo: Plazo | None = None) -> dict:
    """Diagnostica el estado de conectividad e integridad de un notario Concordia.
    Clasificaciones normativas: AVAILABLE, UNAVAILABLE, NOT_EXECUTABLE, INVALID, STALE, VALID.

    `validity_rule` viaja aparte y NO coacciona `status`: que una réplica ejecute otra regla
    de validez es un hecho distinto de que esté caída o sirva otra membresía, y colapsarlos
    perdería cuál de los dos hay que arreglar.

    La clave está SIEMPRE, también cuando no se pudo mirar. Si apareciera sólo en el camino
    bueno, quien lea la evidencia tendría que distinguir «no diverge» de «no se comprobó» por
    la ausencia de un campo, que es como se cuelan los falsos verdes. En los caminos de error
    no se vuelve a la red: si la membresía no contestó, la regla tampoco lo hará.
    """
    if plazo is None:
        plazo = Plazo(5)
    try:
        raw = _http(f"{endpoint}/v1/membership", plazo=plazo)
        doc = _json(raw, f"{endpoint}/v1/membership")
        ms = reconstruir_membresia(doc)
        if pin and ms.digest != pin:
            return {"status": INVALID, "reason": f"Membership digest mismatch: expected {pin}, got {ms.digest}",
                    "validity_rule": regla_de_validez(endpoint, plazo=plazo)}
        return {"status": VALID, "membership_digest": ms.digest, "epoch": ms.epoch, "n": ms.n, "q": ms.q,
                "validity_rule": regla_de_validez(endpoint, plazo=plazo)}
    except NoDisponible as exc:
        msg = str(exc)
        estado = NOT_EXECUTABLE if "Operation not permitted" in msg else UNAVAILABLE
        return {"status": estado, "reason": msg,
                "validity_rule": _regla_sin_comprobar(f"la réplica no está disponible: {msg}")}
    except Invalido as exc:
        return {"status": INVALID, "reason": str(exc),
                "validity_rule": _regla_sin_comprobar(f"la réplica no es válida: {exc}")}
    except Exception as exc:
        return {"status": UNAVAILABLE, "reason": str(exc),
                "validity_rule": _regla_sin_comprobar(f"la réplica no está disponible: {exc}")}


def _json(cuerpo: bytes, que: str) -> dict:
    try:
        doc = json.loads(cuerpo.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise NoDisponible(f"{que}: respuesta ilegible ({type(exc).__name__})") from None
    if not isinstance(doc, dict):
        raise NoDisponible(f"{que}: la respuesta no es un objeto JSON")
    return doc


def obtener_membresia(endpoints: list, *, plazo: Plazo) -> dict:
    """`GET /v1/membership` de la primera réplica que conteste. Devuelve `{raw, doc, fuente}`;
    `raw` son los BYTES tal como llegaron: lo que se guarda y lo que se vuelve a verificar."""
    errores = []
    for base in endpoints:
        url = base.rstrip("/") + "/v1/membership"
        try:
            raw = _http(url, plazo=plazo)
            return {"raw": raw, "doc": _json(raw, url), "fuente": url}
        except NoDisponible as exc:
            errores.append(str(exc))
            if plazo.agotado():
                break
    raise NoDisponible("ninguna réplica sirvió la membresía: " + " | ".join(errores))


def ordenar(endpoints: list, *, client_id: int, nonce: int, payload: bytes, plazo: Plazo) -> dict:
    """`POST /v1/order`. La respuesta `{accepted}` NO es evidencia de nada: sólo dice si la
    petición entró. Lo que cuenta viene después, en el certificado."""
    cuerpo = json.dumps({"client_id": client_id, "nonce": nonce,
                         "payload_b64": base64.b64encode(payload).decode("ascii")}).encode("utf-8")
    errores = []
    for base in endpoints:
        url = base.rstrip("/") + "/v1/order"
        try:
            return {"doc": _json(_http(url, plazo=plazo, datos=cuerpo), url), "fuente": url}
        except NoDisponible as exc:
            errores.append(str(exc))
            if plazo.agotado():
                break
    raise NoDisponible("ninguna réplica aceptó la orden: " + " | ".join(errores))


def buscar_entrada(endpoints: list, *, payload_digest: str, q: int, plazo: Plazo,
                   desde: int = 1, paginas: int = 64) -> dict:
    """Localiza en `GET /v1/log` la entrada cuyo `payload_digest` es el del checkpoint enviado y
    que trae `≥ q` atestaciones. La API no devuelve `seq` al ordenar (`api/mod.rs:110`): se busca.

    Una réplica puede servir la entrada con menos de `q` atestaciones (SPEC §8.6): se pregunta a
    las demás. Devuelve `{raw_entry, entry, seq, fuente, incompletas}`; `raw_entry` es el TEXTO JSON
    exacto de la entrada dentro de la respuesta, reserializado canónicamente desde los bytes
    recibidos, y `entry` su parseo.
    """
    errores: list = []
    incompletas: list = []
    for base in endpoints:
        if plazo.agotado():
            break
        frm = desde
        for _ in range(paginas):
            url = f"{base.rstrip('/')}/v1/log?from={frm}&limit=1000"
            try:
                raw = _http(url, plazo=plazo)
                doc = _json(raw, url)
            except NoDisponible as exc:
                errores.append(str(exc))
                break
            entradas = doc.get("entries")
            if not isinstance(entradas, list):
                errores.append(f"{url}: sin `entries`")
                break
            for e in entradas:
                if isinstance(e, dict) and e.get("payload_digest") == payload_digest:
                    n_at = len(e.get("attestations") or []) if isinstance(e.get("attestations"), list) else 0
                    if n_at >= q:
                        return {"raw_entry": json.dumps(e, ensure_ascii=False, sort_keys=True,
                                                        separators=(",", ":")),
                                "entry": e, "seq": e.get("seq"), "fuente": url, "incompletas": incompletas}
                    incompletas.append(f"{url}: seq {e.get('seq')} con {n_at} atestación(es) < q={q}")
            if not entradas:
                break
            ultimo = entradas[-1].get("seq") if isinstance(entradas[-1], dict) else None
            last_executed = doc.get("last_executed")
            if not isinstance(ultimo, int) or (isinstance(last_executed, int) and ultimo >= last_executed):
                break
            frm = ultimo + 1
    detalle = " | ".join(incompletas + errores) or "la entrada no aparece en el log de ninguna réplica"
    raise NoDisponible(f"sin certificado completo para el checkpoint: {detalle}")


def _esperar_entrada(endpoints: list, *, payload_digest: str, q: int, plazo: Plazo) -> dict:
    """El consenso no es instantáneo: tras `POST /v1/order` la entrada tarda en ejecutarse y en
    reunir `q` atestaciones. Se reintenta `buscar_entrada` mientras quede PRESUPUESTO, y si se
    agota es `NoDisponible`: un plazo vencido no es un certificado."""
    ultimo = None
    while True:
        try:
            return buscar_entrada(endpoints, payload_digest=payload_digest, q=q, plazo=plazo)
        except NoDisponible as exc:
            ultimo = exc
        if plazo.agotado():
            raise NoDisponible(f"plazo de {plazo.total:g} s vencido sin certificado completo: {ultimo}")
        time.sleep(min(0.2, max(plazo.restante(), 0.0)))


# ── checkpoint ──────────────────────────────────────────────────────────────────────────
def canonico(doc: dict) -> bytes:
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def origen_de(workspace: Path, manifest: dict | None) -> str:
    """Identificador del diario. Del nombre declarado del espacio si lo hay; si no, del camino."""
    nombre = ((manifest or {}).get("workspace") or {}).get("name") if isinstance(manifest, dict) else None
    base = nombre if isinstance(nombre, str) and nombre else str(Path(workspace).resolve())
    return hashlib.sha256(("refuto.origin/v1\n" + base).encode("utf-8")).hexdigest()


def checkpoint(*, origin: str, size: int, root: str, engine_digest: str, policy_digest: str,
               membership_digest: str, run_id: str) -> dict:
    return {"schema": SCHEMA_CHECKPOINT, "origin": origin, "size": size, "root": root,
            "engine_digest": engine_digest, "policy_digest": policy_digest,
            "membership_digest": membership_digest, "run_id": run_id}


def carga_ordenada(client_id: int, nonce: int, payload: bytes) -> bytes:
    """`client_id ‖ nonce ‖ payload` (big-endian): lo que concordia vota y ejecuta (`types.rs:242`).
    El `payload_digest` del certificado es SHA-256 de ESTO, no de la carga desnuda."""
    return client_id.to_bytes(8, "big") + nonce.to_bytes(8, "big") + payload


def dir_anclas(workspace: Path) -> Path:
    return Path(workspace) / ".harness" / DIR_ANCLAS[0] / DIR_ANCLAS[1]


def anclar(workspace: Path, cfg: dict, *, run_id: str, engine_digest: str, policy_digest: str,
           manifest: dict | None, pin: str, cadena: dict) -> dict:
    """Ancla la cabeza ACTUAL del diario en concordia y verifica el certificado que vuelve.

    Devuelve `{"estado", "motivo", "ancla", "path"}`. `ancla` es el documento `refuto.anchor/v1`
    que se escribió (sólo si se llegó a verificar algo; un fallo de transporte no deja ancla, deja
    un evento). El evento `evidence/anchor` se escribe SIEMPRE que haya veredicto, también FAIL:
    un anclaje fallido es un hecho del diario.
    """
    from core.evidence import append_event
    from core.model import write_json

    if cadena.get("cicatrices"):
        # CICATRIZADA cierra, pero por TRAMOS. Un ancla afirma «el diario medía n y su cabeza
        # era h»; con una discontinuidad en medio, el tramo anterior no está atado al posterior
        # y esa afirmación sería más fuerte de lo que la cadena sostiene. No es un fallo del
        # diario —las cicatrices están declaradas y contrastadas— pero tampoco algo que anclar.
        return {"estado": BLOCKED, "ancla": None, "path": "",
                "motivo": f"el diario tiene {len(cadena['cicatrices'])} discontinuidad(es) "
                          f"declarada(s): cierra por tramos y un ancla afirmaría que cierra "
                          f"entero. Anclar exige una cadena sin saltos"}
    if cadena.get("estado") != "INTEGRA" or not cadena.get("ok"):
        return {"estado": FAIL, "ancla": None, "path": "",
                "motivo": f"no se ancla un diario que no cierra ({cadena.get('estado')}): "
                          f"{cadena.get('motivo') or 'sin motivo'}"}
    size, root = int(cadena.get("eventos") or 0), str(cadena.get("cabeza") or "")
    if size < 1:
        return {"estado": BLOCKED, "ancla": None, "path": "",
                "motivo": "el diario no tiene eventos: no hay nada que anclar (y la API exige nonce ≥ 1)"}
    endpoints = cfg.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints or not all(isinstance(e, str) and e for e in endpoints):
        return {"estado": BLOCKED, "ancla": None, "path": "",
                "motivo": "`anchoring.endpoints` no declara ninguna réplica"}
    remotos = [e for e in endpoints if not es_local(e)]
    if remotos:
        # SÓLO LOCAL hasta la publicación (decisión de la persona, 2026-09-27). Se comprueba aquí,
        # no sólo en el esquema: un manifiesto puede saltarse G-MANIFEST y llegar a `anclar`
        # igual. Se decide ANTES de abrir ninguna conexión: BLOCKED, sin evento de red.
        return {"estado": BLOCKED, "ancla": None, "path": "",
                "motivo": f"anclaje sólo contra réplicas locales hasta la publicación; endpoints no "
                          f"locales: {remotos[:3]}"}
    # UN reloj para toda la operación: membresía + orden + espera del certificado. Ver `Plazo`.
    plazo = Plazo(float(cfg.get("timeout_s") or 5.0))
    origin = origen_de(workspace, manifest)
    cp = checkpoint(origin=origin, size=size, root=root, engine_digest=engine_digest,
                    policy_digest=policy_digest, membership_digest=pin, run_id=run_id)
    payload = canonico(cp)
    client_id = int.from_bytes(bytes.fromhex(origin)[:8], "big")
    nonce = size
    carga = carga_ordenada(client_id, nonce, payload)
    payload_digest = hashlib.sha256(carga).hexdigest()

    try:
        mem = obtener_membresia(endpoints, plazo=plazo)
    except NoDisponible as exc:
        return _sin_ancla(workspace, run_id, NOT_EXECUTABLE, f"membresía: {exc}", cp)
    # El pin manda ANTES de mandar nada: una membresía que no es la fijada no merece ni la orden.
    try:
        ms = reconstruir_membresia(mem["doc"])
    except Invalido as exc:
        return _sin_ancla(workspace, run_id, FAIL, f"membresía servida inválida: {exc}", cp)
    if ms.digest != pin:
        return _sin_ancla(workspace, run_id, FAIL,
                          f"PinMismatch: el clúster sirve la membresía {ms.digest[:16]}… y el pin es "
                          f"{pin[:16]}…", cp)
    try:
        orden = ordenar(endpoints, client_id=client_id, nonce=nonce, payload=payload, plazo=plazo)
        hallazgo = _esperar_entrada(endpoints, payload_digest=payload_digest, q=ms.q, plazo=plazo)
    except NoDisponible as exc:
        return _sin_ancla(workspace, run_id, NOT_EXECUTABLE, str(exc), cp)

    # Se verifica lo que se GUARDA: el texto exacto de la entrada, vuelto a parsear.
    entry = json.loads(hallazgo["raw_entry"])
    membership_doc = json.loads(mem["raw"].decode("utf-8"))
    ver = verificar_certificado(membership_doc, entry, pin=pin)
    estado, motivo = PASS, ""
    if not ver["valido"]:
        # El motivo lleva TAMBIÉN las atestaciones rechazadas: «InsufficientQuorum: 2 < 3» sin decir
        # por qué la tercera no contó esconde justo el hecho que importa (firma rota, duplicado,
        # firmante ajeno). Lo cazó la batería adversarial el 2026-09-27.
        estado, motivo = FAIL, _motivo_certificado(ver)
    elif entry.get("payload_digest") != payload_digest:
        estado, motivo = FAIL, "el certificado no es del checkpoint enviado (payload_digest distinto)"
    elif "payload_b64" in entry and _b64_o_none(entry.get("payload_b64")) != carga:
        estado, motivo = FAIL, "la carga certificada no es byte a byte el checkpoint enviado"
    ancla = {
        "schema": SCHEMA_ANCLA,
        "run_id": run_id,
        "obtained_at": now(),
        "checkpoint": cp,
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "ordered_payload_digest": payload_digest,
        "order": {"client_id": client_id, "nonce": nonce, "accepted": (orden["doc"] or {}).get("accepted"),
                  "source": orden["fuente"]},
        "membership_pin": pin,
        "membership_raw": mem["raw"].decode("utf-8"),
        "membership_source": mem["fuente"],
        "entry_raw": hallazgo["raw_entry"],
        "entry_source": hallazgo["fuente"],
        "incomplete_replicas": hallazgo["incompletas"],
        "verification": {**ver, "verifier": "refuto.core.concordia/1", "engine_digest": engine_digest,
                         "status": estado, "reason": motivo},
    }
    seq = entry.get("seq")
    # El nombre lleva `seq` Y el `entry_digest`: tras un reinicio total del clúster (sin durabilidad,
    # SPEC §8.4) el log vuelve a empezar y un segundo ancla puede caer también en `seq = 1`. Con
    # sólo `seq` en el nombre, la nueva PISABA a la vieja — evidencia perdida en silencio. Dos
    # anclas con el mismo `entry_digest` son la misma entrada, y ahí sobrescribir es idempotente.
    ed_hex = str(ver.get("entry_digest") or entry.get("entry_digest") or "")[:16] or "sin-digest"
    path = dir_anclas(workspace) / (f"{int(seq):012d}-{ed_hex}.json" if isinstance(seq, int) and not isinstance(seq, bool)
                                   else f"sin-seq-{ed_hex}.json")
    write_json(path, ancla)
    append_event(workspace, {"kind": KIND_ANCLA, "run_id": run_id, "status": estado, "seq": seq,
                             "entry_digest": ver.get("entry_digest") or entry.get("entry_digest"),
                             "root": root, "size": size, "membership_digest": pin,
                             "signers": ver.get("signers"), "rejected": ver.get("rejected"),
                             "reason": motivo, "path": str(path)})
    return {"estado": estado, "motivo": motivo, "ancla": ancla, "path": str(path)}


def _motivo_certificado(ver: dict) -> str:
    """El motivo de un certificado inválido con sus atestaciones rechazadas, si las hay."""
    rechazadas = ver.get("rejected") or []
    return (f"certificado inválido: {ver['motivo']}"
            + (f" · rechazadas: {'; '.join(rechazadas)}" if rechazadas else ""))


def _b64_o_none(valor):
    try:
        return base64.b64decode(valor, validate=True) if isinstance(valor, str) else None
    except (ValueError, TypeError):
        return None


def _sin_ancla(workspace: Path, run_id: str, estado: str, motivo: str, cp: dict) -> dict:
    from core.evidence import append_event
    append_event(workspace, {"kind": KIND_ANCLA, "run_id": run_id, "status": estado, "seq": None,
                             "root": cp["root"], "size": cp["size"], "membership_digest": cp["membership_digest"],
                             "reason": motivo, "path": ""})
    return {"estado": estado, "motivo": motivo, "ancla": None, "path": ""}


# ── verificación OFFLINE de un ancla guardada ───────────────────────────────────────────
def anclas(workspace: Path) -> list:
    """Todas las anclas legibles, de la más reciente a la más antigua por `mtime`, con las
    ilegibles declaradas aparte: `{"legibles": [(path, doc)], "ilegibles": [{path, problem}]}`."""
    d = dir_anclas(workspace)
    out = {"legibles": [], "ilegibles": []}
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            out["ilegibles"].append({"path": str(p), "problem": f"{type(exc).__name__}: {exc}"})
            continue
        if isinstance(doc, dict) and doc.get("schema") == SCHEMA_ANCLA:
            out["legibles"].append((p, doc))
        else:
            out["ilegibles"].append({"path": str(p), "problem": "no es refuto.anchor/v1"})
    return out


def verificar_ancla(workspace: Path, doc: dict, *, pin: str, engine_digest: str | None = None) -> dict:
    """Vuelve a verificar un ancla guardada, OFFLINE, contra el pin y contra el diario de AHORA.

    Cuatro cosas, y las cuatro tienen que sostenerse:
      1. el certificado (`entry_raw`) verifica bajo la membresía guardada (`membership_raw`) Y esa
         membresía tiene el digest del PIN — el pin viene del llamador, nunca del ancla;
      2. la carga certificada decodifica al checkpoint declarado y su digest es el certificado;
      3. el diario actual contiene `root` en la posición `size` (`verificar_cadena(esperado, eventos_minimos)`);
      4. el `engine_digest` del checkpoint es el del motor que está JUZGANDO ahora.

    La cuarta se añadió el 2026-09-28, medida: hasta entonces el checkpoint grababa `engine_digest`
    y **nadie lo volvía a mirar**. Un motor mutado releía el ancla y devolvía `PASS` sin decir una
    palabra, con lo que la afirmación del ADR-0017 («`engine_digest` ata `I6'` a terceros») sólo se
    sostenía si un tercero lo comparaba a mano. Una discrepancia no es `FAIL` —no hay hecho contra
    la integridad del diario, y actualizar refuto es legítimo— pero tampoco es `PASS`: es
    `INCONCLUSIVE`, porque el veredicto anclado **no se puede atribuir al motor vigente**. Se cierra
    volviendo a anclar.

    Devuelve `{"estado", "motivo", "checkpoint", "seq", "signers", "cadena", "motor"}` con
    `PASS` / `FAIL` (hay un hecho en contra) / `INCONCLUSIVE` (no se pudo establecer).
    """
    from core.evidence import verificar_cadena

    def r(estado: str, motivo: str, **k) -> dict:
        cp = doc.get("checkpoint") if isinstance(doc, dict) else None
        base = {"estado": estado, "motivo": motivo, "checkpoint": cp, "seq": None,
                "signers": [], "cadena": None, "motor": motor}
        base.update(k)
        return base

    cp_previo = doc.get("checkpoint") if isinstance(doc, dict) else None
    del_ancla = (cp_previo or {}).get("engine_digest") if isinstance(cp_previo, dict) else None
    motor = {"vigente": engine_digest, "del_ancla": del_ancla,
             "coincide": None if engine_digest is None else (del_ancla == engine_digest)}

    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA_ANCLA:
        return r(INCONCLUSIVE, "el ancla no es refuto.anchor/v1")
    try:
        membership_doc = json.loads(doc["membership_raw"])
        entry = json.loads(doc["entry_raw"])
    except (KeyError, TypeError, ValueError) as exc:
        return r(INCONCLUSIVE, f"ancla ilegible: {type(exc).__name__}: {exc}")
    ver = verificar_certificado(membership_doc, entry, pin=pin)
    if not ver["valido"]:
        return r(FAIL, f"el certificado guardado no verifica bajo el pin: {_motivo_certificado(ver)}")
    cp = doc.get("checkpoint")
    carga_b64 = doc.get("payload_b64")
    try:
        payload = base64.b64decode(carga_b64, validate=True)
        declarado = json.loads(payload.decode("utf-8"))
    except (TypeError, ValueError):
        return r(INCONCLUSIVE, "la carga del ancla no decodifica a un checkpoint")
    if declarado != cp or not isinstance(cp, dict) or cp.get("schema") != SCHEMA_CHECKPOINT:
        return r(FAIL, "el checkpoint declarado en el ancla no es la carga certificada")
    if cp.get("membership_digest") != pin:
        return r(FAIL, f"el checkpoint se ancló bajo el pin {str(cp.get('membership_digest'))[:16]}… y el pin "
                       f"vigente es {pin[:16]}…: la membresía en la que se confía cambió después")
    orden = doc.get("order") or {}
    try:
        carga = carga_ordenada(int(orden["client_id"]), int(orden["nonce"]), payload)
    except (KeyError, TypeError, ValueError):
        return r(INCONCLUSIVE, "el ancla no conserva client_id/nonce: no se puede recomputar la carga ordenada")
    if hashlib.sha256(carga).hexdigest() != entry.get("payload_digest"):
        return r(FAIL, "la carga del ancla no es la que certifica la entrada (payload_digest distinto)")
    if "payload_b64" in entry and _b64_o_none(entry.get("payload_b64")) != carga:
        return r(FAIL, "la carga certificada por la entrada no es byte a byte el checkpoint del ancla")
    size, root = cp.get("size"), cp.get("root")
    if not isinstance(size, int) or size < 1 or not isinstance(root, str) or not root:
        return r(FAIL, "checkpoint malformado: size/root")
    cadena = verificar_cadena(workspace, esperado=root, eventos_minimos=size)
    if not cadena["ok"]:
        return r(FAIL, f"el diario de ahora no contiene el checkpoint certificado ({cadena['estado']}): "
                       f"{cadena['motivo']}", cadena=cadena, seq=entry.get("seq"), signers=ver["signers"])
    if motor["coincide"] is False:
        return r(INCONCLUSIVE,
                 f"el ancla la certificó el motor {str(del_ancla or '(sin declarar)')[:16]}… y el que "
                 f"juzga ahora es {str(engine_digest)[:16]}…: el certificado sigue siendo válido, pero "
                 f"el veredicto anclado no se puede atribuir al motor vigente",
                 cadena=cadena, seq=entry.get("seq"), signers=ver["signers"])
    return r(PASS, "", cadena=cadena, seq=entry.get("seq"), signers=ver["signers"])


def _ultimo_intento(workspace: Path, run_id: str) -> dict | None:
    """El último evento `evidence/anchor` de esa corrida en el diario, o `None`."""
    from core.evidence import read_events
    eventos = [e for e in read_events(workspace, [KIND_ANCLA]) if e.get("run_id") == run_id]
    return eventos[-1] if eventos else None


def estado_del_anclaje(workspace: Path, manifest: dict | None, *, pin_externo: str | None = None,
                       run_id: str | None = None, engine_digest: str | None = None) -> dict:
    """Lo que `status` pregunta: ¿el último ancla se sostiene hoy, offline, bajo el pin?

    Devuelve `{"declarado", "estado", "motivo", "pin", "ancla", "path", "ilegibles", "detalle"}`.
    Si el espacio no declara anclaje → `declarado=False`, `estado=NOT_APPLICABLE`. Si lo declara y
    no hay ancla → `INCONCLUSIVE` (verificación no ejecutada ≠ PASS). Si hay pin ausente → `BLOCKED`.

    `engine_digest` es el motor que juzga; `None` significa **el de este proceso**, no «no
    comprobar». La comprobación es fail-closed a propósito: un llamador que se olvide del
    parámetro no desactiva el control, sólo quien pase otro valor a sabiendas (las pruebas).
    """
    from core.model import NOT_APPLICABLE
    from core.trust import digest_motor

    if engine_digest is None:
        engine_digest = digest_motor()
    cfg = configuracion(manifest)
    if cfg is None:
        return {"declarado": False, "estado": NOT_APPLICABLE, "motivo": "el espacio no declara `anchoring`",
                "pin": None, "ancla": None, "path": "", "ilegibles": [], "detalle": None}
    pin = resolver_pin(cfg, externo=pin_externo)
    if pin["estado"] != PASS:
        return {"declarado": True, "estado": pin["estado"], "motivo": pin["motivo"], "pin": None,
                "ancla": None, "path": "", "ilegibles": [], "detalle": None}
    todas = anclas(workspace)
    candidatas = todas["legibles"]
    if run_id:
        # SÓLO las anclas de esa corrida. La versión anterior, si ninguna coincidía, se quedaba
        # con TODAS las legibles y elegía la más reciente por `mtime`: tras un `verify` cuyo
        # anclaje había fallado (clúster caído → NOT_EXECUTABLE), `status` reportaba PASS con el
        # ancla de la corrida ANTERIOR. Lo encontró el falsador el 2026-09-27 ejecutando el CLI
        # real; `test_ancla_cli.py::test_status_tras_un_verify_sin_ancla_no_es_pass` lo fija.
        candidatas = [(p, d) for p, d in candidatas if d.get("run_id") == run_id]
    if not candidatas:
        motivo = ("el espacio declara anclaje y no hay ningún ancla" + (f" para «{run_id}»" if run_id else "")
                  + ": la verificación de anclaje no se ejecutó, y no ejecutada no es aprobada")
        if todas["ilegibles"]:
            motivo += f"; {len(todas['ilegibles'])} fichero(s) ilegible(s) en anchors/"
        estado = INCONCLUSIVE
        # Si el diario registró un intento para esa corrida, se dice qué pasó — y un FAIL
        # registrado es un hecho demostrado, no una duda.
        ultimo = _ultimo_intento(workspace, run_id) if run_id else None
        if ultimo is not None:
            motivo = (f"el último intento de anclaje de «{run_id}» quedó en {ultimo.get('status')}: "
                      f"{ultimo.get('reason') or 'sin motivo registrado'}")
            if ultimo.get("status") == FAIL:
                estado = FAIL
        return {"declarado": True, "estado": estado, "motivo": motivo, "pin": pin["pin"],
                "ancla": None, "path": "", "ilegibles": todas["ilegibles"], "detalle": None}
    path, doc = candidatas[0]
    det = verificar_ancla(workspace, doc, pin=pin["pin"], engine_digest=engine_digest)
    estado = det["estado"]
    if estado == PASS and todas["ilegibles"]:
        estado = INCONCLUSIVE
        det["motivo"] = f"{len(todas['ilegibles'])} ancla(s) ilegible(s): «no pude leerlo» no es «no existe»"
    return {"declarado": True, "estado": estado, "motivo": det["motivo"], "pin": pin["pin"],
            "ancla": doc, "path": str(path), "ilegibles": todas["ilegibles"], "detalle": det}
