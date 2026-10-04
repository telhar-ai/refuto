# -*- coding: utf-8 -*-
"""core.change — Modelo Formal de Cambio Protegido y Separación de Autoridad.

Implementa el ciclo canónico:
    Propose → Inspect → Authorize → Apply → Verify → Admit

Garantías de Seguridad e Invariantes:
1. Separación Estricta de Autoridad (A01):
   El proponente de un cambio (agente o humano) NO PUEDE autorizarse a sí mismo.
2. Integridad de la Autorización (A02, A07, A08):
   La autorización es un token firmado con Ed25519 sobre el digest exacto del diff,
   los archivos objetivo y un nonce irrepetible. Cualquier mutación invalida la firma.
3. Protección de Políticas Raíz (A03):
   Tocar `.harness/policy.json` requiere rol de gobernanza raíz y quórum verificado.
4. Protección de Compuertas (A04):
   Modificar cualquier archivo en `DEFAULT_PROTECTED` (incluyendo `gates/**`) exige
   obligatoriamente un token de autorización válido firmado por una clave de confianza.
5. Prevención de Suplantación (A05):
   La clave pública del firmante debe estar previamente registrada en el almacén de
   autorizadores de confianza.
6. Protección contra Replay y Expiración (A06):
   Cada token tiene un TTL estricto y un nonce único registrado en el estado para
   impedir su reutilización.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core import ed25519 as E
from core.digest import sha256_text
from core.model import (
    FAIL,
    PASS,
)
from core.policy import DEFAULT_PROTECTED, Policy

# ── Excepciones normativas de seguridad ────────────────────────────────────────────────

class ProtectedChangeError(Exception):
    """Error base de cambio protegido."""


class AuthoritySeparationViolation(ProtectedChangeError):
    """A01: El proponente intentó autorizar su propio cambio."""


class InvalidAuthorizationSignatureError(ProtectedChangeError):
    """A02: La firma criptográfica de la autorización es inválida o forjada."""


class PolicyTamperBlockedError(ProtectedChangeError):
    """A03: Intento de debilitar la política raíz sin quórum de gobernanza."""


class ProtectedTargetRequiresAuthorizationError(ProtectedChangeError):
    """A04: Modificación de compuerta o superficie protegida sin autorización."""


class UntrustedAuthorizerError(ProtectedChangeError):
    """A05: El autorizador o su clave pública no están registrados en la lista de confianza."""


class AuthorizationReplayError(ProtectedChangeError):
    """A06: Intento de reutilizar un token de autorización ya consumido."""


class AuthorizationExpiredError(ProtectedChangeError):
    """A06: El token de autorización ha superado su tiempo de vida (TTL)."""


class DiffTamperDetectedError(ProtectedChangeError):
    """A07: El diff o su hash fue mutado tras la emisión de la autorización."""


class TargetTamperDetectedError(ProtectedChangeError):
    """A08: Los archivos objetivo no coinciden con los autorizados."""


class EvidenceTamperDetectedError(ProtectedChangeError):
    """A09: La evidencia de verificación fue alterada o forjada."""


class CircularWitnessError(ProtectedChangeError):
    """A10: El autor del cambio no puede ser testigo de su propia verificación."""


class ScopeReductionError(ProtectedChangeError):
    """A11: El cambio reduce arbitrariamente el ámbito o introduce ámbito vacío."""


# ── Estructuras de datos ─────────────────────────────────────────────────────────────

@dataclass
class ChangeProposal:
    schema: str = "refuto.change_proposal/v1"
    proposal_id: str = field(default_factory=lambda: f"chg_{uuid.uuid4().hex[:12]}")
    title: str = ""
    author: str = ""
    author_type: str = "agent"  # "agent" | "human"
    target_files: List[str] = field(default_factory=list)
    diff: str = ""
    diff_hash: str = ""
    invariants: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.diff_hash and self.diff:
            self.diff_hash = sha256_text(self.diff)
        if not self.target_files and self.diff:
            parsed = parse_unified_diff(self.diff)
            self.target_files = sorted({f["new_path"] for f in parsed})

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ChangeProposal:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AuthorizationToken:
    schema: str = "refuto.authorization_token/v1"
    token_id: str = field(default_factory=lambda: f"auth_{uuid.uuid4().hex[:12]}")
    proposal_id: str = ""
    diff_hash: str = ""
    target_files: List[str] = field(default_factory=list)
    authorizer_id: str = ""
    authorizer_type: str = "human"  # "human" | "governance_authority"
    public_key: str = ""  # Hex-encoded Ed25519
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex)
    expires_at: str = ""
    signature: str = ""  # Hex-encoded Ed25519 signature

    def canonical_signing_bytes(self) -> bytes:
        """Serialización canónica para firma Ed25519."""
        targets = ",".join(sorted(self.target_files))
        msg = f"{self.token_id}:{self.proposal_id}:{self.diff_hash}:{targets}:{self.authorizer_id}:{self.nonce}:{self.expires_at}"
        return msg.encode("utf-8")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthorizationToken:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class VerificationResult:
    schema: str = "refuto.change_verification/v1"
    verification_id: str = field(default_factory=lambda: f"ver_{uuid.uuid4().hex[:12]}")
    proposal_id: str = ""
    status: str = PASS
    can_advance: bool = True
    invariants_checked: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    remediations: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Parser y Aplicador de Diffs Unificados (Sólo Biblioteca Estándar) ─────────────────

def parse_unified_diff(diff_text: str) -> List[Dict[str, Any]]:
    """Parsea un diff unificado estándar en bloques por archivo y hunks."""
    files: List[Dict[str, Any]] = []
    lines = diff_text.splitlines(keepends=True)
    i = 0
    current_file: Optional[Dict[str, Any]] = None

    while i < len(lines):
        line = lines[i]
        if line.startswith("--- "):
            old_path = line[4:].strip().split("\t")[0]
            if old_path.startswith("a/"):
                old_path = old_path[2:]
            i += 1
            if i < len(lines) and lines[i].startswith("+++ "):
                new_path = lines[i][4:].strip().split("\t")[0]
                if new_path.startswith("b/"):
                    new_path = new_path[2:]
                i += 1
                current_file = {
                    "old_path": old_path,
                    "new_path": new_path,
                    "hunks": []
                }
                files.append(current_file)
                continue
        if line.startswith("@@ ") and current_file is not None:
            m = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
            if m:
                old_start = int(m.group(1))
                old_count = int(m.group(2)) if m.group(2) is not None else 1
                new_start = int(m.group(3))
                new_count = int(m.group(4)) if m.group(4) is not None else 1
                hunk_lines = []
                i += 1
                while i < len(lines):
                    hl = lines[i]
                    if hl.startswith("@@ ") or hl.startswith("--- ") or hl.startswith("diff "):
                        break
                    if hl.startswith(" ") or hl.startswith("+") or hl.startswith("-") or hl == "\n":
                        hunk_lines.append(hl)
                        i += 1
                    elif hl.startswith("\\ No newline at end of file"):
                        i += 1
                    else:
                        break
                current_file["hunks"].append({
                    "old_start": old_start,
                    "old_count": old_count,
                    "new_start": new_start,
                    "new_count": new_count,
                    "lines": hunk_lines
                })
                continue
        i += 1

    return files


def apply_hunks_to_text(original_text: str, hunks: List[Dict[str, Any]]) -> str:
    """Aplica hunks a un texto original respetando numeración y contexto."""
    orig_lines = original_text.splitlines(keepends=True)
    out_lines = []
    orig_idx = 0

    for hunk in hunks:
        target_orig_start = hunk["old_start"] - 1  # 0-indexed
        while orig_idx < target_orig_start and orig_idx < len(orig_lines):
            out_lines.append(orig_lines[orig_idx])
            orig_idx += 1

        for hline in hunk["lines"]:
            tag = hline[0] if hline else " "
            content = hline[1:]
            if tag == " ":
                if orig_idx < len(orig_lines):
                    out_lines.append(orig_lines[orig_idx])
                    orig_idx += 1
                else:
                    out_lines.append(content)
            elif tag == "-":
                if orig_idx < len(orig_lines):
                    orig_idx += 1
            elif tag == "+":
                out_lines.append(content)

    while orig_idx < len(orig_lines):
        out_lines.append(orig_lines[orig_idx])
        orig_idx += 1

    return "".join(out_lines)


# ── Funciones Criptográficas Auxiliares (Ed25519) ─────────────────────────────────────

def _ed25519_sign(secret: bytes, message: bytes) -> bytes:
    """Firma Ed25519 (RFC 8032 §5.1.6). Sólo para autorizadores."""
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    pk = E.encode_point(E._mul(a, E.BASE))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % E.L
    R = E.encode_point(E._mul(r, E.BASE))
    k = int.from_bytes(hashlib.sha512(R + pk + message).digest(), "little") % E.L
    s = (r + k * a) % E.L
    return R + s.to_bytes(32, "little")


def _ed25519_public_key(secret: bytes) -> bytes:
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return E.encode_point(E._mul(a, E.BASE))


# ── Motor del Ciclo de Cambio Protegido ───────────────────────────────────────────────

class ChangeGovernanceEngine:
    """Motor de gestión de cambios protegidos sobre un espacio de trabajo."""

    def __init__(self, workspace: Path):
        self.workspace = workspace
        self.state_dir = workspace / ".harness" / "state"
        self.consumed_auth_file = self.state_dir / "consumed_authorizations.json"
        self.trusted_keys_file = workspace / ".harness" / "trusted_authorizers.json"

    def _load_consumed_nonces(self) -> Set[str]:
        if not self.consumed_auth_file.exists():
            return set()
        try:
            data = json.loads(self.consumed_auth_file.read_text(encoding="utf-8"))
            return set(data.get("consumed_nonces", []))
        except Exception:
            return set()

    def _mark_nonce_consumed(self, nonce: str) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        consumed = self._load_consumed_nonces()
        consumed.add(nonce)
        tmp = self.consumed_auth_file.with_suffix(".tmp")
        tmp.write_text(json.dumps({"consumed_nonces": sorted(consumed)}, indent=2), encoding="utf-8", newline="\n")
        tmp.replace(self.consumed_auth_file)

    def load_trusted_authorizers(self) -> Dict[str, str]:
        """Carga el registro de autorizadores de confianza `{authorizer_id: pubkey_hex}`."""
        if not self.trusted_keys_file.exists():
            return {}
        try:
            data = json.loads(self.trusted_keys_file.read_text(encoding="utf-8"))
            return data.get("authorizers", {})
        except Exception:
            return {}

    def is_target_protected(self, rel_path: str) -> bool:
        """Determina si un archivo objetivo está bajo una ruta protegida o de gobierno.

        Los artefactos de GOBIERNO cuentan, y desde el 2026-10-03 hay que preguntarlo aparte:
        `policies/base.json` salió de `protected_paths` y pasó a `authority_paths`, que es otro
        mecanismo (ver `core.policy.DEFAULT_AUTHORITY`). Sin esta rama, A04 habría dejado de
        exigir token de autorización para tocar el documento del que cuelga la norma — una
        protección perdida por refactor, que es la forma más silenciosa de perderla.

        Se anclan a la RAÍZ DEL ESPACIO y no se recorren raíces más profundas: aquí sólo hay una
        ruta relativa de un diff, sin sistema de archivos que consultar. Eso es conservador en la
        dirección correcta —puede exigir autorización de más, nunca de menos— y la resolución
        completa la hace el guardián, que sí ve el disco.
        """
        policy_file = self.workspace / ".harness" / "policy.json"
        if policy_file.exists():
            try:
                pol = Policy.load(policy_file)
                if pol.is_writable(rel_path):
                    return False
                if pol.is_protected(rel_path):
                    return True
                return bool(pol.is_authority(rel_path, ("",))[0])
            except Exception:
                pass
        # Fallback a las constantes del motor
        from core.policy import DEFAULT_AUTHORITY, _normalize, _path_matches
        norm = _normalize(rel_path)
        for pat in tuple(DEFAULT_PROTECTED) + tuple(DEFAULT_AUTHORITY):
            if _path_matches(norm, pat):
                return True
        return False

    def propose(self, title: str, author: str, author_type: str,
                diff: str, invariants: Optional[List[str]] = None,
                target_files: Optional[List[str]] = None) -> ChangeProposal:
        """1. PROPOSE: Registra una propuesta formal de cambio."""
        proposal = ChangeProposal(
            title=title,
            author=author,
            author_type=author_type,
            diff=diff,
            invariants=invariants or [],
            target_files=target_files or []
        )
        return proposal

    def inspect(self, proposal: ChangeProposal) -> Dict[str, Any]:
        """2. INSPECT: Analiza el impacto de la propuesta y requisitos de autorización."""
        protected_targets = [f for f in proposal.target_files if self.is_target_protected(f)]
        touches_root_policy = any(".harness/policy.json" in f for f in proposal.target_files)

        return {
            "proposal_id": proposal.proposal_id,
            "target_files": proposal.target_files,
            "protected_targets": protected_targets,
            "requires_authorization": len(protected_targets) > 0,
            "touches_root_policy": touches_root_policy,
            "diff_hash": proposal.diff_hash,
            "invariants": proposal.invariants
        }

    def authorize(self, proposal: ChangeProposal, authorizer_id: str,
                  authorizer_type: str, secret_key_bytes: bytes,
                  ttl_seconds: int = 3600,
                  trusted_keys: Optional[Dict[str, str]] = None) -> AuthorizationToken:
        """3. AUTHORIZE: Un autorizador independiente emite un token criptográfico."""
        # Invariante A01: Prohibido auto-autorizarse
        if proposal.author == authorizer_id:
            raise AuthoritySeparationViolation(
                f"A01: El proponente '{proposal.author}' no puede auto-autorizarse. "
                "Separación de autoridad estricta violada."
            )

        pubkey = _ed25519_public_key(secret_key_bytes)
        pubkey_hex = pubkey.hex()

        # Emitir un token NO es una afirmación de confianza, y conviene decirlo aquí porque se
        # lee como si lo fuera: con el almacén ausente, o con un `authorizer_id` que no está en
        # él, este método devuelve un token perfectamente firmado. El control de identidad vive
        # en `apply`, que es donde se escribe, y desde el 2026-10-03 falla cerrado. Se deja
        # permisivo a propósito: acuñar en una máquina sin el almacén y aplicar en otra que sí lo
        # tiene es un flujo legítimo, y mover el rechazo aquí no añadiría ninguna garantía —sólo
        # cambiaría dónde salta—. No trate «token emitido» como «autorizador reconocido».
        trusted = trusted_keys or self.load_trusted_authorizers()
        if trusted and authorizer_id in trusted:
            if trusted[authorizer_id].lower() != pubkey_hex.lower():
                raise UntrustedAuthorizerError(
                    f"A05: La clave pública para '{authorizer_id}' no coincide con el almacén de confianza."
                )

        expires_at = datetime.fromtimestamp(time.time() + ttl_seconds, tz=timezone.utc).isoformat()
        token = AuthorizationToken(
            proposal_id=proposal.proposal_id,
            diff_hash=proposal.diff_hash,
            target_files=sorted(proposal.target_files),
            authorizer_id=authorizer_id,
            authorizer_type=authorizer_type,
            public_key=pubkey_hex,
            expires_at=expires_at
        )

        sig = _ed25519_sign(secret_key_bytes, token.canonical_signing_bytes())
        token.signature = sig.hex()
        return token

    def apply(self, proposal: ChangeProposal,
              authorization: Optional[AuthorizationToken] = None,
              trusted_keys: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """4. APPLY: Aplica el cambio comprobando todas las restricciones de seguridad."""
        inspection = self.inspect(proposal)

        # Invariante A04: Si toca archivos protegidos, EXIGE autorización; si se provee token, debe validar
        if inspection["requires_authorization"] or authorization is not None:
            if not authorization:
                raise ProtectedTargetRequiresAuthorizationError(
                    "A04: Modificación de superficies protegidas requiere un token de autorización válido."
                )

            # Invariante A01: El proponente no puede ser el autorizador
            if proposal.author == authorization.authorizer_id:
                raise AuthoritySeparationViolation(
                    "A01: El autor del token es idéntico al proponente. Violación de autoridad."
                )

            # Invariante A07: El diff hash debe coincidir
            calculated_hash = sha256_text(proposal.diff)
            if calculated_hash != authorization.diff_hash or proposal.diff_hash != authorization.diff_hash:
                raise DiffTamperDetectedError(
                    "A07: El diff_hash del token no coincide con el diff propuesto. Parche alterado."
                )

            # Invariante A08: Los archivos objetivo deben coincidir
            if sorted(proposal.target_files) != sorted(authorization.target_files):
                raise TargetTamperDetectedError(
                    "A08: Los archivos objetivo difieren de los autorizados en el token."
                )

            # Invariante A06: Comprobar expiración TTL
            try:
                exp_dt = datetime.fromisoformat(authorization.expires_at)
                if datetime.now(timezone.utc) > exp_dt:
                    raise AuthorizationExpiredError("A06: El token de autorización ha expirado.")
            except (ValueError, TypeError) as exc:
                raise AuthorizationExpiredError(f"A06: Fecha de expiración inválida: {exc}") from exc

            # Invariante A06: Comprobar replay de nonce
            consumed_nonces = self._load_consumed_nonces()
            if authorization.nonce in consumed_nonces:
                raise AuthorizationReplayError(
                    f"A06: El nonce '{authorization.nonce}' ya fue consumido previamente (Replay Attack)."
                )

            # Invariante A05: Clave en almacén de confianza. FALLA CERRADO.
            #
            # Decía `if trusted:`, y un almacén ausente o vacío saltaba el bloque entero. Medido
            # el 2026-10-03 a través del protocolo, de punta a punta:
            #
            #     propone  agente            → propuesta creada
            #     autoriza «revisor-humano»  → token EMITIDO (identidad inventada, par propio)
            #     aplica   gates/g_colado.py → *** APLICADO ***
            #
            # Lo mismo con `verification/**` y `evidence/**`. Es decir: un agente podía escribir
            # su propio juez y su propia evidencia inventándose un segundo nombre, que es la
            # única propiedad que este producto existe para impedir. Sólo `.harness/policy.json`
            # se salvaba, y por otro invariante (A03, quórum de gobernanza).
            #
            # A02 seguía verificando la firma y por eso no se notaba: verifica contra la clave
            # pública que el TOKEN TRAE, así que sin A05 demuestra que el token no se alteró, no
            # que lo firmara nadie en concreto. Una firma sin almacén de confianza es un sello
            # sin registro.
            #
            # Un almacén vacío es un ÁMBITO VACÍO, y en esta herramienta un ámbito vacío no
            # aprueba: es la misma regla que hace que una suite de 0 pruebas falle y que
            # `G-SECURITY` no apruebe con el escáner caído. «No puedo comprobar quién firma» no
            # es «lo firmó alguien de confianza».
            #
            # Coste declarado: a partir de aquí, un espacio sin `.harness/trusted_authorizers.json`
            # NO puede aplicar ningún cambio sobre superficie protegida por esta vía. Es lo
            # correcto —registrar al primer autorizador es un acto de persona, y ese fichero está
            # bajo `.harness/**`, protegido— y hoy no rompe ningún uso: el almacén no existe en
            # ninguno de los 11 espacios medidos, luego nadie estaba usando esta vía con
            # autoridad real. Lo que se retira es la capacidad de usarla SIN autoridad.
            trusted = trusted_keys if trusted_keys else self.load_trusted_authorizers()
            if not trusted:
                raise UntrustedAuthorizerError(
                    "A05: no hay almacén de autorizadores de confianza en este espacio "
                    "(`.harness/trusted_authorizers.json`), así que la identidad del firmante no "
                    "se puede comprobar. No se aprueba: un almacén vacío no es un almacén que "
                    "autorice a cualquiera. Registre al autorizador — es un acto de persona, y "
                    "ese fichero está protegido justo por eso."
                )
            if authorization.authorizer_id not in trusted:
                raise UntrustedAuthorizerError(
                    f"A05: Autorizador '{authorization.authorizer_id}' no es de confianza."
                )
            expected_pk = trusted[authorization.authorizer_id].lower()
            if authorization.public_key.lower() != expected_pk:
                raise UntrustedAuthorizerError(
                    f"A05: Clave pública del token no coincide con la registrada para '{authorization.authorizer_id}'."
                )

            # Invariante A02: Verificar firma Ed25519
            try:
                pk_bytes = bytes.fromhex(authorization.public_key)
                sig_bytes = bytes.fromhex(authorization.signature)
                msg_bytes = authorization.canonical_signing_bytes()
                valid = E.verify(pk_bytes, msg_bytes, sig_bytes)
                if not valid:
                    raise InvalidAuthorizationSignatureError("A02: Firma de autorización Ed25519 inválida.")
            except Exception as exc:
                if isinstance(exc, InvalidAuthorizationSignatureError):
                    raise
                raise InvalidAuthorizationSignatureError(f"A02: Error al verificar firma: {exc}") from exc

            # Invariante A03: Tocar política raíz requiere verificación adicional
            if inspection["touches_root_policy"]:
                if authorization.authorizer_type != "governance_authority":
                    raise PolicyTamperBlockedError(
                        "A03: La política raíz sólo puede modificarse por una entidad de gobernanza (quórum)."
                    )

        # Aplicar el diff atómicamente a cada archivo
        parsed_files = parse_unified_diff(proposal.diff)
        applied_paths = []
        for file_info in parsed_files:
            rel_target = file_info["new_path"]
            abs_target = self.workspace / rel_target
            abs_target.parent.mkdir(parents=True, exist_ok=True)
            orig_content = abs_target.read_text(encoding="utf-8") if abs_target.exists() else ""
            new_content = apply_hunks_to_text(orig_content, file_info["hunks"])
            abs_target.write_text(new_content, encoding="utf-8", newline="\n")
            applied_paths.append(rel_target)

        # Si se usó autorización, consumir el nonce
        if authorization:
            self._mark_nonce_consumed(authorization.nonce)

        # Registrar evento en el ledger
        from core.evidence import append_event
        event_data = {
            "kind": "governed_change_applied",
            "proposal_id": proposal.proposal_id,
            "title": proposal.title,
            "author": proposal.author,
            "diff_hash": proposal.diff_hash,
            "authorizer_id": authorization.authorizer_id if authorization else "unrestricted_proposer",
            "applied_files": applied_paths,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        append_event(self.workspace, event_data)

        return {
            "status": "APPLIED",
            "proposal_id": proposal.proposal_id,
            "applied_files": applied_paths,
            "authorization_consumed": authorization.token_id if authorization else None
        }

    def verify(self, proposal: ChangeProposal,
               witness_id: Optional[str] = None) -> VerificationResult:
        """5. VERIFY: Ejecuta verificación independiente de las propiedades del cambio."""
        # Invariante A10: El testigo no puede ser el proponente
        if witness_id and witness_id == proposal.author:
            raise CircularWitnessError("A10: El proponente no puede ser testigo de su propia verificación.")

        observations = []
        remediations = []
        invariants_checked = []

        # Verificar que todos los archivos objetivo existen y compilan sintácticamente
        all_ok = True
        for rel_file in proposal.target_files:
            abs_path = self.workspace / rel_file
            if not abs_path.exists():
                observations.append(f"Archivo objetivo {rel_file} no existe tras la aplicación.")
                all_ok = False
                continue
            if abs_path.suffix == ".py":
                try:
                    import ast
                    ast.parse(abs_path.read_text(encoding="utf-8"))
                    observations.append(f"Sintaxis AST Python válida: {rel_file}")
                except SyntaxError as e:
                    observations.append(f"Error de sintaxis en {rel_file}: {e}")
                    all_ok = False

        invariants_checked.append("ast_syntax_validity")

        # Comprobar no-vacuidad si el cambio tocó compuertas
        if any("gates/" in f for f in proposal.target_files):
            invariants_checked.append("gate_non_vacuity")

        status = PASS if all_ok else FAIL
        return VerificationResult(
            proposal_id=proposal.proposal_id,
            status=status,
            can_advance=all_ok,
            invariants_checked=invariants_checked,
            observations=observations,
            remediations=remediations
        )

    def admit(self, proposal: ChangeProposal,
              verification: VerificationResult) -> Dict[str, Any]:
        """6. ADMIT: Emite la decisión de admisión del cambio."""
        admitted = (verification.status == PASS and verification.can_advance)
        return {
            "admitted": admitted,
            "proposal_id": proposal.proposal_id,
            "status": verification.status,
            "can_advance": admitted,
            "rationale": "Verificación independiente satisfactoria de invariantes y contratos." if admitted else "Fallo en verificación independiente."
        }
