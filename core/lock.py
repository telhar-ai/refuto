# -*- coding: utf-8 -*-
"""H-06 · Lock criptográfico. Evidencia **y** enforcement.

El hallazgo que motiva este módulo
----------------------------------
El guion de sincronización que refuto sustituye hacía, en este orden:

    git clone --branch v3.0.1  →  copiar 36 archivos  →  REESCRIBIR el lock  →  comparar

Comparar contra un lock que se acaba de fabricar con las huellas de lo que se acaba de traer no
comprueba nada: siempre coincide. Y el ancla era una **etiqueta de git**, que es mutable. Quien
pueda mover `v3.0.1` cambia `verificacion/*.py` —el juez— en todas las copias, y la
verificación sigue en verde porque está comparando el árbol contra el lock nuevo.

La secuencia correcta, que es la que implementa este módulo
-----------------------------------------------------------
    LOCK CONOCIDO  →  TRAER ORIGEN  →  FIJAR COMMIT INMUTABLE  →  VERIFICAR CONTENIDO
                   →  COMPARAR CONTRA EL LOCK  →  FALLAR SI HAY DERIVA
                   →  ACTUALIZAR EL LOCK SÓLO SI SE PIDE EXPLÍCITAMENTE

Tres invariantes, y las tres se prueban en `tests/adversarial/`:

    I1  `verify()` NUNCA escribe el lock.
    I2  el ancla persistida es el SHA del commit, no la etiqueta.
    I3  una etiqueta que se mueve produce FAIL, no un lock nuevo.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from core.digest import sha256_file
from core.model import (BLOCKED, FAIL, Finding, NOT_APPLICABLE, PASS, Result, Scope, now)
from core.proc import TEXT_IO

LOCK_SCHEMA = "harness.lock/v1"

#: Un SHA-1 de git tiene 40 caracteres hexadecimales; SHA-256, 64. Se aceptan los dos.
_SHA_LEN = (40, 64)


@dataclass
class SourceLock:
    name: str
    uri: str
    ref: str                       # lo que se pidió (mutable: rama o etiqueta)
    commit: str                    # lo que se resolvió (inmutable) ← el ancla de verdad
    manifest_digest: str = ""
    tree_digest: str = ""
    files: dict = field(default_factory=dict)
    resolved_at: str = ""

    def to_dict(self) -> dict:
        return {"uri": self.uri, "ref": self.ref, "commit": self.commit,
                "manifest_digest": self.manifest_digest, "tree_digest": self.tree_digest,
                "resolved_at": self.resolved_at, "files": self.files}


# ── resolución del origen ────────────────────────────────────────────────────────────
def resolve_ref(uri: str, ref: str, *, timeout: int = 60) -> tuple[str, str]:
    """Resuelve `ref` a un SHA sin clonar. Devuelve (sha, error).

    `git ls-remote` es la forma barata y honesta: pregunta al servidor a qué apunta la
    referencia AHORA. Si la etiqueta se movió, aquí se ve.
    """
    try:
        proc = subprocess.run(["git", "ls-remote", uri, ref, f"refs/tags/{ref}",
                               f"refs/heads/{ref}"],
                              capture_output=True, **TEXT_IO, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return "", f"no se pudo consultar el origen: {exc}"
    if proc.returncode != 0:
        return "", f"git ls-remote falló ({proc.returncode}): {(proc.stderr or '').strip()[:200]}"
    lines = [l for l in (proc.stdout or "").splitlines() if l.strip()]
    if not lines:
        return "", f"la referencia «{ref}» no existe en {uri}"
    # Una etiqueta anotada expone `refs/tags/X^{}` con el commit real; se prefiere ése.
    peeled = [l for l in lines if l.endswith("^{}")]
    sha = (peeled or lines)[0].split()[0]
    return sha, ""


def local_head(repo: Path) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                              capture_output=True, **TEXT_IO, timeout=20)
        return proc.stdout.strip() if proc.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


# ── verificación ─────────────────────────────────────────────────────────────────────
def verify(workspace: Path, lock: dict | None, *, check_remote: bool = False) -> Result:
    """Comprueba el árbol contra el lock. **Nunca lo escribe** (invariante I1).

    Cinco formas de deriva, y las cinco tienen un veredicto propio:

        archivo modificado   FAIL — la huella no coincide
        archivo ausente      FAIL — se materializó y se borró
        archivo de más       FAIL — hay algo del origen que el lock no declara
        commit distinto      FAIL — la referencia apunta a otro sitio que cuando se fijó
        ancla mutable        FAIL — el lock guarda una etiqueta en vez de un SHA
    """
    gate_id, title = "LOCK", "Lock criptográfico del origen"
    threshold = "el árbol coincide con el lock · el ancla es un SHA inmutable · cero deriva"

    if lock is None:
        return Result(gate_id, title, BLOCKED, threshold=threshold,
                      scope=Scope(0, 0, "archivos anclados", declared=False, subject="harness.lock.json"),
                      measure="no hay harness.lock.json: el espacio no declara con qué origen "
                              "se materializó. Ejecute `refuto lock init`.")
    if lock.get("schema") != LOCK_SCHEMA:
        return Result(gate_id, title, FAIL, threshold=threshold,
                      scope=Scope(0, 0, "archivos anclados", declared=False, subject="harness.lock.json"),
                      measure=f"esquema de lock desconocido: {lock.get('schema')!r}")

    findings: list = []
    observations: list = []
    total_files = 0

    for name, entry in sorted((lock.get("sources") or {}).items()):
        commit = (entry.get("commit") or "").strip()
        ref = entry.get("ref", "")

        # I2 · el ancla persistida tiene que ser un SHA. Una etiqueta no ancla nada.
        if len(commit) not in _SHA_LEN or not all(c in "0123456789abcdef" for c in commit.lower()):
            findings.append(Finding(
                f"lock.sources.{name}", "el ancla no es un SHA de commit: "
                f"{commit!r}. Una etiqueta es mutable; quien la mueva cambia lo que se "
                f"materializa sin que el lock lo note."))
            continue

        files = entry.get("files") or {}
        total_files += len(files)
        for rel, expected in sorted(files.items()):
            path = workspace / rel
            if not path.is_file():
                findings.append(Finding(rel, "declarado en el lock y ausente del árbol"))
                continue
            actual = sha256_file(path)
            if actual != expected:
                findings.append(Finding(
                    rel, f"huella distinta de la del lock (esperada {expected[:12]}…, "
                         f"hallada {actual[:12]}…): se materializó y después se editó aquí"))

        # I3 · si se pide, se comprueba que la referencia siga apuntando al mismo commit.
        if check_remote and entry.get("uri"):
            sha, err = resolve_ref(entry["uri"], ref)
            if err:
                observations.append(f"«{name}»: no se pudo comprobar el origen — {err}")
            elif sha != commit:
                findings.append(Finding(
                    f"lock.sources.{name}",
                    f"la referencia «{ref}» de {entry['uri']} apunta ahora a {sha[:12]}… y el "
                    f"lock fijó {commit[:12]}…. La etiqueta SE MOVIÓ. No se actualiza sola: "
                    f"revise el cambio y ejecute `refuto lock update --source {name}`."))
            else:
                observations.append(f"«{name}»: la referencia «{ref}» sigue en {commit[:12]}…")

    n_origenes = len(lock.get("sources") or {})
    measure = (f"{n_origenes} orígenes · {total_files} archivos anclados · "
               f"{len(findings)} desviaciones"
               + ("" if check_remote else " · origen remoto NO comprobado (use --check-remote)"))
    if not check_remote:
        observations.append(
            "Sin --check-remote esta puerta comprueba deriva LOCAL. Una etiqueta movida en el "
            "origen sólo se detecta consultando el origen.")

    # Ámbito vacío. `PASS if not findings` no consultaba `total_files`, así que un lock con
    # `sources: {}` —o con un origen declarado y CERO ficheros anclados— aprobaba con la
    # medida «0 archivos anclados · 0 desviaciones» escrita en voz alta. Medido el
    # 2026-09-23, tres formas del mismo cero. Comparar cero huellas contra cero huellas es
    # cierto y no demuestra nada sobre el origen. Ver FORMAL-MODEL §3.3.
    if total_files == 0 and not findings:
        if n_origenes == 0:
            return Result(gate_id, title, NOT_APPLICABLE, threshold=threshold,
                          scope=Scope(0, 0, "archivos anclados", declared=False),
                          measure="no aplica en este espacio — el lock no declara ningún "
                                  "origen que materializar, luego no hay huella que "
                                  "comparar. No es un aprobado: no se comprobó nada.",
                          observations=observations)
        return Result(gate_id, title, BLOCKED, threshold=threshold,
                      scope=Scope(0, 0, "archivos anclados", declared=True),
                      measure=f"no se intentó — el lock declara {n_origenes} origen(es) y "
                              f"CERO archivos anclados. Un origen sin huellas no ancla nada: "
                              f"el árbol podría ser cualquiera y la comprobación saldría "
                              f"igual. Ejecute `refuto lock update`.",
                      observations=observations)

    return Result(gate_id, title, PASS if not findings else FAIL, threshold=threshold,
                  scope=Scope(total_files, 0, "archivos anclados", declared=n_origenes > 0),
                  measure=measure, findings=findings, observations=observations)


# ── actualización explícita ──────────────────────────────────────────────────────────
def build_source_lock(name: str, uri: str, ref: str, commit: str, workspace: Path,
                      files: list, manifest_digest: str = "") -> SourceLock:
    from core.digest import digest_tree
    hashes = {rel: sha256_file(workspace / rel) for rel in sorted(files)
              if (workspace / rel).is_file()}
    return SourceLock(name=name, uri=uri, ref=ref, commit=commit,
                      manifest_digest=manifest_digest,
                      tree_digest=digest_tree(workspace, sorted(hashes)),
                      files=hashes, resolved_at=now())


def plan_update(current: dict | None, proposed: SourceLock) -> dict:
    """Qué cambiaría al actualizar. Se muestra ANTES de escribir, siempre.

    Un lock que se actualiza solo no es un lock. Este plan es lo que convierte la
    actualización en una decisión y no en un efecto secundario.
    """
    entry = ((current or {}).get("sources") or {}).get(proposed.name) or {}
    old_files = entry.get("files") or {}
    new_files = proposed.files
    return {
        "source": proposed.name,
        "commit_from": entry.get("commit", ""),
        "commit_to": proposed.commit,
        "ref_from": entry.get("ref", ""),
        "ref_to": proposed.ref,
        "added": sorted(set(new_files) - set(old_files)),
        "removed": sorted(set(old_files) - set(new_files)),
        "changed": sorted(r for r in set(old_files) & set(new_files)
                          if old_files[r] != new_files[r]),
        "unchanged": len([r for r in set(old_files) & set(new_files)
                          if old_files[r] == new_files[r]]),
    }


def write_lock(path: Path, sources: dict) -> None:
    """Escribe el lock. Sólo se llama desde `refuto lock init|update`, nunca desde `verify`."""
    from core.model import write_json
    write_json(path, {
        "schema": LOCK_SCHEMA,
        "_que_es": "Con qué origen exacto —commit, no etiqueta— se materializó este espacio, y "
                   "con qué huella cada archivo. Es evidencia y es control. No se edita a mano; "
                   "`refuto verify` lo comprueba y NUNCA lo reescribe.",
        "generated_at": now(),
        "sources": {name: src.to_dict() for name, src in sorted(sources.items())},
    })
