# -*- coding: utf-8 -*-
"""Selftest: disjoint case outcomes, separate fixture incidents, explicit provenance."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SUITES = ("unit", "contract", "selftest", "adversarial")
CATEGORIES = ("PASS", "FAIL", "ERROR", "XPASS", "XFAIL", "SKIP", "UNKNOWN")


class AccountingResult(unittest.TextTestResult):
    """One outcome per started case, even with multiple failing subtests.

    ERROR takes precedence over FAIL; a skipped subtest makes the otherwise successful
    parent SKIP. Class/module setup incidents without a started case remain separate.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.case_counts = Counter({k: 0 for k in CATEGORIES})
        self.fixture_incidents = Counter()
        self._active = None
        self._flags = set()

    def startTest(self, test):
        self._active = test
        self._flags = set()
        super().startTest(test)

    def _mark(self, outcome):
        if self._active is None:
            self.fixture_incidents[outcome] += 1
        else:
            self._flags.add(outcome)

    def stopTest(self, test):
        category = next((k for k in ("ERROR", "FAIL", "XPASS", "XFAIL", "SKIP", "PASS")
                         if k in self._flags), "UNKNOWN")
        self.case_counts[category] += 1
        self._active = None
        super().stopTest(test)

    def addSuccess(self, test):
        self._mark("PASS")
        super().addSuccess(test)

    def addFailure(self, test, err):
        self._mark("FAIL")
        super().addFailure(test, err)

    def addError(self, test, err):
        self._mark("ERROR")
        super().addError(test, err)

    def addSkip(self, test, reason):
        self._mark("SKIP")
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self._mark("XFAIL")
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self._mark("XPASS")
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self._mark("FAIL" if issubclass(err[0], test.failureException) else "ERROR")
        super().addSubTest(test, subtest, err)


def source_state(root: Path) -> dict:
    """Hash tracked and nonignored untracked bytes. Never hash ignored private state.

    This detects different boundary snapshots, not transient edits restored mid-run.
    An immutable checkout is required to exclude that stronger threat.
    """
    try:
        def git(*args):
            return subprocess.check_output(["git", "-C", str(root), *args],
                                           stderr=subprocess.DEVNULL, timeout=20)
        revision = git("rev-parse", "HEAD").decode().strip()
        names = sorted(set(git("ls-files", "-co", "--exclude-standard", "-z").split(b"\0")) - {b""})
        h = hashlib.sha256()
        for name in names:
            path = root / name.decode("utf-8", "surrogateescape")
            data = path.readlink().as_posix().encode() if path.is_symlink() else path.read_bytes()
            h.update(name + b"\0" + hashlib.sha256(data).digest())
        return {"revision": revision, "source_digest": h.hexdigest()}
    except (OSError, subprocess.SubprocessError):
        return {"revision": None, "source_digest": None}


def run_suites(only: list | None = None, verbose: bool = False,
               report_file: Path | None = None) -> int:
    """No tests, only skips, XPASS, unknown outcomes or source drift cannot approve."""
    if report_file is not None:
        report_file = Path(report_file).resolve()
        if report_file == ROOT.resolve() or ROOT.resolve() in report_file.parents:
            print("El informe local debe guardarse fuera del repositorio público.", file=sys.stderr)
            return 64
    sys.path.insert(0, str(ROOT))
    names = [s for s in SUITES if not only or s in only]
    unknown = [s for s in (only or []) if s not in SUITES]
    if unknown:
        print(f"\n  suite desconocida: {', '.join(unknown)}. Las que hay: {', '.join(SUITES)}.")
        return 1
    started_at = datetime.now(timezone.utc).isoformat()
    before = source_state(ROOT)
    loader = unittest.TestLoader()
    master = unittest.TestSuite()
    for name in names:
        directory = ROOT / "tests" / name
        if directory.is_dir():
            master.addTests(loader.discover(str(directory), pattern="test_*.py", top_level_dir=str(ROOT)))
    discovered = master.countTestCases()
    t0 = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2 if verbose else 1, stream=sys.stdout,
                                    resultclass=AccountingResult).run(master)
    elapsed = time.monotonic() - t0
    after = source_state(ROOT)
    bad, reasons = veredicto(result)
    counts = dict(result.case_counts)
    reconciled = sum(counts.values()) == result.testsRun
    drift = before != after
    empty = result.testsRun == 0 or result.testsRun == counts["SKIP"]
    status = ("FAIL" if bad else "INCONCLUSIVE" if drift or not reconciled or counts["UNKNOWN"]
              else "NOT_APPLICABLE" if empty else "PASS")
    report = {"schema": "refuto.selftest/v1", "status": status, "suites": names,
              "started_at": started_at, "finished_at": datetime.now(timezone.utc).isoformat(),
              "duration_seconds": elapsed, "discovered": discovered, "started": result.testsRun,
              "not_started": max(0, discovered - result.testsRun), "cases": counts,
              "fixture_incidents": dict(result.fixture_incidents), "reconciled": reconciled,
              "source_before": before, "source_after": after, "source_changed": drift,
              "environment": {"python": platform.python_version(), "os": platform.system(),
                              "architecture": platform.machine()}}
    print(f"\n  {counts['PASS']}/{result.testsRun} pruebas pasan · suites: {', '.join(names)}")
    print("  " + " · ".join(f"{k}={counts[k]}" for k in CATEGORIES))
    print(f"  descubiertas={discovered} · iniciadas={result.testsRun} · estado={status}")
    for reason in reasons:
        print(f"  {reason}")
    if empty:
        print("  No hubo casos comprobados: una suite vacía o íntegramente omitida no aprueba.")
    if drift:
        print("  El código o HEAD cambiaron durante la corrida; no certifica una revisión fija.")
    if report_file is not None:
        try:
            report_file.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                                   encoding="utf-8", newline="\n")
        except OSError as exc:
            print(f"  No se pudo preservar el informe: {exc}", file=sys.stderr)
            return 1
    return 0 if status == "PASS" else 1


def veredicto(result) -> tuple[int, list]:
    """Cuántas incidencias dejan la corrida en rojo, y por qué. Función aparte para poder
    probarla con un `TestResult` fabricado, sin montar una suite entera.

    El tercer cubo, y por qué faltaba
    ---------------------------------
    Esto contaba `failures + errors` y nada más. `unittest` tiene un tercer cubo que también
    invalida la corrida y que `wasSuccessful()` sí consulta: **`unexpectedSuccesses`**.

    Cuándo aparece. Alguien marca una prueba `@unittest.expectedFailure` para mantener
    VISIBLE un defecto conocido sin romper la cadena — es la única forma honesta de no
    perder la constancia de algo que no se puede arreglar todavía. El día que el defecto se
    corrige, esa prueba pasa, y `unittest` lo llama `unexpectedSuccess` precisamente porque
    es información: el decorador sobra.

    Con el recuento viejo, ese día no pasaba nada. La corrida salía verde, el decorador se
    quedaba puesto para siempre, y a partir de ahí esa prueba **no comprobaba nada**: pasara
    o fallara, el resultado era el mismo. El mecanismo que existe para no perder de vista un
    defecto se quedaba mudo justo cuando el defecto se arreglaba.

    Medido el 2026-09-23. Encontrado en otro espacio con la misma forma de recuento y
    verificado aquí: `bad = len(result.failures) + len(result.errors)` — el tercer cubo no
    estaba.
    """
    fallos = len(result.failures)
    errores = len(result.errors)
    inesperadas = len(getattr(result, "unexpectedSuccesses", []) or [])
    motivos = []
    if fallos or errores:
        motivos.append(f"{fallos + errores} incidencias de fallo/error. Un juez que no se prueba a sí mismo deja "
                       f"de ser un juez.")
    if inesperadas:
        nombres = ", ".join(str(t).split(" ")[0]
                            for t in result.unexpectedSuccesses[:4])
        motivos.append(
            f"{inesperadas} pasaron estando marcadas `@expectedFailure`: {nombres}. "
            f"Eso NO es una buena noticia silenciosa — es que el defecto que documentaban "
            f"se arregló y el decorador sobra. Retírelo, o la prueba deja de comprobar nada.")
    return fallos + errores + inesperadas, motivos
