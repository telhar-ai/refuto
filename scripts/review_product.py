#!/usr/bin/env python3
"""Offline forensic review. Private outputs MUST be outside the checkout.

Free text is omitted from normalized data; metadata still requires privacy review.
Original paths are retained only in the private manifest. Originals are never written.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import collections
import hashlib
import gzip
import json
import math
import os
from pathlib import Path
import platform
import sqlite3
import sys
import re
from datetime import datetime, timezone

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from core import telemetry  # noqa: E402

SCHEMA = "refuto.review.event/v2"
PRIVACY_PATTERNS = {
    "token_shape": rb"\b(?:AKIA[A-Z0-9]{16}|sk-[A-Za-z0-9_-]{20,})\b",
    "private_key": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    "email_shape": rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "home_path": rb"/(?:Users|home)/[^/\s\"']+",
    "bearer_shape": rb"(?i)Bearer\s+[A-Za-z0-9._~-]{16,}",
}
FIELDS = "event_id session_id trace_id parent_event_id runtime runtime_version model tool_name tool_call_id reported_run_id timestamp task_id project_id repository branch decision permission_state hook_result exit_code stdout stderr duration token_usage cost retry_count error_type human_intervention artifact_reference commit_reference test_result effect_observed evidence_reference".split()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def ident(value):
    return digest(str(value).encode()) if value not in (None, "") else None


def normalize(raw, runtime, source, line):
    """A source locator is an evidence reference, never a fabricated runtime ID."""
    row = dict.fromkeys(FIELDS)
    p = raw.get("payload") if isinstance(raw.get("payload"), dict) else {}
    row.update(schema=SCHEMA, event_id=f"{source}:{line}", runtime=runtime,
               evidence_reference={"sha256": source, "line": line},
               timestamp=raw.get("ts") or raw.get("timestamp"),
               session_id=ident(raw.get("sessionId") or raw.get("session_id")),
               parent_event_id=ident(raw.get("parentUuid")),
               reported_run_id=ident(raw.get("run_id")),
               tool_name=raw.get("tool"),
               raw_type=raw.get("kind") or raw.get("type"),
               tool_call_id=ident(raw.get("tool_call_id") or p.get("call_id")))
    # Ledger fields have defined semantics; transcript text is deliberately omitted.
    if raw.get("kind") in ("policy/decision", "tool/result"):
        row.update(runtime=raw.get("runtime") or runtime, decision=raw.get("outcome"),
                   exit_code=raw.get("exit_code"), duration=raw.get("duration_ms"),
                   duration_unit="ms", duration_scope="guard_internal",
                   result_ok=raw.get("ok"), policy_digest=raw.get("policy_digest"),
                   input_digest=raw.get("entrada_digest"))
    if raw.get("type") == "session_meta":
        row["session_id"] = ident(p.get("session_id") or p.get("id"))
        row["runtime_version"] = p.get("cli_version")
    return row


def write(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8", newline="\n")


def vector(text):
    """128-dimensional signed token hashing baseline; NOT semantic embeddings."""
    result = [0] * 128
    for token in re.findall(r"\w+", text.lower()):
        h = hashlib.sha256(token.encode()).digest()
        result[int.from_bytes(h[:2], "big") % 128] += 1 if h[2] & 1 else -1
    norm = math.sqrt(sum(x*x for x in result))
    return [x/norm if norm else 0.0 for x in result]


def index_corpus(out, corpora):
    """Local indexes separated by corpus, 80 lines/chunk, exact source locations.

    Incremental replacement by file hash; deleted source files lose their chunks.
    Only explicitly selected corpora are read. The caller owns privacy classification.
    """
    out = out.resolve()
    if out == REPO or REPO in out.parents:
        raise ValueError("Indexes must be outside the public checkout")
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    for category, root in corpora:
        if not re.fullmatch(r"[a-z_]+", category):
            raise ValueError("invalid category")
        db = sqlite3.connect(out / (category + ".sqlite"))
        with db:
            db.execute("CREATE TABLE IF NOT EXISTS docs(path TEXT PRIMARY KEY, sha TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS chunks(id TEXT PRIMARY KEY,path TEXT,start INTEGER,end INTEGER,text TEXT,vector TEXT,model TEXT)")
            db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS search USING fts5(id UNINDEXED,text)")
            current = set()
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.suffix not in (".py", ".md", ".html", ".txt", ".jsonl"):
                    continue
                if path.is_symlink():
                    continue
                current.add(str(path))
                data = path.read_bytes()
                sha = digest(data)
                if db.execute("SELECT sha FROM docs WHERE path=?", (str(path),)).fetchone() == (sha,):
                    continue
                db.execute("DELETE FROM search WHERE id IN (SELECT id FROM chunks WHERE path=?)", (str(path),))
                db.execute("DELETE FROM chunks WHERE path=?", (str(path),))
                lines = data.decode("utf-8", errors="replace").splitlines()
                for start in range(0, len(lines), 80):
                    text = "\n".join(lines[start:start+80])
                    cid = digest((category + str(path) + sha + str(start)).encode())
                    db.execute("INSERT INTO chunks VALUES(?,?,?,?,?,?,?)", (cid, str(path), start+1,
                               min(len(lines),start+80), text, json.dumps(vector(text)), "sha256-token-hash/v1:128"))
                    db.execute("INSERT INTO search VALUES(?,?)", (cid, text))
                db.execute("INSERT OR REPLACE INTO docs VALUES(?,?)", (str(path), sha))
            for (path,) in db.execute("SELECT path FROM docs").fetchall():
                if path not in current:
                    db.execute("DELETE FROM search WHERE id IN (SELECT id FROM chunks WHERE path=?)", (path,))
                    db.execute("DELETE FROM chunks WHERE path=?", (path,))
                    db.execute("DELETE FROM docs WHERE path=?", (path,))
        db.close()


def collect(out):
    out = out.resolve()
    if out == REPO or REPO in out.parents:
        raise ValueError("Private review output must be outside the public checkout")
    if (out / "manifest.private.json").exists():
        raise ValueError("Existing forensic capture must not be overwritten; choose a new output")
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out, 0o700)
    snapshots = out / "snapshots"
    snapshots.mkdir(exist_ok=True, mode=0o700)
    sources, candidates, summary = [], [], {"schema": "refuto.review/v1"}
    spaces = telemetry.espacios_registrados()
    roots = [p for paths in spaces.values() for p in paths]
    ledgers = telemetry.diarios(roots)
    summary.update(registered_spaces=len(spaces), registered_roots=len(roots),
                   ledger_discovery_depth=2, ledger_sources=len(ledgers),
                   environment={"python": platform.python_version(), "system": platform.system(),
                                "machine": platform.machine(), "sqlite": sqlite3.sqlite_version},
                   collected_at=datetime.now(timezone.utc).isoformat())
    # Inventory complete JSONL path populations; analyze ALL ledgers and 3 recent
    # transcripts per runtime, bounded to 20 MiB each. This is NOT a random sample.
    for rt, root in (("codex", Path.home()/".codex/sessions"),
                     ("claude", Path.home()/".claude/projects"),
                     ("kiro", Path.home()/".kiro/sessions")):
        files = list(root.rglob("*.jsonl")) if root.is_dir() else []
        selected = set(sorted((p for p in files if p.stat().st_size <= 20*1024*1024),
                              key=lambda p: p.stat().st_mtime, reverse=True)[:3])
        summary[rt] = {"jsonl_files_found": len(files), "selected": len(selected),
                       "bytes_found": sum(p.stat().st_size for p in files)}
        candidates += [(rt, p, p in selected) for p in files]
    candidates += [("ledger", p, True) for p in ledgers]
    counts, missing, sessions = collections.Counter(), collections.Counter(), {}
    decisions = collections.defaultdict(collections.Counter)
    with gzip.open(out/"normalized.jsonl.gz", "wt", encoding="utf-8", newline="\n") as normalized:
        for rt, path, selected in candidates:
            before = path.stat()
            h = hashlib.sha256()
            dest = snapshots / f"copy-{len(sources):05d}.jsonl"
            target = dest.open("wb") if selected else None
            try:
                with path.open("rb") as src:
                    for block in iter(lambda: src.read(1024*1024), b""):
                        h.update(block)
                        if target:
                            target.write(block)
            finally:
                if target:
                    target.close()
            sha = h.hexdigest()
            after = path.stat()
            entry = dict(runtime=rt, original_path=str(path), size=before.st_size,
                         sha256=sha, selected=selected, format="jsonl", records=None,
                         invalid=None, duplicates=None, schema_keys=None,
                         producer_version=None, min_timestamp=None, max_timestamp=None,
                         stable_during_copy=(before.st_size == after.st_size and
                                             before.st_mtime_ns == after.st_mtime_ns))
            if selected:
                entry["snapshot"] = str(dest)
                entry["snapshot_verified"] = digest(dest.read_bytes()) == sha
                # Indicators, not a guarantee of secret detection. Never emit values.
                data = dest.read_bytes()
                entry["privacy_indicators"] = {
                    name: len(re.findall(pattern, data))
                    for name, pattern in PRIVACY_PATTERNS.items()
                }
                del data
                invalid = n = duplicate = 0
                seen, keys, times = set(), collections.Counter(), []
                with dest.open("rb") as f:
                    for line, text in enumerate(f, 1):
                        if not text.strip():
                            continue
                        n += 1
                        try:
                            raw = json.loads(text)
                            if not isinstance(raw, dict):
                                raise ValueError("not object")
                        except (ValueError, UnicodeError):
                            invalid += 1
                            continue
                        lh = digest(text)
                        duplicate += lh in seen
                        seen.add(lh)
                        keys.update(raw.keys())
                        row = normalize(raw, rt, sha, line)
                        if isinstance(row["timestamp"], str):
                            times.append(row["timestamp"])
                        counts[row["runtime"]] += 1
                        for field in FIELDS:
                            if row.get(field) is None:
                                missing[field] += 1
                        if row.get("decision"):
                            decisions[row["runtime"]][row["decision"]] += 1
                        if row["session_id"]:
                            key = row["runtime"] + ":" + row["session_id"]
                            session = sessions.setdefault(key, {"events": 0, "types": collections.Counter()})
                            session["events"] += 1
                            session["types"][str(row["raw_type"])] += 1
                        normalized.write(json.dumps(row, ensure_ascii=False) + "\n")
                entry.update(records=n, invalid=invalid, duplicates=duplicate, schema_keys=dict(keys),
                             min_timestamp=min(times) if times else None,
                             max_timestamp=max(times) if times else None)
            sources.append(entry)
    # Live SQLite is read with mode=ro, then backed up with SQLite's online backup.
    # WAL is included by SQLite. Hash refers to the consistent snapshot, not the live file.
    sqlite_results = []
    for path in sorted((Path.home()/".codex").glob("*.sqlite")):
        dest = snapshots/path.name
        try:
            # SQLite's transaction context does not close its connection.
            with closing(sqlite3.connect(path.as_uri()+"?mode=ro", uri=True, timeout=1)) as src, src:
                with closing(sqlite3.connect(dest)) as dst, dst:
                    src.backup(dst, pages=128, sleep=0.01)
                    tables = dst.execute("SELECT name,sql FROM sqlite_master WHERE type IN ('table','index')").fetchall()
                    integrity = dst.execute("PRAGMA quick_check").fetchall()
                    table_counts = {}
                    for name, _ in tables:
                        quoted = '"' + name.replace('"', '""') + '"'
                        if dst.execute("SELECT type FROM sqlite_master WHERE name=?", (name,)).fetchone()[0] == 'table':
                            # Identificador delimitado, con comillas duplicadas; probado con nombres hostiles.
                            table_counts[name] = dst.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]  # nosec B608
            sqlite_results.append(dict(original_path=str(path), snapshot=str(dest),
                                       sha256=digest(dest.read_bytes()), schema=tables,
                                       quick_check=integrity, table_counts=table_counts))
        except (sqlite3.Error, OSError) as exc:
            sqlite_results.append(dict(original_path=str(path), error_type=type(exc).__name__))
    summary.update(normalized_events=dict(counts), null_fields_in_projection=dict(missing),
                   null_semantics="unknown, redacted or unsupported extraction; not source missingness",
                   decisions_by_runtime={k: dict(v) for k,v in decisions.items()},
                   observed_session_groups=len(sessions),
                   task_acceptance="INCONCLUSIVE: no adjudicated task denominator",
                   sampling="all discovered ledgers; three most recently modified <=20MiB JSONL per runtime")
    write(out/"manifest.private.json", sources)
    write(out/"sqlite.private.json", sqlite_results)
    write(out/"sessions.json", sessions)
    write(out/"summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--corpus", action="append", default=[], metavar="CATEGORY=PATH")
    args = parser.parse_args()
    if args.selftest:
        import unittest
        suite = unittest.defaultTestLoader.discover(str(REPO/"tests/unit"), pattern="test_review_product.py")
        result = unittest.TextTestRunner().run(suite)
        sys.exit(0 if result.wasSuccessful() and result.testsRun else 1)
    if args.output is None:
        parser.error("--output required unless --selftest")
    if args.corpus:
        index_corpus(args.output, [(x.split("=",1)[0], Path(x.split("=",1)[1])) for x in args.corpus])
    else:
        collect(args.output)
