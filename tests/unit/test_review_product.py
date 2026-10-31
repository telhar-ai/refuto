"""Privacy boundary, provenance and incremental retrieval, with synthetic data only."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import runpy
import contextlib
import io
from unittest.mock import patch

# The collector is a CLI script, not an installed third-party package.
_review = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/review_product.py"))
REPO = _review["REPO"]
collect = _review["collect"]
index_corpus = _review["index_corpus"]
normalize = _review["normalize"]
vector = _review["vector"]


class TestReviewProduct(unittest.TestCase):
    def test_sqlite_snapshot_counts_hostile_identifiers_without_executing_sql(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)/"home"
            (home/".codex").mkdir(parents=True)
            original = home/".codex/fixture.sqlite"
            with contextlib.closing(sqlite3.connect(original)) as db, db:
                db.executescript('''CREATE TABLE ordinary(value TEXT);
                    INSERT INTO ordinary VALUES ('fixture');
                    CREATE TABLE "odd""name; DROP TABLE ordinary;--"(value TEXT);
                    INSERT INTO "odd""name; DROP TABLE ordinary;--" VALUES ('fixture');''')
            before = original.read_bytes()
            out = Path(tmp)/"review"
            connections = []
            real_connect = sqlite3.connect
            def capture_connection(*args, **kwargs):
                conn = real_connect(*args, **kwargs)
                connections.append(conn)
                return conn
            with patch.object(Path, "home", return_value=home), \
                    patch.object(_review["telemetry"], "espacios_registrados", return_value={}), \
                    patch.object(sqlite3, "connect", side_effect=capture_connection), \
                    contextlib.redirect_stdout(io.StringIO()):
                collect(out)
            try:
                self.assertEqual(2, len(connections))
                for conn in connections:
                    with self.assertRaises(sqlite3.ProgrammingError):
                        conn.execute("SELECT 1")
            finally:
                for conn in connections:
                    conn.close()
            results = json.loads((out/"sqlite.private.json").read_text())
            self.assertEqual(1, len(results))
            self.assertNotIn("error_type", results[0])
            self.assertEqual([["ok"]], results[0]["quick_check"])
            self.assertEqual({"ordinary": 1, 'odd"name; DROP TABLE ordinary;--': 1},
                             results[0]["table_counts"])
            self.assertEqual(before, original.read_bytes())

    def test_reported_run_is_not_a_conversation_session(self):
        for raw in ({"kind": "policy/decision", "run_id": "orq_fixture"},
                    {"kind": "policy/decision", "run_id": "orq_fixture", "session_id": "native"}):
            with self.subTest(explicit_session="session_id" in raw):
                e = normalize(raw, "ledger", "fixture", 1)
                self.assertEqual("refuto.review.event/v2", e["schema"])
                self.assertIsNotNone(e["reported_run_id"])
                self.assertEqual("session_id" not in raw, e["session_id"] is None)
                self.assertNotEqual(e["session_id"], e["reported_run_id"])
                self.assertNotIn("orq_fixture", json.dumps(e))

    def test_private_output_cannot_enter_public_checkout(self):
        for operation in (collect, lambda p: index_corpus(p, [])):
            with self.assertRaises(ValueError):
                operation(REPO / "review-private")

    def test_text_secrets_and_paths_do_not_enter_normalized_event(self):
        e = normalize({"timestamp": "2026-10-31T00:00:00Z", "type": "message",
                       "sessionId": "private-session", "cwd": "/private/customer",
                       "content": "secret-token", "payload": {"text": "secret-token"}},
                      "claude", "abc", 4)
        text = json.dumps(e)
        self.assertNotIn("secret-token", text)
        self.assertNotIn("private-session", text)
        self.assertNotIn("/private/customer", text)
        self.assertEqual({"sha256": "abc", "line": 4}, e["evidence_reference"])
        self.assertIsNone(e["task_id"])
        self.assertIsNone(e["effect_observed"])

    def test_index_updates_deletes_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/"corpus"
            root.mkdir()
            doc = root/"example.md"
            out = Path(t)/"index"
            doc.write_text("authorization policy deny")
            for _ in range(2):
                index_corpus(out, [("research", root)])
            with contextlib.closing(sqlite3.connect(out/"research.sqlite")) as db, db:
                self.assertEqual(1, db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0])
                self.assertEqual(1, len(db.execute("SELECT id FROM search WHERE search MATCH 'deny'").fetchall()))
            doc.write_text("replacement evidence")
            index_corpus(out, [("research", root)])
            with contextlib.closing(sqlite3.connect(out/"research.sqlite")) as db, db:
                self.assertEqual([], db.execute("SELECT id FROM search WHERE search MATCH 'deny'").fetchall())
            doc.unlink()
            index_corpus(out, [("research", root)])
            with contextlib.closing(sqlite3.connect(out/"research.sqlite")) as db, db:
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0])

    def test_vector_is_repeatable_and_normalized(self):
        self.assertEqual(vector("policy evidence"), vector("policy evidence"))
        self.assertAlmostEqual(1.0, sum(x*x for x in vector("policy evidence")))
        self.assertEqual([0.0]*128, vector(""))
