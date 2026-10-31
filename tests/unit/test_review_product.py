"""Privacy boundary, provenance and incremental retrieval, with synthetic data only."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import runpy

# The collector is a CLI script, not an installed third-party package.
_review = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/review_product.py"))
REPO = _review["REPO"]
collect = _review["collect"]
index_corpus = _review["index_corpus"]
normalize = _review["normalize"]
vector = _review["vector"]


class TestReviewProduct(unittest.TestCase):
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
            with sqlite3.connect(out/"research.sqlite") as db:
                self.assertEqual(1, db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0])
                self.assertEqual(1, len(db.execute("SELECT id FROM search WHERE search MATCH 'deny'").fetchall()))
            doc.write_text("replacement evidence")
            index_corpus(out, [("research", root)])
            with sqlite3.connect(out/"research.sqlite") as db:
                self.assertEqual([], db.execute("SELECT id FROM search WHERE search MATCH 'deny'").fetchall())
            doc.unlink()
            index_corpus(out, [("research", root)])
            with sqlite3.connect(out/"research.sqlite") as db:
                self.assertEqual(0, db.execute("SELECT COUNT(*) FROM chunks").fetchone()[0])

    def test_vector_is_repeatable_and_normalized(self):
        self.assertEqual(vector("policy evidence"), vector("policy evidence"))
        self.assertAlmostEqual(1.0, sum(x*x for x in vector("policy evidence")))
        self.assertEqual([0.0]*128, vector(""))
