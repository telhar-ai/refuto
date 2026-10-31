"""Execute the real runner in a fresh interpreter against synthetic fixture suites."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import shutil
import unittest

from core.schema import load_schema, validate
from core.proc import TEXT_IO

RUNNER = Path(__file__).resolve().parents[1] / "runner.py"


class TestRunnerReport(unittest.TestCase):
    def run_fixture(self, body, git_repo=False):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/"checkout"
            unit = root/"tests/unit"
            unit.mkdir(parents=True)
            for p in (root/"tests/__init__.py", unit/"__init__.py"):
                p.write_text("", encoding="utf-8")
            (unit/"test_fixture.py").write_text("import unittest\n"+body, encoding="utf-8")
            if git_repo:
                (root/".gitignore").write_text("__pycache__/\n", encoding="utf-8")
                hooks = Path(tmp)/"empty-hooks"
                hooks.mkdir()
                env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
                argv = ["git", "-C", str(root), "-c", "user.name=Fixture",
                        "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
                        "-c", f"core.hooksPath={hooks}"]
                subprocess.run(argv+["init", "-q"], env=env, check=True, capture_output=True)
                subprocess.run(argv+["commit", "-q", "--allow-empty", "-m", "fixture"],
                               env=env, check=True, capture_output=True)
            report = Path(tmp)/"result.json"
            script = ("import importlib.util,pathlib,sys; "
                      f"s=importlib.util.spec_from_file_location('fixture_runner',{str(RUNNER)!r}); "
                      "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
                      f"m.ROOT=pathlib.Path({str(root)!r}); "
                      f"sys.exit(m.run_suites(report_file=pathlib.Path({str(report)!r})))")
            p = subprocess.run([sys.executable,"-c",script],
                               capture_output=True, timeout=30, **TEXT_IO)
            result = json.loads(report.read_text())
            self.assertEqual([], validate(result, load_schema("selftest.schema.json")))
            return p, result

    def test_ordinary_pass_and_skip_are_distinct_in_real_report(self):
        p, r = self.run_fixture("class Cases(unittest.TestCase):\n"
                               " def test_pass(self): pass\n"
                               " @unittest.skip('fixture')\n"
                               " def test_skip(self): pass\n")
        self.assertEqual(0,p.returncode,p.stdout+p.stderr)
        self.assertEqual(1,r['cases']['PASS'])
        self.assertEqual(1,r['cases']['SKIP'])
        self.assertEqual(2,r['discovered'])
        self.assertEqual(r['started'],sum(r['cases'].values()))

    def test_all_skipped_cannot_approve(self):
        p,r=self.run_fixture("@unittest.skip('fixture')\n"
                             "class Cases(unittest.TestCase):\n"
                             " def test_skip(self): pass\n")
        self.assertNotEqual(0,p.returncode)
        self.assertEqual('NOT_APPLICABLE',r['status'])
        self.assertEqual(0,r['cases']['PASS'])

    def test_fixture_error_is_not_a_started_test_case(self):
        p,r=self.run_fixture("class Cases(unittest.TestCase):\n"
                             " @classmethod\n"
                             " def setUpClass(cls): raise ValueError('fixture')\n"
                             " def test_never_started(self): pass\n")
        self.assertNotEqual(0,p.returncode)
        self.assertEqual('FAIL',r['status'])
        self.assertEqual(1,r['fixture_incidents']['ERROR'])
        self.assertEqual(0,r['started'])
        self.assertEqual(1,r['not_started'])

    def test_xpass_remains_a_failing_suite(self):
        p,r=self.run_fixture("class Cases(unittest.TestCase):\n"
                             " @unittest.expectedFailure\n"
                             " def test_fixed(self): pass\n")
        self.assertNotEqual(0,p.returncode)
        self.assertEqual('FAIL',r['status'])
        self.assertEqual(1,r['cases']['XPASS'])

    @unittest.skipUnless(shutil.which("git"), "Git required for source fingerprint fixture")
    def test_real_source_change_invalidates_a_passing_suite(self):
        p,r=self.run_fixture("from pathlib import Path\nclass Cases(unittest.TestCase):\n"
                             " def test_mutate(self):\n"
                             "  (Path(__file__).resolve().parents[2]/'changed.txt').write_bytes(b'fixture')\n",
                             git_repo=True)
        self.assertEqual(1,r['cases']['PASS'])
        self.assertTrue(r['source_changed'])
        self.assertEqual('INCONCLUSIVE',r['status'])
        self.assertNotEqual(0,p.returncode)

    @unittest.skipUnless(shutil.which("git"), "Git required for source fingerprint fixture")
    def test_stable_real_git_fixture_can_approve(self):
        p,r=self.run_fixture("class Cases(unittest.TestCase):\n def test_pass(self): pass\n",
                             git_repo=True)
        self.assertEqual(0,p.returncode,p.stdout+p.stderr)
        self.assertFalse(r['source_changed'])
        self.assertIsNotNone(r['source_before']['source_digest'])
