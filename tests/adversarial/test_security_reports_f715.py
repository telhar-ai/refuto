"""Synthetic process/FS controls; no real credentials, network or host scan."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from gates import g_security as gate


class SecurityReports(unittest.TestCase):
    def run_report(self, tool, code, value):
        program = "import sys; print(" + repr(json.dumps(value)) + "); sys.exit(" + str(code) + ")"
        return gate._run_json([sys.executable, "-c", program], kind=tool, timeout=3)

    def test_nonzero_valid_json_is_not_success(self):
        for tool in ["syft", "trivy"]:
            for value in [{}, {"error": "synthetic"}, {"artifacts": []}, {"Results": []}]:
                self.assertFalse(self.run_report(tool, 2, value)["ok"])

    def test_malformed_shapes_are_not_clean_reports(self):
        for tool in ["gitleaks", "syft", "trivy"]:
            for value in [None, {}, {"error": "synthetic"}, "clean", 0]:
                self.assertFalse(self.run_report(tool, 0, value)["ok"])

    def test_positive_reports_and_gitleaks_findings_exit_one(self):
        self.assertTrue(self.run_report("gitleaks", 0, [])["ok"])
        finding = {"File": "app.txt", "RuleID": "synthetic", "StartLine": 1}
        self.assertTrue(self.run_report("gitleaks", 1, [finding])["ok"])
        self.assertFalse(self.run_report("gitleaks", 1, [])["ok"])
        self.assertFalse(self.run_report("gitleaks", 2, [finding])["ok"])
        self.assertTrue(self.run_report("syft", 0, {"artifacts": [], "schema":{"version":"16.1.0"}, "descriptor":{"name":"syft","version":"1.51.1"}, "source":{"type":"directory"}})["ok"])
        self.assertTrue(self.run_report("trivy", 0, {"SchemaVersion": 2, "ArtifactName": "fixture", "ArtifactType": "filesystem", "Results": []})["ok"])

    def test_report_envelopes_and_nested_types_are_fail_closed(self):
        syft = {"artifacts": [], "schema":{"version":"16.1.0"}, "descriptor":{"name":"syft","version":"1.51.1"}, "source":{"type":"directory"}}
        trivy = {"SchemaVersion":2,"ArtifactName":"fixture","ArtifactType":"filesystem","Results":[]}
        for tool, report in [("syft",syft),("trivy",trivy)]:
            for extra in [{"error":"synthetic"},{"success":False},{"errors":[]}]:
                self.assertFalse(self.run_report(tool,0,{**report,**extra})["ok"])
        for artifacts in [[{}], [{"id":"x","name":"pkg","version":None,"type":"npm"}]]:
            self.assertFalse(self.run_report("syft",0,{**syft,"artifacts":artifacts})["ok"])
        self.assertFalse(self.run_report("trivy",0,{**trivy,"SchemaVersion":999})["ok"])
        for severity in [[],{},False,None,"HIGH"]:
            report={**trivy,"Results":[{"Target":"fixture","Vulnerabilities":[{"Severity":severity}]}]}
            self.assertFalse(self.run_report("trivy",0,report)["ok"])

    def test_reference_classification_is_anchored_and_does_not_hide_literals(self):
        from core.digest import _es_referencia
        for value in ['"opaque_env_synthetic_12345"', '"opaque(synthetic)_12345"', '"environment"']:
            self.assertFalse(_es_referencia(value))
        for value in ['process.env.TEST_SECRET', 'os.environ["TEST_SECRET"]', '"${TEST_SECRET}"', '"placeholder"']:
            self.assertTrue(_es_referencia(value))

    def test_environment_reference_cannot_hide_a_literal_default(self):
        from core.digest import classify
        for line in [
            'token = os.getenv("FIXTURE_ENV", "synthetic-default")',
            'let token = std::env::var("FIXTURE_ENV").unwrap_or("synthetic-default");',
            'token = getenv("FIXTURE_ENV") + "synthetic-default"',
        ]:
            proof, indications=classify(line)
            self.assertEqual(proof,[]);self.assertTrue(indications)
        for line in ['token = os.getenv("FIXTURE_ENV")', 'let token = std::env::var("FIXTURE_ENV")?;']:
            self.assertEqual(classify(line),([],[]))

    def test_environment_reference_is_not_a_confirmed_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"app.txt").write_text('secret = process.env.TEST_SECRET\n')
            self.assertEqual(gate._scan_secrets(root), (1, 0, []))

    def test_ambiguous_detector_result_is_not_silently_approved(self):
        from core.context import Context
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(gate, '_scan_secrets', return_value=(1, 0, [('app.txt', 1, ['REVIEW_REQUIRED'])])), patch('shutil.which', return_value=None):
                result = gate.run(Context(workspace=Path(directory)))
            self.assertNotEqual(result.status, 'PASS')
            self.assertTrue(any('revisión' in o for o in result.observations))

    def test_multiline_private_key_delimiters_without_key_material(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            begin = "-----BEGIN " + "PRIVATE KEY-----"
            end = "-----END " + "PRIVATE KEY-----"
            (root/"app.txt").write_text("first line\n"+begin+"\nSYNTHETIC-NOT-KEY-MATERIAL\n"+end+"\n")
            self.assertIn(("app.txt", 2, ["PRIVKEY"]), gate._scan_secrets(root)[2])

    def test_oversized_file_is_unknown_not_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"large.txt").write_text("x"*(gate.MAX_BYTES+1))
            self.assertEqual(gate._scan_secrets(root)[:2], (0, 1))

    def test_directory_scan_is_not_implicitly_git_history_scan(self):
        from core.context import Context
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/"app.txt").write_text("plain\n")
            with patch('shutil.which', return_value='tool'), patch.object(gate,'_run_json', return_value={"ok":False,"error":"synthetic"}) as run:
                gate.run(Context(workspace=root))
            self.assertIn('--no-git',run.call_args_list[0].args[0])


if __name__ == '__main__':
    unittest.main()
