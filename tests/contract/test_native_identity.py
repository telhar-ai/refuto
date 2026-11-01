"""Actual guard subprocesses and file effects, not a claim about native hook loading."""
import json
import os
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from core.guard import normalize, digest_entrada
from core.telemetry import resumen
from core.proc import TEXT_IO

ROOT = Path(__file__).resolve().parents[2]


class TestNativeIdentity(unittest.TestCase):
    def test_only_documented_dialects_get_reported_identity(self):
        for runtime in ("claude", "codex", "kiro"):
            f = normalize(runtime, {"session_id": "fixture-session", "tool_use_id": "fixture-call"})
            self.assertEqual("reported" if runtime != "kiro" else "unavailable", f["identity_status"])

    def test_malformed_or_absent_identity_is_never_minted(self):
        for value in (None, 1, True, {}, [], "", " "*5, "x"*513):
            with self.subTest(value_type=type(value).__name__):
                f = normalize("claude", {"session_id": "s", "tool_use_id": value})
                self.assertIsNone(f["tool_call_id"])
                self.assertEqual("incomplete", f["identity_status"])

    def test_content_digest_remains_content_not_call_identity(self):
        base = {"session_id": "s", "tool_name": "Bash", "tool_input": {"command": "true"}}
        a = normalize("claude", {**base, "tool_use_id": "a"})
        b = normalize("claude", {**base, "tool_use_id": "b"})
        self.assertEqual(digest_entrada(a), digest_entrada(b))
        self.assertNotEqual(a["tool_call_id"], b["tool_call_id"])

    def test_pre_effect_post_preserve_scoped_call_identity(self):
        for runtime in ("claude", "codex"):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as tmp:
                ws = Path(tmp)
                env = {k:v for k,v in os.environ.items() if not k.startswith("HARNESS_")}
                env["HARNESS_RUN_ID"] = "fixture-harness-session"
                execution = [sys.executable, "-c", "from pathlib import Path; "
                             "Path('effect.txt').write_bytes(b'verified fixture effect')"]
                payload = {"session_id": "fixture-native-session", "tool_use_id": "fixture-call",
                           "tool_name": "Bash", "tool_input": {"command": shlex.join(execution)},
                           "cwd": str(ws)}
                argv = [sys.executable, "-m", "core.guard", "--runtime", runtime,
                        "--workspace", str(ws), "--stdin"]
                pre = subprocess.run(argv, input=json.dumps(payload),
                                     capture_output=True, cwd=ROOT, env=env, timeout=30, **TEXT_IO)
                self.assertEqual(0, pre.returncode, pre.stderr)
                if runtime == "claude":
                    self.assertEqual("allow", json.loads(pre.stdout)["hookSpecificOutput"]["permissionDecision"])
                else:
                    self.assertEqual("", pre.stdout)
                # Dispatch the exact argv whose command was submitted; this fixture is
                # the caller, not a native Codex/Claude session.
                effect = ws / "effect.txt"
                effect_result = subprocess.run(execution, cwd=ws, env=env, capture_output=True,
                                               timeout=30, **TEXT_IO)
                self.assertEqual(0, effect_result.returncode, effect_result.stderr)
                self.assertEqual(b"verified fixture effect", effect.read_bytes())
                post = subprocess.run(argv+["--post"], input=json.dumps({**payload,
                                      "tool_response": {"exit_code": 0}}),
                                      capture_output=True, cwd=ROOT, env=env, timeout=30, **TEXT_IO)
                self.assertEqual(0, post.returncode, post.stderr)
                events = [json.loads(line) for line in (ws/".harness/evidence/ledger.jsonl").read_text().splitlines()]
                self.assertEqual(2, len(events))
                for e in events:
                    self.assertEqual("fixture-native-session", e["session_id"])
                    self.assertEqual("fixture-call", e["tool_call_id"])
                    self.assertEqual("fixture-harness-session", e["run_id"])
                    self.assertNotIn("effect_verified", e)
                s = resumen(events)["herramientas_s"]
                self.assertEqual(1, s["emparejados_por_identidad"])
