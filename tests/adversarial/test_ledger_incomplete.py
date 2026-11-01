"""Real file attacks: never append across incomplete or malformed evidence."""
import json
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys
import signal
import os
from core.proc import TEXT_IO

try:
    import resource
except ImportError:
    resource = None

from core.evidence import append_event, ledger_path, verificar_cadena, INTEGRA, ROTA


class TestIncompleteEvidence(unittest.TestCase):
    def test_append_refuses_bad_tail_and_preserves_every_byte(self):
        for suffix in (b'x\n', b'[]\n', b'null\n', b'{"h":"partial"}\n', b'{"kind":"\xff"}\n'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as tmp:
                ws = Path(tmp)
                append_event(ws, {"kind": "fixture/start"})
                path = ledger_path(ws)
                path.write_bytes(path.read_bytes() + suffix)
                before = path.read_bytes()
                with self.assertRaises(ValueError):
                    append_event(ws, {"kind": "fixture/next"})
                self.assertEqual(before, path.read_bytes())
                self.assertEqual(ROTA, verificar_cadena(ws)['estado'])

    def test_append_refuses_valid_json_without_commit_delimiter(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            append_event(ws, {"kind": "fixture/start"})
            path = ledger_path(ws)
            path.write_bytes(path.read_bytes().rstrip(b'\n'))
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                append_event(ws, {"kind": "fixture/next"})
            self.assertEqual(before, path.read_bytes())

    def test_corrupted_last_hash_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            append_event(ws, {"kind": "fixture/start"})
            path = ledger_path(ws)
            event = json.loads(path.read_bytes())
            event['kind'] = 'fixture/tampered'
            path.write_text(json.dumps(event)+'\n', encoding='utf-8')
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                append_event(ws, {"kind": "fixture/next"})
            self.assertEqual(before, path.read_bytes())

    def test_guard_does_not_allow_when_a_partial_tail_prevents_audit(self):
        for runtime in ("claude", "codex"):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as tmp:
                ws = Path(tmp)
                append_event(ws,{"kind":"fixture/start"})
                path = ledger_path(ws)
                path.write_bytes(path.read_bytes()+b'{"kind":"partial')
                before = path.read_bytes()
                payload = {"tool_name":"Bash","tool_input":{"command":"true"},"cwd":str(ws)}
                env = {k:v for k,v in os.environ.items() if not k.startswith("HARNESS_")}
                p = subprocess.run([sys.executable,"-m","core.guard","--runtime",runtime,
                                    "--workspace",str(ws),"--stdin"], input=json.dumps(payload),
                                   cwd=Path(__file__).resolve().parents[2], env=env,
                                   capture_output=True, timeout=30, **TEXT_IO)
                decision = json.loads(p.stdout)['hookSpecificOutput']['permissionDecision']
                self.assertEqual('deny' if runtime=='codex' else 'ask',decision)
                self.assertIn('AUDITORÍA INTERRUMPIDA',p.stderr)
                self.assertEqual(before,path.read_bytes())

    def test_non_objects_and_partial_chain_fields_never_verify(self):
        for event in ([], None, 5, True, "text", {"h": "partial"}, {"prev": "partial"}):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as tmp:
                ws = Path(tmp)
                append_event(ws, {"kind": "fixture/start"})
                path = ledger_path(ws)
                with path.open('ab') as f: f.write(json.dumps(event).encode()+b'\n')
                result = verificar_cadena(ws)
                self.assertFalse(result['ok'])
                self.assertEqual(ROTA, result['estado'])

    def test_unchained_event_cannot_downgrade_an_existing_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            append_event(ws, {"kind": "fixture/start"})
            with ledger_path(ws).open('ab') as f: f.write(b'{"kind":"fixture/unhashed"}\n')
            self.assertEqual(ROTA, verificar_cadena(ws)['estado'])

    def test_legacy_prefix_and_normal_append_stay_compatible(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            path = ledger_path(ws)
            path.parent.mkdir(parents=True)
            path.write_bytes(b'{"kind":"fixture/legacy"}\n')
            append_event(ws, {"kind": "fixture/start"})
            append_event(ws, {"kind": "fixture/next"})
            result = verificar_cadena(ws)
            self.assertEqual(INTEGRA, result['estado'])
            self.assertEqual(1, result['legado'])
            self.assertEqual(3, result['eventos'])

    def test_abrupt_process_exit_leaves_partial_evidence_without_automatic_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            append_event(ws, {"kind": "fixture/start"})
            path = ledger_path(ws)
            script = ("import os,sys; "
                      "f=os.open(sys.argv[1],os.O_WRONLY|os.O_APPEND); "
                      "os.write(f,b'{\"kind\":\"partial'); os.fsync(f); os._exit(9)")
            p = subprocess.run([sys.executable,"-c",script,str(path)], timeout=30)
            self.assertEqual(9,p.returncode)
            before = path.read_bytes()
            self.assertEqual(ROTA,verificar_cadena(ws)['estado'])
            with self.assertRaises(ValueError): append_event(ws,{"kind":"fixture/next"})
            self.assertEqual(before,path.read_bytes())

    @unittest.skipUnless(resource is not None and hasattr(signal,"SIGXFSZ"),
                         "kernel file-size limit requires POSIX resource support")
    def test_kernel_file_limit_cannot_turn_partial_append_into_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            append_event(ws,{"kind":"fixture/start"})
            path = ledger_path(ws)
            original = path.read_bytes()
            script = ("import sys,signal,resource; from pathlib import Path; "
                      "from core.evidence import append_event; "
                      "signal.signal(signal.SIGXFSZ,signal.SIG_IGN); "
                      f"resource.setrlimit(resource.RLIMIT_FSIZE,({len(original)+17},{len(original)+17})); "
                      "append_event(Path(sys.argv[1]),{'kind':'fixture/next'})")
            p = subprocess.run([sys.executable,"-c",script,str(ws)], timeout=30,
                               cwd=Path(__file__).resolve().parents[2], capture_output=True)
            self.assertNotEqual(0,p.returncode)
            self.assertIn(b'OSError',p.stderr)
            self.assertTrue(path.read_bytes().startswith(original))
            self.assertLessEqual(path.stat().st_size,len(original)+17)
            before = path.read_bytes()
            with self.assertRaises(ValueError): append_event(ws,{"kind":"fixture/retry"})
            self.assertEqual(before,path.read_bytes())
