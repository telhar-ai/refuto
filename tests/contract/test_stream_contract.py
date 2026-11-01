"""Controlled local CLI processes; no paid model calls or native hook claims."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from adapters.claude import ClaudeAdapter, SPEC
from adapters.registry import ADAPTERS
from adapters.codex import SPEC as CODEX
from core.run import _invoke, execute_step, Run, StepResult, BLOCKED_
from core.roles import load
from core.model import new_id, KIND_ORCHESTRATION


def stream():
    return [json.dumps({'type':'assistant','session_id':'fixture-session','message':{'content':[
        {'type':'text','text':'fixture narrative'},
        {'type':'tool_use','name':'Read','id':'fixture-a','input':{'private':'not persisted'}},
        {'type':'tool_use','name':'Write','id':'fixture-b','input':{'nested':{'type':'tool_use','id':'not-a-call'}}}
    ]}}), '[]', 'not json', json.dumps({'type':'unknown'}),
        json.dumps({'type':'result','total_cost_usd':.1,'is_error':False})]


class TestStreamContract(unittest.TestCase):
    def runtime(self, root, lines=None, broken=False):
        script=root/'runtime.py'
        script.write_text("from pathlib import Path\nimport os,json,sys\n"
                          "Path('effect.txt').write_bytes(b'fixture')\n"
                          "Path('prompt.txt').write_text(sys.stdin.read())\n"
                          "Path('argv.json').write_text(json.dumps(sys.argv[1:]))\n"
                          "Path('context.json').write_text(json.dumps({k:os.environ.get(k) "
                          "for k in ('HARNESS_ROLE','HARNESS_RUN_ID')}))\n"
                          +''.join('print('+repr(line)+')\n' for line in (stream() if lines is None else lines)),encoding='utf-8')
        class FixtureClaude(ClaudeAdapter):
            def run_argv(self, **kwargs):return [sys.executable,str(script)]
            def normalize_events(self, raw):
                if broken:raise ValueError('fixture mapper error')
                return super().normalize_events(raw)
        return FixtureClaude(name='claude',binary=sys.executable,native_extensions=SPEC.native_extensions,
                             prompt_from_stdin=SPEC.prompt_from_stdin)

    def test_plural_mapper_preserves_order_without_interpreting_nested_inputs(self):
        raw=json.loads(stream()[0]);events=SPEC.normalize_events(raw)
        self.assertEqual(['fixture-a','fixture-b'],[x['tool_call_id'] for x in events])
        self.assertEqual([1,2],[x['source_block'] for x in events])
        self.assertNotIn('not persisted',json.dumps(events))
        self.assertEqual('fixture-a',SPEC.normalize_event(raw)['payload']['id'])

    def test_real_subprocess_reports_all_blocks_and_capture_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);role=next(iter(load().values()))
            with patch.dict(ADAPTERS,{'claude':self.runtime(root)}):
                out=_invoke(role,StepResult(phase='TEST',role=role.id,runtime='claude'),root,
                            budget_usd=.25,prompt_of=lambda *_:'fixture')
            self.assertTrue(out['ok'],out['detail'])
            self.assertTrue((root/'effect.txt').is_file())
            self.assertEqual(['fixture-a','fixture-b'],[x['tool_call_id'] for x in out['observations'] if x['reported_kind']=='tool/call'])
            self.assertEqual(5,out['stream_coverage']['records'])
            self.assertEqual(2,out['stream_coverage']['invalid_records'])
            self.assertEqual(1,out['stream_coverage']['unmapped_records'])
            self.assertEqual(3,out['stream_coverage']['observations'])
            self.assertFalse(out['stream_coverage']['preserves_original'])
            self.assertNotIn('not persisted',json.dumps(out['observations']))

    def test_orchestrator_persists_both_reported_calls_but_never_task_acceptance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);role=next(x for x in load().values() if not x.human_review)
            run=Run(run_id=new_id(KIND_ORCHESTRATION),workspace=str(root))
            step=StepResult(phase='TEST',role=role.id,runtime='claude')
            with patch.dict(ADAPTERS,{'claude':self.runtime(root)}):
                execute_step(run,step,{},dry_run=False,prompt_of=lambda *_:'fixture')
            events=[json.loads(x) for x in (root/'.harness/evidence/ledger.jsonl').read_text().splitlines()]
            calls=[x for x in events if x['kind']=='runtime/report' and x['reported_kind']=='tool/call']
            self.assertEqual(['fixture-a','fixture-b'],[x['tool_call_id'] for x in calls])
            self.assertIsNone(events[-1]['acceptance'])
            self.assertEqual('runtime_exit_only',events[-1]['completion_scope'])
            context=json.loads((root/'context.json').read_text())
            self.assertEqual(role.id,context['HARNESS_ROLE'])
            self.assertEqual(run.run_id,context['HARNESS_RUN_ID'])

    def test_unsupported_budget_never_generates_prompt_or_starts_runtime(self):
        for runtime in ('codex','kiro','gemini','opencode'):
            with self.subTest(runtime=runtime),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);role=next(iter(load().values()))
                def forbidden(*_):raise AssertionError('prompt must not be requested')
                out=_invoke(role,StepResult(phase='TEST',role=role.id,runtime=runtime),root,
                            budget_usd=.25,prompt_of=forbidden)
                self.assertFalse(out['ok']);self.assertTrue(out['blocked'])
                self.assertFalse((root/'.harness').exists())

    def test_invalid_budgets_fail_before_side_effects(self):
        for budget in (0,-1,True,float('nan'),float('inf'),10**1000,'fixture'):
            with self.subTest(kind=type(budget).__name__),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);role=next(iter(load().values()))
                out=_invoke(role,StepResult(phase='TEST',role=role.id,runtime='claude'),root,
                            budget_usd=budget,prompt_of=lambda *_:self.fail('unexpected prompt'))
                self.assertTrue(out['blocked']);self.assertFalse((root/'.harness').exists())

    def test_mapper_error_blocks_without_claiming_effect_reversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);role=next(iter(load().values()))
            with patch.dict(ADAPTERS,{'claude':self.runtime(root,broken=True)}):
                out=_invoke(role,StepResult(phase='TEST',role=role.id,runtime='claude'),root,
                            budget_usd=.25,prompt_of=lambda *_:'fixture')
            self.assertFalse(out['ok']);self.assertTrue(out['blocked'])
            self.assertTrue((root/'effect.txt').is_file())
            self.assertGreater(out['stream_coverage']['mapping_errors'],0)

    def test_audit_failure_after_effect_stays_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);role=next(x for x in load().values() if not x.human_review)
            (root/'.harness/evidence/ledger.jsonl').mkdir(parents=True)
            run=Run(run_id=new_id(KIND_ORCHESTRATION),workspace=str(root))
            step=StepResult(phase='TEST',role=role.id,runtime='claude')
            with patch.dict(ADAPTERS,{'claude':self.runtime(root)}):
                execute_step(run,step,{},dry_run=False,prompt_of=lambda *_:'fixture')
            self.assertEqual(BLOCKED_,step.status)
            self.assertTrue((root/'effect.txt').is_file())
            self.assertIn('IN_DOUBT',step.reason)

    def test_empty_stream_is_not_a_passing_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);role=next(iter(load().values()))
            with patch.dict(ADAPTERS,{'claude':self.runtime(root,lines=[])}):
                out=_invoke(role,StepResult(phase='TEST',role=role.id,runtime='claude'),root,
                            budget_usd=.25,prompt_of=lambda *_:'fixture')
            self.assertEqual('NOT_APPLICABLE',out['stream_coverage']['status'])
            self.assertEqual(0,out['stream_coverage']['observations'])

    def test_codex_canonical_arguments_keep_sandbox_and_approval(self):
        argv=CODEX.run_argv(prompt_file=Path('fixture.md'),allow_tools=[],effort='medium',
                            headless=True,budget_usd=None)
        self.assertLess(argv.index('--ask-for-approval'),argv.index('exec'))
        self.assertEqual('on-request',argv[argv.index('--ask-for-approval')+1])
        self.assertEqual('workspace-write',argv[argv.index('--sandbox')+1])
        self.assertIn('--json',argv)
        with self.assertRaises(ValueError):
            CODEX.run_argv(prompt_file=Path('fixture.md'),allow_tools=[],effort='medium',budget_usd=.25)

    def test_empty_claude_tool_set_does_not_restore_default_tools(self):
        argv=SPEC.run_argv(prompt_file=Path('fixture.md'),allow_tools=[],effort='medium')
        self.assertEqual('',argv[argv.index('--tools')+1])

    def test_option_like_prompt_is_data_on_stdin_not_an_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);role=next(iter(load().values()))
            with patch.dict(ADAPTERS,{'claude':self.runtime(root)}):
                out=_invoke(role,StepResult(phase='TEST',role=role.id,runtime='claude'),root,
                            budget_usd=.25,prompt_of=lambda *_:'--help')
            self.assertTrue(out['ok'])
            self.assertEqual('--help',(root/'prompt.txt').read_text())
            self.assertEqual([],json.loads((root/'argv.json').read_text()))
            self.assertNotIn('--help',out['command'])

    def test_repeated_role_captures_do_not_overwrite_previous_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);role=next(iter(load().values()));references=[]
            with patch.dict(ADAPTERS,{'claude':self.runtime(root)}):
                for text in ('first fixture','second fixture'):
                    out=_invoke(role,StepResult(phase='TEST',role=role.id,runtime='claude'),root,
                                budget_usd=.25,prompt_of=lambda *_,value=text:value)
                    references.append(out['prompt_reference'])
            self.assertNotEqual(references[0]['source'],references[1]['source'])
            self.assertEqual('first fixture',(root/references[0]['source']).read_text())
            self.assertEqual('second fixture',(root/references[1]['source']).read_text())
            if os.name=='posix':
                self.assertEqual(0o600,(root/references[0]['source']).stat().st_mode & 0o777)

    def test_codex_cannot_silently_ignore_a_requested_tool_restriction(self):
        with self.assertRaises(ValueError):
            CODEX.run_argv(prompt_file=Path('fixture.md'),allow_tools=['read'],effort='medium')


if __name__=='__main__':unittest.main()
