"""Real worktree pushes: fixtures cannot inherit the publishing repository."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from core.proc import TEXT_IO


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / ".githooks/pre-push"


class TestPrePushGitContext(unittest.TestCase):
    def prepare(self, directory, exit_code=0):
        root = Path(directory)
        local_names = subprocess.check_output(
            ["git", "rev-parse", "--local-env-vars"], **TEXT_IO).splitlines()
        env = {k: v for k, v in os.environ.items() if k not in local_names}
        env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                   GIT_TERMINAL_PROMPT="0")

        def git(*args, cwd=None, check=True, extra=None):
            return subprocess.run(["git", "-c", "user.name=Fixture", "-c",
                "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", *args],
                cwd=cwd, env=dict(env, **(extra or {})), check=check,
                capture_output=True, timeout=20, **TEXT_IO)

        repo, worktree, remote = root / "repo", root / "worktree", root / "remote.git"
        marker = root / "preflight-ran"
        git("init", "-b", "main", str(repo))
        (repo / ".githooks").mkdir()
        (repo / "scripts").mkdir()
        hook = repo / ".githooks/pre-push"
        hook.write_bytes(HOOK.read_bytes())
        hook.chmod(0o755)
        (repo / "scripts/preflight.py").write_text(
            "import pathlib,subprocess,sys,tempfile\n"
            f"pathlib.Path({str(marker)!r}).write_text('ran')\n"
            "with tempfile.TemporaryDirectory() as foreign:\n"
            " subprocess.run(['git','init','--bare'],cwd=foreign,check=True,capture_output=True)\n"
            f"sys.exit({exit_code})\n")
        (repo / "sentinel.txt").write_text("original\n")
        git("add", ".", cwd=repo)
        git("commit", "-m", "fixture", cwd=repo)
        initial = git("rev-parse", "HEAD", cwd=repo).stdout.strip()
        git("config", "core.hooksPath", ".githooks", cwd=repo)
        git("init", "--bare", str(remote))
        git("remote", "add", "origin", str(remote), cwd=repo)
        git("worktree", "add", "-b", "feature", str(worktree), cwd=repo)
        return git, repo, worktree, remote, marker, initial

    def test_real_worktree_push_does_not_change_repository_via_foreign_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            git, repo, worktree, remote, marker, initial = self.prepare(directory)
            git_dir = git("rev-parse", "--absolute-git-dir", cwd=worktree).stdout.strip()
            result = git("push", "origin", "HEAD:refs/heads/feature", cwd=worktree,
                         check=False, extra={"GIT_DIR": git_dir})
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue(marker.exists(), "preflight must actually run")
            self.assertEqual("false", git("config", "--get", "core.bare", cwd=repo).stdout.strip())
            self.assertEqual(initial, git("rev-parse", "HEAD", cwd=worktree).stdout.strip())
            self.assertEqual("", git("status", "--porcelain", cwd=worktree).stdout.strip())
            self.assertEqual(initial, git("--git-dir=" + str(remote), "rev-parse",
                                          "refs/heads/feature").stdout.strip())

    def test_failed_preflight_and_protected_main_still_block_publication(self):
        for target, code, preflight_runs in (("feature", 1, True), ("main", 0, False)):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                git, repo, worktree, remote, marker, initial = self.prepare(directory, code)
                result = git("push", "origin", "HEAD:refs/heads/" + target,
                             cwd=worktree, check=False)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(preflight_runs, marker.exists())
                self.assertEqual(initial, git("rev-parse", "HEAD", cwd=worktree).stdout.strip())
                missing = git("--git-dir=" + str(remote), "rev-parse", "--verify",
                              "refs/heads/" + target, check=False)
                self.assertNotEqual(0, missing.returncode)
