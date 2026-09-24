#!/usr/bin/env python3
"""Test suite for the claude-for-idiots hooks.

Run with:  python3 tests/test_hooks.py

Standard library only (plus git on PATH for the secrets tests). Every hook must
keep covering its three contract scenarios: should BLOCK, should ALLOW, and
no config -> ALLOW (fail open).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS_DIR = Path(__file__).resolve().parent.parent / "hooks"

MIGRATIONS_CONFIG = {
    "migrations": {
        "tool": "alembic",
        "command": 'alembic revision --autogenerate -m "msg"',
        "protected_paths": ["alembic/versions/**"],
    }
}

ARCH_CONFIG = {
    "architecture": {
        "name": "layered",
        "enforce": "deny",
        "allowed_paths": ["app/**", "tests/**"],
        "layers": {"app/services": "business logic"},
    }
}


def run_hook(script, event):
    return subprocess.run(
        [sys.executable, str(HOOKS_DIR / script)],
        input=json.dumps(event) if isinstance(event, dict) else event,
        capture_output=True, text=True, timeout=30,
    )


def decision(proc):
    """The permissionDecision the hook printed, or None if it stayed silent (allow)."""
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]


class TempProject(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def write_config(self, config):
        cfg_dir = Path(self.root) / ".claude-for-idiots"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "config.json").write_text(json.dumps(config))

    def event(self, tool, **tool_input):
        return {"cwd": self.root, "tool_name": tool, "tool_input": tool_input}


class TestBlockMigrationEdits(TempProject):
    SCRIPT = "block_migration_edits.py"

    def test_blocks_protected_migration_file(self):
        self.write_config(MIGRATIONS_CONFIG)
        proc = run_hook(self.SCRIPT, self.event(
            "Edit", file_path=os.path.join(self.root, "alembic/versions/abc.py")))
        self.assertEqual(decision(proc), "deny")

    def test_allows_normal_file(self):
        self.write_config(MIGRATIONS_CONFIG)
        proc = run_hook(self.SCRIPT, self.event(
            "Edit", file_path=os.path.join(self.root, "app/main.py")))
        self.assertIsNone(decision(proc))

    def test_allows_without_config(self):
        proc = run_hook(self.SCRIPT, self.event(
            "Edit", file_path=os.path.join(self.root, "alembic/versions/abc.py")))
        self.assertIsNone(decision(proc))

    def test_fails_open_on_garbage_stdin(self):
        proc = run_hook(self.SCRIPT, "this is not json")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "")


class TestEnforceArchitecture(TempProject):
    SCRIPT = "enforce_architecture.py"

    def test_denies_new_code_outside_architecture(self):
        self.write_config(ARCH_CONFIG)
        proc = run_hook(self.SCRIPT, self.event(
            "Write", file_path=os.path.join(self.root, "random/thing.py")))
        self.assertEqual(decision(proc), "deny")

    def test_ask_mode_asks_instead_of_denying(self):
        cfg = json.loads(json.dumps(ARCH_CONFIG))
        cfg["architecture"]["enforce"] = "ask"
        self.write_config(cfg)
        proc = run_hook(self.SCRIPT, self.event(
            "Write", file_path=os.path.join(self.root, "random/thing.py")))
        self.assertEqual(decision(proc), "ask")

    def test_allows_inside_architecture(self):
        self.write_config(ARCH_CONFIG)
        proc = run_hook(self.SCRIPT, self.event(
            "Write", file_path=os.path.join(self.root, "app/services/x.py")))
        self.assertIsNone(decision(proc))

    def test_allows_non_code_files(self):
        self.write_config(ARCH_CONFIG)
        proc = run_hook(self.SCRIPT, self.event(
            "Write", file_path=os.path.join(self.root, "random/notes.md")))
        self.assertIsNone(decision(proc))

    def test_allows_overwriting_existing_file(self):
        self.write_config(ARCH_CONFIG)
        target = Path(self.root) / "random" / "old.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n")
        proc = run_hook(self.SCRIPT, self.event("Write", file_path=str(target)))
        self.assertIsNone(decision(proc))

    def test_allows_when_enforce_off(self):
        cfg = json.loads(json.dumps(ARCH_CONFIG))
        cfg["architecture"]["enforce"] = "off"
        self.write_config(cfg)
        proc = run_hook(self.SCRIPT, self.event(
            "Write", file_path=os.path.join(self.root, "random/thing.py")))
        self.assertIsNone(decision(proc))

    def test_allows_without_config(self):
        proc = run_hook(self.SCRIPT, self.event(
            "Write", file_path=os.path.join(self.root, "random/thing.py")))
        self.assertIsNone(decision(proc))


class TestPolicedExtensions(TempProject):
    POLICED = ["x.ts", "x.mjs", "x.cjs", "x.mts", "x.astro", "x.sql",
               "x.sh", "x.py", "x.go", "x.rs", "x.vue"]
    IGNORED = ["notes.md", "data.json", "config.yml", "Cargo.lock", "logo.svg"]

    def test_every_code_extension_is_policed(self):
        self.write_config(ARCH_CONFIG)
        for name in self.POLICED:
            proc = run_hook("enforce_architecture.py", self.event(
                "Write", file_path=os.path.join(self.root, "random", name)))
            self.assertEqual(decision(proc), "deny", name)

    def test_non_code_is_never_policed(self):
        self.write_config(ARCH_CONFIG)
        for name in self.IGNORED:
            proc = run_hook("enforce_architecture.py", self.event(
                "Write", file_path=os.path.join(self.root, "random", name)))
            self.assertIsNone(decision(proc), name)

    def test_config_can_override_the_ignore_list(self):
        cfg = json.loads(json.dumps(ARCH_CONFIG))
        cfg["architecture"]["ignored_extensions"] = [".ts"]
        self.write_config(cfg)
        proc = run_hook("enforce_architecture.py", self.event(
            "Write", file_path=os.path.join(self.root, "random", "x.ts")))
        self.assertIsNone(decision(proc))


class TestScanSecretsBeforePush(TempProject):
    SCRIPT = "scan_secrets_before_push.py"

    def _repo_with(self, relpath, content):
        subprocess.run(["git", "-C", self.root, "init", "-q"],
                       check=True, capture_output=True)
        target = Path(self.root) / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        subprocess.run(["git", "-C", self.root, "add", "-A"],
                       check=True, capture_output=True)

    def test_blocks_push_with_tracked_secret(self):
        self._repo_with("app/leak.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        proc = run_hook(self.SCRIPT, self.event("Bash", command="git push origin main"))
        self.assertEqual(decision(proc), "deny")

    def test_blocks_push_with_tracked_dotenv(self):
        self._repo_with(".env", "TOKEN=supersecretvalue123\n")
        proc = run_hook(self.SCRIPT, self.event("Bash", command="git push"))
        self.assertEqual(decision(proc), "deny")

    def test_allows_clean_push(self):
        self._repo_with("app/main.py", "print('hello')\n")
        proc = run_hook(self.SCRIPT, self.event("Bash", command="git push origin main"))
        self.assertIsNone(decision(proc))

    def test_allows_non_publish_command(self):
        self._repo_with("app/leak.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        proc = run_hook(self.SCRIPT, self.event("Bash", command="ls -la"))
        self.assertIsNone(decision(proc))

    def test_ignores_other_tools(self):
        proc = run_hook(self.SCRIPT, self.event("Edit", file_path="x.py"))
        self.assertIsNone(decision(proc))


class TestSharedBehavior(TempProject):
    def test_migration_hook_handles_relative_dot_path(self):
        self.write_config(MIGRATIONS_CONFIG)
        proc = run_hook("block_migration_edits.py",
                        self.event("Edit", file_path="./alembic/versions/a.py"))
        self.assertEqual(decision(proc), "deny")

    def test_migration_hook_reads_notebook_path(self):
        self.write_config(MIGRATIONS_CONFIG)
        proc = run_hook("block_migration_edits.py",
                        self.event("NotebookEdit",
                                   notebook_path="alembic/versions/a.ipynb"))
        self.assertEqual(decision(proc), "deny")

    def test_arch_hook_ignores_path_outside_project(self):
        self.write_config(ARCH_CONFIG)
        proc = run_hook("enforce_architecture.py",
                        self.event("Write", file_path="/etc/cron.d/x.py"))
        self.assertIsNone(decision(proc))
        self.assertEqual(proc.returncode, 0)

    def test_arch_hook_existing_file_check_uses_event_cwd(self):
        """A relative path must resolve against event['cwd'], not the process cwd."""
        self.write_config(ARCH_CONFIG)
        target = Path(self.root) / "random" / "old.py"
        target.parent.mkdir(parents=True)
        target.write_text("x = 1\n")
        proc = subprocess.run(
            [sys.executable, str(HOOKS_DIR / "enforce_architecture.py")],
            input=json.dumps(self.event("Write", file_path="random/old.py")),
            capture_output=True, text=True, timeout=30, cwd="/",
        )
        self.assertIsNone(decision(proc))


if __name__ == "__main__":
    unittest.main(verbosity=2)
