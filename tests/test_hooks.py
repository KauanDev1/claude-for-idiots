#!/usr/bin/env python3
"""Test suite for the claude-for-idiots hooks.

Run with:  python3 tests/test_hooks.py

Standard library only (plus git on PATH for the secrets tests). Every hook must
keep covering its three contract scenarios: should BLOCK, should ALLOW, and
no config -> ALLOW (fail open).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
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


def run_hook(script, event, env=None):
    return subprocess.run(
        [sys.executable, str(HOOKS_DIR / script)],
        input=json.dumps(event) if isinstance(event, dict) else event,
        capture_output=True, text=True, timeout=30, env=env,
    )


def decision(proc):
    """The permissionDecision the hook printed, or None if it stayed silent (allow)."""
    if not proc.stdout.strip():
        return None
    return json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"]


def reason(proc):
    """The permissionDecisionReason the hook printed, or "" if it stayed silent."""
    if not proc.stdout.strip():
        return ""
    return json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecisionReason"]


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

    def test_fails_open_on_invalid_character_class_in_protected_paths(self):
        # protected_paths comes straight out of config.json, which is as
        # attacker/beginner-influenced as stdin -- a project generated (or
        # hand-edited) with a backwards range like "[9-0]" or "[z-a]" made
        # re.compile() raise re.error/re.PatternError while parsing the
        # glob, crashing the hook with a non-zero exit instead of failing
        # open, the same family of bug as the RecursionError/TypeError
        # fixes elsewhere in this module.
        cfg = {"migrations": {"tool": "x", "command": "x",
                              "protected_paths": ["**/migrations/[9-0]*"]}}
        self.write_config(cfg)
        proc = run_hook(self.SCRIPT, self.event(
            "Edit", file_path=os.path.join(self.root, "migrations/0001.py")))
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)


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


class TestIgnoreListOverrideRobustness(TempProject):
    """Round-1 review findings: the override must behave as predictably as
    the built-in default list, or a beginner's typo silently turns Rule 5
    into "police literally everything" without any error or warning."""

    def _check(self, override_entry, filename):
        cfg = json.loads(json.dumps(ARCH_CONFIG))
        cfg["architecture"]["ignored_extensions"] = [override_entry]
        self.write_config(cfg)
        proc = run_hook("enforce_architecture.py", self.event(
            "Write", file_path=os.path.join(self.root, "random", filename)))
        return decision(proc)

    def test_override_matching_is_case_insensitive_both_ways(self):
        # The default list already lowercases before comparing (achado 1
        # measured ".TS" in config failing to exempt "x.ts" and "x.TS").
        # Whichever side -- config or filename -- carries the odd case, the
        # match must still happen.
        for override_entry, filename in [
            (".TS", "x.ts"), (".TS", "x.TS"), (".ts", "x.TS"), (".Md", "x.mD"),
        ]:
            self.assertIsNone(self._check(override_entry, filename),
                               f"override={override_entry!r} file={filename!r}")

    def test_override_entry_without_leading_dot_still_exempts_its_extension(self):
        # os.path.splitext always returns the extension WITH its dot, so an
        # override entry typed without one ("ts" instead of ".ts") used to
        # match nothing at all -- not even the extension the author meant to
        # exempt -- which is how achado 2 turned a one-character typo into
        # "policia o projeto inteiro".
        for override_entry, filename in [
            ("ts", "x.ts"), ("PY", "x.py"), ("Json", "x.json"),
        ]:
            self.assertIsNone(self._check(override_entry, filename),
                               f"override={override_entry!r} file={filename!r}")

    def test_override_entry_with_stray_whitespace_still_exempts_its_extension(self):
        for override_entry, filename in [(" .ts", "x.ts"), (".ts ", "x.ts"),
                                          (" ts ", "x.ts")]:
            self.assertIsNone(self._check(override_entry, filename),
                               f"override={override_entry!r} file={filename!r}")

    def test_override_that_normalizes_to_nothing_falls_back_to_default(self):
        # If every override entry is whitespace and normalizes away to
        # nothing, that is a malformed config, not a deliberate "ignore
        # nothing" instruction. Fail open to the default list rather than
        # policing every file in the project -- consistent with how this
        # hook already fails open elsewhere on malformed config.
        cfg = json.loads(json.dumps(ARCH_CONFIG))
        cfg["architecture"]["ignored_extensions"] = ["   "]
        self.write_config(cfg)
        proc = run_hook("enforce_architecture.py", self.event(
            "Write", file_path=os.path.join(self.root, "random", "notes.md")))
        self.assertIsNone(decision(proc))


class TestDotenvAndDataFilesAreIgnored(TempProject):
    def _not_policed(self, filename, cfg=None):
        self.write_config(cfg if cfg is not None else ARCH_CONFIG)
        proc = run_hook("enforce_architecture.py", self.event(
            "Write", file_path=os.path.join(self.root, "random", filename)))
        self.assertIsNone(decision(proc), filename)

    def test_dotenv_and_its_suffixed_siblings_are_never_policed(self):
        # os.path.splitext(".env.local") reports the extension as ".local",
        # not ".env" -- achado 3 measured ".env" passing while ".env.local"
        # and ".env.production" (the standard Next.js/Vite convention) were
        # denied.
        for name in [".env", ".env.local", ".env.production",
                     ".env.development.local", ".env.test"]:
            self._not_policed(name)

    def test_dotenv_stays_exempt_even_under_a_narrow_override(self):
        # A dotenv file is never "code" for Rule 5, the same way an
        # extension-less file (Dockerfile, Makefile, LICENSE) never is --
        # unconditionally, regardless of what the project chose to police.
        cfg = json.loads(json.dumps(ARCH_CONFIG))
        cfg["architecture"]["ignored_extensions"] = [".ts"]
        for name in [".env.local", ".env.production"]:
            self._not_policed(name, cfg)

    def test_ml_data_file_extensions_are_ignored_by_default(self):
        # achado 4: .parquet and .pkl are direct siblings of .csv/.tsv,
        # which were already ignored.
        for name in ["train.parquet", "model.pkl"]:
            self._not_policed(name)


class TestEnforceMode(TempProject):
    def test_missing_enforce_defaults_to_ask_not_off(self):
        cfg = {"architecture": {"name": "x", "allowed_paths": ["src/**"],
                                "layers": {}}}
        self.write_config(cfg)
        proc = run_hook("enforce_architecture.py", self.event(
            "Write", file_path=os.path.join(self.root, "random", "x.py")))
        self.assertEqual(decision(proc), "ask")

    def test_malformed_config_fails_open_without_crashing(self):
        for raw in ['{"architecture": "layered"}',
                    '{"architecture": ["a"]}',
                    '{"architecture": {"allowed_paths": "src/**"}}',
                    '{broken', '[]', '']:
            cfg_dir = Path(self.root) / ".claude-for-idiots"
            cfg_dir.mkdir(parents=True, exist_ok=True)
            (cfg_dir / "config.json").write_text(raw)
            proc = run_hook("enforce_architecture.py", self.event(
                "Write", file_path=os.path.join(self.root, "random", "x.py")))
            self.assertEqual(proc.returncode, 0, raw)
            self.assertNotIn("Traceback", proc.stderr, raw)

    def test_allowed_paths_as_bare_string_still_works(self):
        cfg = {"architecture": {"name": "x", "enforce": "deny",
                                "allowed_paths": "src/**", "layers": {}}}
        self.write_config(cfg)
        ok = run_hook("enforce_architecture.py", self.event(
            "Write", file_path=os.path.join(self.root, "src", "x.py")))
        bad = run_hook("enforce_architecture.py", self.event(
            "Write", file_path=os.path.join(self.root, "random", "x.py")))
        self.assertIsNone(decision(ok))
        self.assertEqual(decision(bad), "deny")


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

    def test_blocks_push_when_secret_lives_in_a_non_ascii_named_file(self):
        # git ls-files quotes any path containing a non-ASCII byte as an
        # octal-escaped string by default (core.quotePath=true). If the
        # scanner ever uses that quoted string as a literal filesystem path
        # again, open() raises OSError and the file is skipped in silence --
        # so a secret sitting in a file like "serviço/júlia's config.py"
        # would sail through undetected. This must still be caught.
        self._repo_with("serviço/júlia's config.py",
                         'GOOGLE_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu"\n')
        proc = run_hook(self.SCRIPT, self.event("Bash", command="git push origin main"))
        self.assertEqual(decision(proc), "deny")
        self.assertIn("serviço", reason(proc))

    def test_non_ascii_named_file_without_a_secret_still_allows(self):
        # The fix must actually read the content of non-ASCII-named files,
        # not just fail differently on them -- a scanner that denies every
        # push touching a non-ASCII path (instead of reading it) would pass
        # the sibling test above for the wrong reason.
        self._repo_with("dados/relatório (março).py", "print('sem segredo aqui')\n")
        proc = run_hook(self.SCRIPT, self.event("Bash", command="git push origin main"))
        self.assertIsNone(decision(proc))

    def test_scan_covers_the_whole_repo_regardless_of_cwd(self):
        # `git push` sends the whole repository, not just the subtree under
        # the directory the command happened to run from. A secret sitting
        # outside the invoking cwd must still be caught.
        self._repo_with("ci/deploy_keys.py",
                         "SLACK_TOKEN = 'xoxb-111111111111-222222222222-abcdefghijklmnopqrstuvwx'\n")
        nested = Path(self.root) / "packages" / "web" / "src"
        nested.mkdir(parents=True)
        (nested / "index.js").write_text("console.log('hi')\n")
        subprocess.run(["git", "-C", self.root, "add", "-A"],
                       check=True, capture_output=True)
        event = {
            "cwd": str(nested),
            "tool_name": "Bash",
            "tool_input": {"command": "git push origin main"},
        }
        proc = run_hook(self.SCRIPT, event)
        self.assertEqual(decision(proc), "deny")
        self.assertIn("ci/deploy_keys.py", reason(proc))

    def test_fails_open_on_non_string_command(self):
        # tool_input.command is attacker/tool-influenced input like anything
        # else read from the event. A malformed event carrying e.g. a number
        # or null for "command" used to reach PUBLISH_RE.search() directly
        # and crash with TypeError -- a fail-open violation.
        self._repo_with("app/leak.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        for bad_command in (123, None, ["git", "push"], {"x": 1}):
            event = {"cwd": self.root, "tool_name": "Bash",
                     "tool_input": {"command": bad_command}}
            proc = run_hook(self.SCRIPT, event)
            self.assertEqual(proc.returncode, 0, bad_command)
            self.assertNotIn("Traceback", proc.stderr, bad_command)

    def test_scan_from_nested_cwd_still_allows_a_genuinely_clean_repo(self):
        # Root-relative scanning must not become "deny everything from a
        # subdirectory" -- a clean repo pushed from deep inside it should
        # still pass.
        self._repo_with("ci/build.py", "print('build step')\n")
        nested = Path(self.root) / "packages" / "web" / "src"
        nested.mkdir(parents=True)
        (nested / "index.js").write_text("console.log('hi')\n")
        subprocess.run(["git", "-C", self.root, "add", "-A"],
                       check=True, capture_output=True)
        event = {
            "cwd": str(nested),
            "tool_name": "Bash",
            "tool_input": {"command": "git push origin main"},
        }
        proc = run_hook(self.SCRIPT, event)
        self.assertIsNone(decision(proc))


class TestScannerHistoryAndEnv(TempProject):
    """Two furos beyond scanning tracked files at HEAD:

    1. `git push` sends the full diff of every unpushed commit, not just
       what's at HEAD -- a secret added and then "fixed" in a later commit
       is still in that diff.
    2. A gitignored `.env` is invisible to `git ls-files` by definition, but
       every OTHER publishing path (vercel, docker build, scp, rsync, ...)
       uploads the whole working directory, ignored or not.

    The two are deliberately mutually exclusive in the fixtures below: a
    real `git push` never carries a gitignored file, and a non-git deploy
    never carries unpushed git history -- each test proves its own
    direction AND guards against the other becoming a false positive.
    """
    SCRIPT = "scan_secrets_before_push.py"

    def _init(self):
        subprocess.run(["git", "-C", self.root, "init", "-q"],
                       check=True, capture_output=True)

    def _commit(self, message):
        subprocess.run(["git", "-C", self.root, "add", "-A"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", self.root, "-c", "user.email=t@t",
                        "-c", "user.name=t", "commit", "-qm", message],
                       check=True, capture_output=True)

    # -- history: secret present only in an unpushed commit, not at HEAD --

    def test_secret_fixed_in_a_later_unpushed_commit_still_blocks_the_push(self):
        self._init()
        cfg = Path(self.root) / "settings.py"
        cfg.write_text('SLACK = "xoxb-111111111111-222222222222-'
                        'abcdefghijklmnopqrstuvwx"\n')
        self._commit("wip: hardcode slack token for testing")
        cfg.write_text('SLACK = os.environ["SLACK_TOKEN"]\n')
        self._commit("fix: stop hardcoding the slack token")
        proc = run_hook(self.SCRIPT,
                        self.event("Bash", command="git push origin main"))
        self.assertEqual(decision(proc), "deny")
        self.assertIn("history", reason(proc).lower())

    def test_history_scan_does_not_reflag_a_secret_already_on_the_remote(self):
        # `@{upstream}..HEAD` -- once a commit is on the remote, pushing
        # again (e.g. a later, unrelated, genuinely clean commit) must not
        # re-scan and re-block on old, already-published history. Otherwise
        # every subsequent push in the repo's lifetime would be permanently
        # blocked by one old secret nobody can un-push.
        self._init()
        remote = tempfile.mkdtemp()
        try:
            subprocess.run(["git", "init", "-q", "--bare", remote],
                           check=True, capture_output=True)
            # Both the leak AND its fix land on the remote together as the
            # first push, so at HEAD -- on the remote and locally -- the
            # secret is gone; only its ghost sits a few commits back, all
            # already published.
            leak = Path(self.root) / "leak.py"
            leak.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            self._commit("oops, hardcoded a key")
            leak.write_text('AWS_KEY = os.environ["AWS_KEY"]\n')
            self._commit("cleanup")
            subprocess.run(["git", "-C", self.root, "remote", "add",
                            "origin", remote], check=True, capture_output=True)
            subprocess.run(["git", "-C", self.root, "push", "-q", "-u",
                            "origin", "HEAD:main"],
                           check=True, capture_output=True)
            # A later, genuinely unrelated, clean commit -- this is the one
            # `@{upstream}..HEAD` should actually diff.
            (Path(self.root) / "README.md").write_text("docs\n")
            self._commit("docs: add a readme")
            proc = run_hook(self.SCRIPT,
                            self.event("Bash", command="git push origin main"))
            self.assertIsNone(decision(proc))
        finally:
            shutil.rmtree(remote, ignore_errors=True)

    def test_first_push_with_no_upstream_still_scans_history(self):
        # No remote configured at all (a brand-new repo's first push):
        # `@{upstream}..HEAD` has nothing to resolve, so unpushed_diff must
        # fall back to scanning recent commits instead of silently skipping
        # history entirely.
        self._init()
        cfg = Path(self.root) / "infra.tf"
        cfg.write_text('GOOGLE_KEY = "AIzaSyD-1234567890abcdefghijklmnopqrstu"\n')
        self._commit("initial infra")
        cfg.write_text('GOOGLE_KEY = os.environ["GOOGLE_KEY"]\n')
        self._commit("stop hardcoding the key")
        proc = run_hook(self.SCRIPT,
                        self.event("Bash", command="git push origin main"))
        self.assertEqual(decision(proc), "deny")

    def test_clean_unpushed_history_allows_the_push(self):
        # Guard against the history check becoming "deny any push with more
        # than one unpushed commit" -- several genuinely clean commits ahead
        # of nothing (no upstream) must still allow.
        self._init()
        for i in range(3):
            (Path(self.root) / f"note{i}.md").write_text(f"note {i}\n")
            self._commit(f"add note {i}")
        proc = run_hook(self.SCRIPT,
                        self.event("Bash", command="git push origin main"))
        self.assertIsNone(decision(proc))

    # -- gitignored .env on disk: real for non-git deploys, not for git --

    def test_gitignored_env_blocks_a_non_git_deploy(self):
        self._init()
        (Path(self.root) / ".gitignore").write_text(".env\n")
        (Path(self.root) / ".env").write_text(
            'STRIPE_SECRET_KEY="sk_live_abcdefghijklmnop123456"\n')
        (Path(self.root) / "index.js").write_text("x\n")
        self._commit("init")
        proc = run_hook(self.SCRIPT, self.event("Bash", command="scp -r . user@host:/srv"))
        self.assertEqual(decision(proc), "deny")
        self.assertIn(".env", reason(proc))

    def test_gitignored_env_nested_in_a_monorepo_package_blocks_deploy(self):
        # env_files_on_disk must not be limited to the repo's top level --
        # every stack in the catalog can have the service (and its .env)
        # sitting inside a subdirectory (apps/api/.env, backend/.env, ...).
        self._init()
        (Path(self.root) / ".gitignore").write_text(".env\n")
        api_dir = Path(self.root) / "apps" / "api"
        api_dir.mkdir(parents=True)
        (api_dir / ".env").write_text('DB_PASSWORD="hunter2hunter2hunter2"\n')
        (Path(self.root) / "package.json").write_text("{}\n")
        self._commit("init")
        proc = run_hook(self.SCRIPT, self.event("Bash", command="vercel --prod"))
        self.assertEqual(decision(proc), "deny")
        self.assertIn(".env", reason(proc))

    def test_gitignored_env_does_not_block_git_push(self):
        """git never sends an ignored file, so pushing is fine."""
        self._init()
        (Path(self.root) / ".gitignore").write_text(".env\n")
        (Path(self.root) / ".env").write_text('KEY="sk_live_abcdefghij123456"\n')
        (Path(self.root) / "index.js").write_text("x\n")
        self._commit("init")
        proc = run_hook(self.SCRIPT, self.event("Bash", command="git push origin main"))
        self.assertIsNone(decision(proc))

    def test_env_example_file_on_disk_is_not_flagged(self):
        # A template committed for onboarding (no real secret in it) must
        # not be treated the same as an actual .env with live values.
        self._init()
        (Path(self.root) / ".gitignore").write_text(".env\n")
        (Path(self.root) / ".env.example").write_text('STRIPE_SECRET_KEY=""\n')
        (Path(self.root) / "index.js").write_text("x\n")
        self._commit("init")
        proc = run_hook(self.SCRIPT, self.event("Bash", command="netlify deploy --prod"))
        self.assertIsNone(decision(proc))

    def test_clean_repo_with_no_env_at_all_allows_a_non_git_deploy(self):
        self._init()
        (Path(self.root) / "index.js").write_text("console.log('hi')\n")
        self._commit("init")
        proc = run_hook(self.SCRIPT, self.event("Bash", command="docker push myreg/app:v1"))
        self.assertIsNone(decision(proc))

    # -- Task 7's deferred GIT_DIR bypass: closed as part of this task --

    def test_git_dir_pointing_elsewhere_does_not_hide_a_real_secret(self):
        # Task 7 review finding, deferred to this task: with GIT_DIR (and
        # GIT_WORK_TREE) set in the environment to a DIFFERENT repository,
        # `git ls-files`/`git rev-parse --show-toplevel` used to resolve
        # against THAT repo instead of `root`. None of its paths exist
        # under `root` (or `root` itself silently became the other repo's
        # toplevel), so the real secret at `root` was never read and the
        # push was allowed -- a silent bypass. Regression test for env
        # stripping in every git subprocess this hook runs.
        self._init()
        (Path(self.root) / "leak.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        self._commit("add key")
        with tempfile.TemporaryDirectory() as other:
            subprocess.run(["git", "-C", other, "init", "-q"],
                           check=True, capture_output=True)
            (Path(other) / "unrelated.txt").write_text("nothing here\n")
            subprocess.run(["git", "-C", other, "add", "-A"],
                           check=True, capture_output=True)
            subprocess.run(["git", "-C", other, "-c", "user.email=t@t",
                            "-c", "user.name=t", "commit", "-qm", "x"],
                           check=True, capture_output=True)
            env = dict(os.environ)
            env["GIT_DIR"] = str(Path(other) / ".git")
            env["GIT_WORK_TREE"] = other
            proc = run_hook(self.SCRIPT,
                            self.event("Bash", command="git push origin main"),
                            env=env)
            self.assertEqual(decision(proc), "deny")


class TestPublishDetection(TempProject):
    """Rule 6 must recognize the whole publish surface, not just `git push` and
    a couple of `gh` subcommands -- an audit found eleven of twelve real
    publishing commands (npm publish, vercel --prod, docker push, scp, ...)
    sailing through untouched, plus `git push` itself dodged by any global
    flag before the subcommand (`git -C .`, `--git-dir=`)."""

    PUBLISHES = [
        "git push origin main", "git -C . push origin main",
        "git --git-dir=.git --work-tree=. push",
        "git -c user.name=x push --force-with-lease",
        "gh repo create x --public", "gh pr create", "gh gist create leak.py",
        "gh repo edit --visibility public",
        "npm publish", "pnpm publish", "yarn publish", "bun publish",
        "poetry publish", "cargo publish", "twine upload dist/*",
        "docker push myreg/app:v1", "vercel --prod", "netlify deploy --prod",
        "firebase deploy", "flyctl deploy", "npx wrangler deploy",
        "scp -r . user@host:/srv", "rsync -av . user@host:/srv",
        "aws s3 sync . s3://bucket",
        "cd app && git push",
        # Task-9b review, "Important": eleven-command audit missed these too.
        "docker compose push", "docker-compose push",
        "helm push chart.tgz oci://registry.example.com/charts",
        "aws s3api put-object --bucket b --key k --body f",
        "gcloud run deploy svc --image=img",
    ]
    IGNORES = [
        "ls -la", "git status", "git commit -m 'x'", "git log --oneline",
        "npm install", "npm run build", "docker build -t x .",
        "vercel dev", "git add -A",
        # A publish-shaped word sitting inside a quoted argument is not a
        # command being invoked -- it is prose. "push notification" is an
        # extremely ordinary thing to name a feature/commit about.
        'git commit -m "add push notification support"',
        "git commit -m 'remember to npm publish next week'",
        'git commit -m "docker push once CI is green"',
        # Task-9b review, "Important": these commands never actually publish.
        "cargo publish --dry-run", "npm publish --dry-run",
        # Task-9b review, "Important": escaped quotes inside a -m message
        # must not close quote-tracking early and re-expose "push" as if it
        # sat outside the message. The docstring's claim -- suppress only,
        # never fabricate -- must hold even with escaped quotes present.
        'git commit -m "rename \\"push\\" button"',
    ]

    # Task-9b review, Important: registries that support --dry-run must not
    # be blocked when a push genuinely can't happen. Every registry in
    # PUBLISH_RE's group, not just the two PoCs (cargo, npm) the review
    # happened to demonstrate -- this is the property, not the PoC.
    REGISTRIES = ["npm", "pnpm", "yarn", "bun", "poetry", "cargo", "flit"]

    def _repo_with_secret(self):
        subprocess.run(["git", "-C", self.root, "init", "-q"],
                       check=True, capture_output=True)
        (Path(self.root) / "leak.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        subprocess.run(["git", "-C", self.root, "add", "-A"],
                       check=True, capture_output=True)

    def test_every_publishing_command_is_intercepted(self):
        self._repo_with_secret()
        missed = [c for c in self.PUBLISHES
                  if decision(run_hook("scan_secrets_before_push.py",
                                       self.event("Bash", command=c))) != "deny"]
        self.assertEqual(missed, [], "comandos não interceptados: " + str(missed))

    def test_ordinary_commands_are_left_alone(self):
        self._repo_with_secret()
        blocked = [c for c in self.IGNORES
                   if decision(run_hook("scan_secrets_before_push.py",
                                        self.event("Bash", command=c))) is not None]
        self.assertEqual(blocked, [], "falsos positivos: " + str(blocked))

    def test_dry_run_never_blocks_any_registry_publish(self):
        # Property: for every registry `X publish` recognizes, appending
        # --dry-run must flip the decision from deny to allow, because a
        # dry run never sends anything anywhere.
        self._repo_with_secret()
        still_blocked = []
        for registry in self.REGISTRIES:
            proc = run_hook("scan_secrets_before_push.py",
                            self.event("Bash", command=f"{registry} publish --dry-run"))
            if decision(proc) is not None:
                still_blocked.append(registry)
        self.assertEqual(still_blocked, [],
                         "--dry-run não suprimiu o bloqueio para: " + str(still_blocked))

    def test_dry_run_does_not_suppress_a_real_publish_in_a_different_clause(self):
        # --dry-run must only cancel the match in ITS OWN clause -- a real
        # publish chained alongside a dry-run of something else must still
        # block.
        self._repo_with_secret()
        proc = run_hook("scan_secrets_before_push.py", self.event(
            "Bash", command="npm publish --dry-run && cargo publish"))
        self.assertEqual(decision(proc), "deny")


class TestExecWrapperCannotHideAPublish(TempProject):
    """Task-9b review, CRITICAL 1: `blank_quoted` used to erase the CONTENTS
    of every quoted span unconditionally -- including when that quoted span
    IS the command actually being run (`bash -c "..."`, `sh -c '...'`,
    `ssh host "..."`, `eval "..."`). That blanked the publish command clean
    out of the text before PUBLISH_RE ever saw it: a real `git push`/`npm
    publish`/etc. wrapped in any of these sailed straight through.

    Tests the PROPERTY -- every publish-shaped command, wrapped in every
    known shell-invoking construct, in either quote style -- rather than
    just the five PoC lines from the review, so a fix that closes only
    those five specific strings (and leaves the underlying "blank every
    quote indiscriminately" bug alive) still fails this suite.
    """
    SCRIPT = "scan_secrets_before_push.py"

    WRAPPERS = [
        'bash -c {q}{inner}{q}',
        'sh -c {q}{inner}{q}',
        'zsh -c {q}{inner}{q}',
        'ssh user@host {q}{inner}{q}',
        'eval {q}{inner}{q}',
    ]
    INNER_PUBLISH_COMMANDS = [
        "git push origin main",
        "npm publish",
        "docker push myreg/app:v1",
        "vercel --prod",
        "scp -r . user@host:/srv",
    ]

    def _repo_with_secret(self):
        subprocess.run(["git", "-C", self.root, "init", "-q"],
                       check=True, capture_output=True)
        (Path(self.root) / "leak.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        subprocess.run(["git", "-C", self.root, "add", "-A"],
                       check=True, capture_output=True)

    def test_every_wrapper_around_every_publish_command_still_blocks(self):
        self._repo_with_secret()
        missed = []
        for wrapper in self.WRAPPERS:
            for inner in self.INNER_PUBLISH_COMMANDS:
                for q in ("'", '"'):
                    cmd = wrapper.format(q=q, inner=inner)
                    proc = run_hook(self.SCRIPT, self.event("Bash", command=cmd))
                    if decision(proc) != "deny":
                        missed.append(cmd)
        self.assertEqual(missed, [], "bypassou o wrapper: " + str(missed))

    def test_a_non_publish_command_inside_a_wrapper_still_allows(self):
        # The fix must not degrade into "any quoted content is now
        # dangerous" -- an innocuous command inside the exact same wrappers
        # must still be allowed.
        self._repo_with_secret()
        blocked = []
        for wrapper in self.WRAPPERS:
            cmd = wrapper.format(q='"', inner="echo hello && ls -la")
            proc = run_hook(self.SCRIPT, self.event("Bash", command=cmd))
            if decision(proc) is not None:
                blocked.append(cmd)
        self.assertEqual(blocked, [], "falso positivo dentro do wrapper: " + str(blocked))

    def test_a_two_level_nested_wrapper_still_blocks(self):
        # Not just one level of unwrapping -- a publish command wrapped
        # twice (a common CI/deploy-script shape: ssh into a box, which
        # itself runs bash -c) must still be caught.
        self._repo_with_secret()
        cmd = """bash -c "ssh user@host 'git push origin main'\""""
        proc = run_hook(self.SCRIPT, self.event("Bash", command=cmd))
        self.assertEqual(decision(proc), "deny")

    def test_a_commit_message_merely_describing_a_wrapper_still_allows(self):
        # Prose that happens to LOOK like an exec wrapper, sitting inside a
        # real -m message, must stay suppressed -- the fix must keep telling
        # "this text IS the command" apart from "this text MENTIONS a
        # command", not just for git push/publish words but for the
        # wrapper syntax itself.
        self._repo_with_secret()
        proc = run_hook(self.SCRIPT, self.event(
            "Bash", command='git commit -m "document how bash -c \\"git push\\" works"'))
        self.assertIsNone(decision(proc))

    def test_a_message_nested_inside_a_wrapper_still_allows(self):
        # Recursion must re-apply message-flag blanking at every level, not
        # just treat everything inside an exec wrapper as raw text to
        # scan -- a commit made *through* a wrapper, whose own message
        # merely mentions a publish word, must not block.
        self._repo_with_secret()
        cmd = """bash -c "git commit -m 'remember to npm publish next week'\""""
        proc = run_hook(self.SCRIPT, self.event("Bash", command=cmd))
        self.assertIsNone(decision(proc))


class TestQuoteRecursionCapFailsRawNotBlank(unittest.TestCase):
    """White-box coverage for blank_quoted's recursion-depth cap
    (MAX_QUOTE_RECURSION), which the public command-line interface cannot
    exercise at all: real double-quote escaping through N nested shells
    grows the command length exponentially in N (each layer roughly
    doubles every backslash needed to survive one more parse), so a chain
    deep enough to exceed MAX_QUOTE_RECURSION (20 levels) already exceeds
    MAX_COMMAND_CHARS (2,000,000) and gets truncated well before recursion
    depth becomes the limiting factor -- the two caps defend each other's
    edge in practice. Tested directly against blank_quoted's internal
    `_depth` parameter instead, as insurance: past the cap, exec content
    must be left RAW for the caller's flat scan, never blanked -- blanking
    it would silently suppress a genuine publish command at exactly the
    depth an attacker chose to exhaust the budget, recreating CRITICAL 1
    at the cap's edge. This is the one place in this suite that imports
    the hook module directly rather than going through run_hook, because
    the property being tested is unreachable from the subprocess/event
    interface by construction.
    """

    def _blank_quoted_at_depth(self, command, depth):
        harness = f"""
import sys, json
sys.path.insert(0, {str(HOOKS_DIR)!r})
import scan_secrets_before_push as m
data = json.loads(sys.stdin.read())
print(json.dumps(m.blank_quoted(data["command"], _depth=data["depth"])))
"""
        proc = subprocess.run(
            [sys.executable, "-c", harness],
            input=json.dumps({"command": command, "depth": depth}),
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def _max_quote_recursion(self):
        harness = f"""
import sys, json
sys.path.insert(0, {str(HOOKS_DIR)!r})
import scan_secrets_before_push as m
print(json.dumps(m.MAX_QUOTE_RECURSION))
"""
        proc = subprocess.run([sys.executable, "-c", harness],
                              capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_one_level_below_the_cap_still_recurses_and_blanks_a_nested_message(self):
        cap = self._max_quote_recursion()
        out = self._blank_quoted_at_depth(
            """bash -c "git commit -m 'mentions npm publish'\"""", cap - 1)
        self.assertNotIn("publish", out)

    def test_at_the_cap_the_command_is_left_raw_not_blanked(self):
        cap = self._max_quote_recursion()
        out = self._blank_quoted_at_depth('bash -c "git push origin main"', cap)
        self.assertIn("git push origin main", out)


class TestPublishRegexTimeBudget(unittest.TestCase):
    """Task-9b review, CRITICAL 2 (plus the coordinator's addendum): two
    independent constructs in this file cost O(n^2) when their trigger word
    repeats and the thing it's looking for never shows up --

    1. Each alternative in `\\b(?:vercel|netlify|firebase|flyctl|fly|surge|
       amplify)\\b(?=[^|;&]*(?:deploy|publish|--prod))` re-scans to the end
       of the string from EVERY occurrence of the trigger word.
    2. `GIT_PUSH_RE = \\bgit\\b[^|;&]*?\\bpush\\b` does the same thing via
       its lazy gap -- this is a second, independent mechanism, not the
       same lookahead, so fixing only the vercel/netlify alternative would
       leave this bug class alive.

    Both are ordinary English/devops words ("fly", "git", "surge") that
    show up at scale in heredocs, CI logs, and generated scripts without
    anyone attacking anything. This asserts a time BUDGET, not a single
    point measurement, over every trigger word in both mechanisms, so a fix
    that special-cases one word (or one mechanism) and leaves the general
    pattern quadratic still fails.
    """
    HOSTING_TRIGGERS = ["vercel", "netlify", "firebase", "flyctl", "fly",
                        "surge", "amplify"]
    REPEAT_COUNT = 20_000
    BUDGET_SECONDS = 5.0

    def _time_allow(self, command):
        proc = run_hook("scan_secrets_before_push.py",
                        {"cwd": tempfile.mkdtemp(), "tool_name": "Bash",
                         "tool_input": {"command": command}})
        return proc

    def test_hosting_trigger_words_never_blow_up_when_the_target_is_absent(self):
        slow = []
        for trigger in self.HOSTING_TRIGGERS:
            command = (trigger + " ") * self.REPEAT_COUNT
            start = time.time()
            proc = self._time_allow(command)
            elapsed = time.time() - start
            self.assertIsNone(decision(proc))  # never deploy/publish/--prod
            if elapsed > self.BUDGET_SECONDS:
                slow.append((trigger, round(elapsed, 2)))
        self.assertEqual(slow, [], "estourou o orçamento de tempo: " + str(slow))

    def test_git_word_never_blows_up_when_push_is_absent(self):
        command = ("git status; " * self.REPEAT_COUNT)
        start = time.time()
        proc = self._time_allow(command)
        elapsed = time.time() - start
        self.assertIsNone(decision(proc))
        self.assertLessEqual(elapsed, self.BUDGET_SECONDS,
                             f"git-word scan took {elapsed:.2f}s")

    def test_a_multi_megabyte_command_still_completes_quickly(self):
        # Defense in depth: even with the quadratic behavior fixed, an
        # unbounded command has no legitimate reason to cost real hook
        # time. A several-MB pathological command (trigger word repeated,
        # target never present) must still return well inside budget.
        command = ("fly " * 400_000)  # ~2MB
        start = time.time()
        proc = self._time_allow(command)
        elapsed = time.time() - start
        self.assertIsNone(decision(proc))
        self.assertLessEqual(elapsed, self.BUDGET_SECONDS,
                             f"multi-MB command took {elapsed:.2f}s")


class TestMigrationPatterns(TempProject):
    """Rule 1's protected_paths must be anchored to actual migration
    directories/files, never a catch-all that also swallows application code
    or docs that merely mention "migrations", and the suggested command in
    the deny reason must be runnable shell, not a doc placeholder like
    `<describe_change>` that a shell reads as a redirection."""

    CONFIG = {"migrations": {
        "tool": "prisma",
        "command": "npx prisma migrate dev --name describe_change",
        "protected_paths": ["prisma/migrations/**", "alembic/versions/**",
                            "**/migrations/[0-9]*", "**/migrations/*.sql"]}}

    BLOCK = ["prisma/migrations/20260101_init/migration.sql",
             "alembic/versions/abc123_init.py",
             "app/migrations/0001_initial.py",
             "migrations/0002_add_user.py"]
    ALLOW = ["src/lib/migrations/runner.ts",
             "src/features/migrations/MigrationBanner.tsx",
             "docs/migrations/guide.md",
             "tests/migrations/test_runner.py"]

    def test_real_migrations_are_blocked(self):
        self.write_config(self.CONFIG)
        for rel in self.BLOCK:
            proc = run_hook("block_migration_edits.py", self.event(
                "Edit", file_path=os.path.join(self.root, rel)))
            self.assertEqual(decision(proc), "deny", rel)

    def test_application_code_named_migrations_is_allowed(self):
        self.write_config(self.CONFIG)
        for rel in self.ALLOW:
            proc = run_hook("block_migration_edits.py", self.event(
                "Edit", file_path=os.path.join(self.root, rel)))
            self.assertIsNone(decision(proc), rel)

    def test_the_suggested_command_is_valid_shell(self):
        self.write_config(self.CONFIG)
        proc = run_hook("block_migration_edits.py", self.event(
            "Edit", file_path=os.path.join(self.root, self.BLOCK[0])))
        reason_text = json.loads(proc.stdout)["hookSpecificOutput"][
            "permissionDecisionReason"]
        command = reason_text.split("run: ")[1].split("\n")[0]
        check = subprocess.run(["bash", "-n", "-c", command],
                               capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_a_nearby_non_numeric_non_sql_migrations_file_is_allowed(self):
        # Property, not just the brief's examples: anything under a
        # "migrations" directory that is neither a numbered file nor a .sql
        # file is application code (a helper, an index, a README), not a
        # generated migration -- must stay editable.
        self.write_config(self.CONFIG)
        for rel in ["migrations/README.md", "migrations/index.ts",
                    "app/db/migrations/utils.py", "migrations/migrations.py"]:
            proc = run_hook("block_migration_edits.py", self.event(
                "Edit", file_path=os.path.join(self.root, rel)))
            self.assertIsNone(decision(proc), rel)


class TestShippedConfigExampleMigrations(unittest.TestCase):
    """Objective lock on assets/config.example.json's migrations section --
    the exact config a real beginner project gets from onboarding. Runs the
    same BLOCK/ALLOW/valid-shell checks TestMigrationPatterns runs against a
    hand-picked config, but against what actually ships."""

    ROOT = Path(__file__).resolve().parent.parent

    @classmethod
    def setUpClass(cls):
        raw = (cls.ROOT / "assets" / "config.example.json").read_text()
        cls.migrations = json.loads(raw)["migrations"]

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        cfg_dir = Path(self.root) / ".claude-for-idiots"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "config.json").write_text(
            json.dumps({"migrations": self.migrations}))

    def tearDown(self):
        self._tmp.cleanup()

    def event(self, tool, **tool_input):
        return {"cwd": self.root, "tool_name": tool, "tool_input": tool_input}

    def test_real_migrations_are_blocked(self):
        for rel in TestMigrationPatterns.BLOCK:
            proc = run_hook("block_migration_edits.py", self.event(
                "Edit", file_path=os.path.join(self.root, rel)))
            self.assertEqual(decision(proc), "deny", rel)

    def test_application_code_named_migrations_is_allowed(self):
        for rel in TestMigrationPatterns.ALLOW:
            proc = run_hook("block_migration_edits.py", self.event(
                "Edit", file_path=os.path.join(self.root, rel)))
            self.assertIsNone(decision(proc), rel)

    def test_the_suggested_command_is_valid_shell(self):
        proc = run_hook("block_migration_edits.py", self.event(
            "Edit", file_path=os.path.join(
                self.root, TestMigrationPatterns.BLOCK[0])))
        reason_text = json.loads(proc.stdout)["hookSpecificOutput"][
            "permissionDecisionReason"]
        command = reason_text.split("run: ")[1].split("\n")[0]
        check = subprocess.run(["bash", "-n", "-c", command],
                               capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)


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


class TestGlobListWorkBudgetEndToEnd(TempProject):
    """CRITICAL-A (fix round 3), exercised through the real hook subprocess
    (not just the library function): a config.json listing many expensive
    glob patterns must not push a hook's wall-clock time toward Claude
    Code's 60s PreToolUse timeout. Uses the same near-worst-case pattern
    shape as the round-3 review's own measurement (a long literal prefix +
    wildcards + long literal suffix, forcing the DP to scan the whole
    non-matching path instead of failing out after the first character).
    """

    _EXPENSIVE_PATTERN = "a" * 510 + "*" * 10 + "a" * 500 + "z"
    # Single path component (no '/'), so the DP cannot bail out early on a
    # literal mismatch at the first separator -- it must actually walk the
    # wildcard section, matching the cost the review measured. Under
    # MAX_GLOB_PATH_CHARS so cost() is not simply 0 via the per-path cap.
    _NONMATCHING_MIGRATION_TARGET = "a" * 4094 + "q"
    _NONMATCHING_CODE_TARGET = "a" * 4090 + ".py"

    def test_many_expensive_protected_paths_do_not_stall_block_migration_edits(self):
        self.write_config({"migrations": {
            "tool": "x", "command": "x",
            "protected_paths": [self._EXPENSIVE_PATTERN] * 200}})
        start = time.monotonic()
        proc = run_hook("block_migration_edits.py", self.event(
            "Edit", file_path=os.path.join(self.root, self._NONMATCHING_MIGRATION_TARGET)))
        elapsed = time.monotonic() - start
        self.assertEqual(proc.returncode, 0)
        self.assertIsNone(decision(proc))
        self.assertLess(elapsed, 10.0,
                         f"block_migration_edits.py took {elapsed:.2f}s for 200 expensive patterns")

    def test_many_expensive_allowed_paths_do_not_stall_enforce_architecture(self):
        self.write_config({"architecture": {
            "name": "x", "enforce": "deny",
            "allowed_paths": [self._EXPENSIVE_PATTERN] * 200, "layers": {}}})
        start = time.monotonic()
        proc = run_hook("enforce_architecture.py", self.event(
            "Write", file_path=os.path.join(self.root, self._NONMATCHING_CODE_TARGET)))
        elapsed = time.monotonic() - start
        self.assertEqual(proc.returncode, 0)
        self.assertLess(elapsed, 10.0,
                         f"enforce_architecture.py took {elapsed:.2f}s for 200 expensive patterns")


class TestCompileGlobNeverCrashesTheRealHook(TempProject):
    """CRITICAL-B (fix round 3), the exact end-to-end repro from the brief:
    a descending-range character class in protected_paths must not crash
    block_migration_edits.py."""

    def test_descending_range_in_protected_paths_fails_open(self):
        self.write_config({"migrations": {
            "tool": "x", "command": "x", "protected_paths": ["[b-a]"]}})
        proc = run_hook("block_migration_edits.py", self.event(
            "Edit", file_path=os.path.join(self.root, "b")))
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)
        self.assertIsNone(decision(proc))


class TestAllowedVsProtectedFailOpenSymmetry(TempProject):
    """IMPORTANT (fix round 3): matches_any's aggregate work budget must
    fail open in the DIRECTION each hook needs, not just return a fixed
    boolean. block_migration_edits.py DENIES on a match (protected_paths),
    so an unevaluated pattern list must never manufacture a block.
    enforce_architecture.py ALLOWS on a match (allowed_paths), so an
    unevaluated pattern list must never manufacture a deny/ask -- otherwise
    an absurd config makes Rule 5 over-block legitimate writes instead of
    just degrading, the exact asymmetry the round-3 review reported (a
    1044-char allowed_paths entry that should have matched instead denied).
    """

    _EXPENSIVE_PATTERN = "a" * 510 + "*" * 10 + "a" * 500 + "z"
    # Enough copies that the aggregate budget is exhausted before the list
    # is fully evaluated (see test_common.py's derivation of this count from
    # the module's own constants; hardcoded here at a value known to exceed
    # it with today's cap sizes: 200 * ~4.18M cells far exceeds 20M).
    _MANY = [_EXPENSIVE_PATTERN] * 200

    def test_enforce_architecture_allows_when_allowed_paths_cannot_be_fully_evaluated(self):
        self.write_config({"architecture": {
            "name": "x", "enforce": "deny",
            "allowed_paths": self._MANY, "layers": {}}})
        proc = run_hook("enforce_architecture.py", self.event(
            "Write", file_path=os.path.join(self.root, "a" * 4090 + ".py")))
        self.assertIsNone(decision(proc),
                           "an unevaluated allowed_paths list must ALLOW, not deny/ask")

    def test_block_migration_edits_allows_when_protected_paths_cannot_be_fully_evaluated(self):
        self.write_config({"migrations": {
            "tool": "x", "command": "x", "protected_paths": self._MANY}})
        proc = run_hook("block_migration_edits.py", self.event(
            "Edit", file_path=os.path.join(self.root, "a" * 4094 + "q")))
        self.assertIsNone(decision(proc),
                           "an unevaluated protected_paths list must ALLOW, not block")


class TestMainNeverExitsNonZero(TempProject):
    """Item 4 (fix round 3): a blanket try/except around every hook's
    main() call, as a backstop for the NEXT unanticipated exception -- this
    execution alone found four of this same shape (RecursionError on deep
    JSON, re.error on a descending range, TypeError on a non-string
    command, and the ReDoS/work-budget family). Simulates "a bug nobody has
    found yet" by forcing an unrelated, generic exception deep inside
    main()'s call chain via monkeypatching, then running the hook's own
    `if __name__ == "__main__":` guard through runpy so the real
    try/except wrapper is exercised, not a hand test of the exception
    handler in isolation.
    """

    def _run_with_forced_exception(self, script, patch_target, event):
        harness = f"""
import sys, runpy
sys.path.insert(0, {str(HOOKS_DIR)!r})
import _cfi_common as cfi

def _boom(*args, **kwargs):
    raise RuntimeError("simulated unanticipated failure")

{patch_target} = _boom
runpy.run_path({str(HOOKS_DIR / script)!r}, run_name="__main__")
"""
        return subprocess.run(
            [sys.executable, "-c", harness],
            input=json.dumps(event) if isinstance(event, dict) else event,
            capture_output=True, text=True, timeout=30,
        )

    def test_block_migration_edits_survives_a_failure_reading_the_event(self):
        self.write_config(MIGRATIONS_CONFIG)
        proc = self._run_with_forced_exception(
            "block_migration_edits.py", "cfi.read_event",
            self.event("Edit", file_path=os.path.join(self.root, "alembic/versions/a.py")))
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)

    def test_block_migration_edits_survives_a_failure_inside_matches_any(self):
        self.write_config(MIGRATIONS_CONFIG)
        proc = self._run_with_forced_exception(
            "block_migration_edits.py", "cfi.matches_any",
            self.event("Edit", file_path=os.path.join(self.root, "alembic/versions/a.py")))
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)

    def test_enforce_architecture_survives_a_failure_reading_the_event(self):
        self.write_config(ARCH_CONFIG)
        proc = self._run_with_forced_exception(
            "enforce_architecture.py", "cfi.read_event",
            self.event("Write", file_path=os.path.join(self.root, "random/thing.py")))
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)

    def test_enforce_architecture_survives_a_failure_inside_matches_any(self):
        self.write_config(ARCH_CONFIG)
        proc = self._run_with_forced_exception(
            "enforce_architecture.py", "cfi.matches_any",
            self.event("Write", file_path=os.path.join(self.root, "app/services/x.py")))
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)

    def test_scan_secrets_before_push_survives_a_failure_reading_the_event(self):
        proc = self._run_with_forced_exception(
            "scan_secrets_before_push.py", "cfi.read_event",
            self.event("Bash", command="git push origin main"))
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
