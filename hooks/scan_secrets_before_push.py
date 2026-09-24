#!/usr/bin/env python3
"""Rule 6 — secrets never reach the remote.

PreToolUse hook (matcher: Bash). When a command publishes anything (git push,
gh repo create, gh release, gh pr create), scan the repo's git-tracked files for
obvious secrets and for a tracked .env. Blocks the command if anything is found.
Fails open on every other command.

This is a deliberately simple, extendable scanner — add patterns as needed.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _cfi_common as cfi

PUBLISH_RE = re.compile(
    r"\b(git\s+push|gh\s+repo\s+create|gh\s+release|gh\s+pr\s+create)\b"
)

SECRET_PATTERNS = [
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Private key block", re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("Hardcoded credential", re.compile(
        r"(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*"
        r"['\"][^'\"\s]{12,}['\"]")),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Generic bearer/JWT", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
]

MAX_BYTES = 1_000_000


def repo_root(cwd):
    """Top level of the working tree, so a push from a subdirectory still
    scans everything `git push` is about to send -- not just the slice of
    the tree under `cwd`. None when `cwd` isn't inside a git repo (or git
    can't be run), in which case the caller falls back to `cwd` itself.
    """
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=cwd,
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    root = out.stdout.strip()
    return root or None


def tracked_files(root):
    """Git-tracked paths under `root`, relative to it.

    Uses `-z` (NUL-separated, raw bytes) rather than the newline-separated
    default: with the default `core.quotePath=true`, git prints any path
    containing a non-ASCII byte as a quoted string with octal escapes (e.g.
    `"app/configura\\303\\247\\303\\243o.py"`), and that quoted form is not a
    path `open()` can resolve -- it would silently fail to open, and the
    caller's `except OSError: continue` would skip the file without a trace.
    `-z` sides-steps quoting entirely. Decoding is `surrogateescape` so a
    path that isn't valid UTF-8 still round-trips to a working local path
    instead of raising or getting mangled.
    """
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"], cwd=root,
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    names = out.stdout.split(b"\0")
    return [n.decode("utf-8", "surrogateescape") for n in names if n]


def main():
    event = cfi.read_event()
    if not event:
        cfi.allow()

    if event.get("tool_name") != "Bash":
        cfi.allow()
    command = (event.get("tool_input") or {}).get("command", "")
    if not PUBLISH_RE.search(command):
        cfi.allow()

    cwd = event.get("cwd") or os.getcwd()
    root = repo_root(cwd) or cwd
    findings = []

    for rel in tracked_files(root):
        base = os.path.basename(rel)
        if base == ".env" or (base.startswith(".env.") and not base.endswith(".example")):
            findings.append(f"{rel}: tracked .env file (should be gitignored)")
        full = os.path.join(root, rel)
        try:
            if os.path.getsize(full) > MAX_BYTES:
                continue
            with open(full, "r", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(f"{rel}: {label}")
                break

    if findings:
        listing = "\n".join(f"  - {x}" for x in findings[:20])
        cfi.decide("deny", (
            "BLOCKED by claude-for-idiots Rule 6: possible secrets would "
            "be published.\n" + listing + "\n"
            "Move secrets to a gitignored .env, add a .env.example, remove "
            "them from git history if already committed, then retry. "
            "Warn the user clearly in their language."
        ))

    cfi.allow()


if __name__ == "__main__":
    main()
