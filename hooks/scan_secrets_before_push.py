#!/usr/bin/env python3
"""Rule 6 — secrets never reach the remote.

PreToolUse hook (matcher: Bash). When a command publishes anything -- git push
(any global flags), gh (repo create/edit, release, pr create, gist create),
package registries (npm/pnpm/yarn/bun/poetry/cargo/flit publish, twine
upload), docker push, hosting deploys (vercel/netlify/firebase/flyctl/fly/
surge/amplify/wrangler), or raw file transfer (scp/rsync/aws s3 cp/sync) --
scan the repo's git-tracked files for obvious secrets and for a tracked .env.
Blocks the command if anything is found. Fails open on every other command.

This is a deliberately simple, extendable scanner — add patterns as needed.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _cfi_common as cfi

# Matches only "git ... push", not any other publishing command -- kept
# separate (rather than inlined into PUBLISH_RE below) so a future hook that
# needs to tell "this is specifically a git push" apart from "this is some
# other kind of publish" (git never sends a gitignored file; scp/vercel/etc.
# upload the whole working directory, gitignored or not) can reuse it instead
# of writing a second copy. `[^|;&]*?` -- any run of characters that isn't a
# shell separator -- absorbs git's own global flags (`-C .`, `--git-dir=`,
# `-c k=v`) between `git` and `push` without crossing into a chained command
# (`git status && ls push` must NOT match).
GIT_PUSH_RE = re.compile(r"\bgit\b[^|;&]*?\bpush\b")

# The whole publish surface, not just git/gh: package registries (npm/pnpm/
# yarn/bun/poetry/cargo/flit/twine), container registries (docker push),
# hosting platforms (vercel/netlify/firebase/flyctl/fly/surge/amplify,
# wrangler), and raw file transfer (scp/rsync/aws s3). An audit of twelve
# real publishing commands found eleven passing through the old regex
# untouched, and `git push` itself dodged by any global flag placed before
# the subcommand. Case-insensitive because a shell doesn't care and neither
# should this.
PUBLISH_RE = re.compile(r"""(?xi)
      """ + GIT_PUSH_RE.pattern + r"""
    | \bgh\s+(?: repo\s+(?:create|edit)
               | release\b
               | pr\s+create
               | gist\s+create )
    | \b(?:npm|pnpm|yarn|bun|poetry|cargo|flit)\s+publish\b
    | \btwine\s+upload\b
    | \bdocker\s+push\b
    | \b(?:vercel|netlify|firebase|flyctl|fly|surge|amplify)\b(?=[^|;&]*(?:deploy|publish|--prod))
    | \bwrangler\s+(?:deploy|publish)\b
    | \b(?:scp|rsync)\s
    | \baws\s+s3\s+(?:cp|sync)\b
""")

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


def blank_quoted(command):
    """`command` with the CONTENTS of every '...'/"..." span replaced by
    spaces, quote characters themselves kept in place.

    PUBLISH_RE's whole point is to tell "this command publishes something"
    from free text sitting in an argument -- and the single most common
    free-text argument in a git workflow is a commit message. Without this,
    `git commit -m "add push notification support"` matches PUBLISH_RE: the
    word "push" sits right after "git" with nothing but ordinary characters
    (no `|`, `;`, `&`) in between, exactly what the publish patterns are
    built to tolerate (git's own global flags, docker's registry path, ...).
    Blanking quoted content first means a publish-shaped word only counts
    when it is actually part of the command being invoked, not part of what
    a flag's value says. This helps every alternative in PUBLISH_RE, not
    just git -- "remember to npm publish next week" in a commit message is
    exactly as much a false positive as the push case.

    Deliberately not real shell parsing (no backslash-escape handling, no
    distinguishing single- from double-quote semantics): an unterminated
    quote just blanks to the end of the string, which only ever suppresses a
    potential match, never manufactures one out of quoted text -- the safe
    direction for a fail-open hook.
    """
    out = []
    quote = None
    for ch in command:
        if quote:
            out.append(ch if ch == quote else " ")
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
        out.append(ch)
    return "".join(out)


def main():
    event = cfi.read_event()
    if not event:
        cfi.allow()

    if event.get("tool_name") != "Bash":
        cfi.allow()
    command = (event.get("tool_input") or {}).get("command", "")
    if not isinstance(command, str):
        # Pre-existing gap, not introduced here: `tool_input.command` is
        # attacker/tool-influenced input, same as everything else read from
        # the event. A non-string value (a malformed or hostile event) used
        # to reach PUBLISH_RE.search() directly and raise TypeError --
        # crashing the hook with a non-zero exit instead of failing open.
        cfi.allow()
    if not PUBLISH_RE.search(blank_quoted(command)):
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
    try:
        main()
    except Exception:
        # Last-resort net -- see block_migration_edits.py for the rationale
        # (this codebase has already found three distinct fail-open gaps of
        # this same shape across the three hooks). Never catches the
        # SystemExit that cfi.allow()/cfi.decide() raise.
        sys.exit(0)
