#!/usr/bin/env python3
"""Rule 6 — secrets never reach the remote.

PreToolUse hook (matcher: Bash). When a command publishes anything -- git push
(any global flags), gh (repo create/edit, release, pr create, gist create),
package registries (npm/pnpm/yarn/bun/poetry/cargo/flit publish, twine
upload), docker/docker-compose/helm push, hosting deploys (vercel/
netlify/firebase/flyctl/fly/surge/amplify/wrangler/gcloud run deploy/az
webapp up), or raw file transfer (scp/rsync/sftp/curl -T/aws s3 cp,sync,
s3api put-object) -- scan the repo's git-tracked files for obvious secrets
and for a tracked .env.
Blocks the command if anything is found. Fails open on every other command.

This is a deliberately simple, extendable scanner — add patterns as needed.
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _cfi_common as cfi

# Word-level building blocks for the two ordered-pair checks below (git...
# push, and hosting-trigger...deploy). Case-insensitive because a shell
# doesn't care and neither should this.
_GIT_WORD_RE = re.compile(r"\bgit\b", re.I)
_PUSH_WORD_RE = re.compile(r"\bpush\b", re.I)
_HOSTING_TRIGGER_RE = re.compile(
    r"\b(?:vercel|netlify|firebase|flyctl|fly|surge|amplify)\b", re.I)
# Deliberately no \b around --prod (mirrors the pre-existing target set --
# this file has never required a word boundary before the leading '-').
_HOSTING_TARGET_RE = re.compile(r"deploy|publish|--prod", re.I)


def _ordered_pair_in_clause(clause, first_re, second_re):
    """True if `first_re` matches somewhere in `clause` AND `second_re`
    matches somewhere AFTER that match -- checked from `first_re`'s
    LEFTMOST occurrence only, not from every occurrence.

    This is the fix for task-9b's CRITICAL 2: the code this replaced --
    `\\bgit\\b[^|;&]*?\\bpush\\b` and `\\b(?:vercel|...)\\b(?=[^|;&]*(?:deploy
    |publish|--prod))` -- re-scanned forward to the end of the clause from
    EVERY occurrence of the trigger word, an O(n^2) blowup when the trigger
    repeats and the target never appears (a heredoc or log mentioning "git"
    or "fly" thousands of times took 20-45s; see task-9b-report.md for the
    measured curve). Checking only the leftmost occurrence is sound, not
    just faster: if `second_re` doesn't occur anywhere after the FIRST
    occurrence of `first_re`, it cannot occur after any LATER occurrence
    either -- the search space after a later position is strictly smaller.
    So one leftmost search plus one forward search from there (both O(n),
    no backtracking blowup) captures exactly the same "some occurrence of
    first_re has second_re after it" condition the old lazy/lookahead scan
    was computing the expensive way.
    """
    m = first_re.search(clause)
    if not m:
        return False
    return bool(second_re.search(clause, m.end()))


def _clauses(command):
    """`command` split on shell control operators (|, ;, &) -- the same
    boundary the ordered-pair ("git push", hosting-trigger-then-deploy")
    checks must not cross (`git status && ls push` must NOT match). Used
    so those checks -- and the plain publish patterns below, which are
    self-contained and never need to cross this boundary either -- only
    ever look within one clause at a time.
    """
    return re.split(r"[|;&]+", command)


def is_git_push(blanked_command):
    """True if any clause of `blanked_command` (already run through
    `blank_quoted`) invokes `git ... push` -- git's own global flags
    (`-C .`, `--git-dir=`, `-c k=v`) between `git` and `push` are absorbed
    by the ordered-pair check the same way the old `[^|;&]*?` gap did,
    just without its quadratic cost.
    """
    return any(_ordered_pair_in_clause(c, _GIT_WORD_RE, _PUSH_WORD_RE)
               for c in _clauses(blanked_command))


def _is_hosting_deploy(blanked_command):
    return any(_ordered_pair_in_clause(c, _HOSTING_TRIGGER_RE, _HOSTING_TARGET_RE)
               for c in _clauses(blanked_command))


# Registries that support a --dry-run (or equivalent) flag which performs
# every check but never actually sends anything -- task-9b review,
# Important: `cargo publish --dry-run` / `npm publish --dry-run` were
# blocked despite never publishing. Scoped per-clause (see
# _is_registry_publish) so a dry run of one command never suppresses a real
# publish chained alongside it.
_REGISTRY_PUBLISH_RE = re.compile(
    r"\b(?:npm|pnpm|yarn|bun|poetry|cargo|flit)\s+publish\b", re.I)
_DRY_RUN_RE = re.compile(r"--dry-run\b", re.I)


def _is_registry_publish(clause):
    return bool(_REGISTRY_PUBLISH_RE.search(clause)) and not _DRY_RUN_RE.search(clause)


# curl's upload flag (-T/--upload-file) sends a local file TO a remote
# server -- task-9b review, "Important". Checked as two independent,
# order-agnostic scans (not a single pattern joining them with `.*`) so
# this can never become a third quadratic construct: `curl` and `-T`
# appearing anywhere in the same clause is already a narrow enough signal
# without requiring a particular order between them.
_CURL_RE = re.compile(r"\bcurl\b", re.I)
_CURL_UPLOAD_FLAG_RE = re.compile(r"(?:^|\s)(?:-T|--upload-file)(?:\s|$)", re.I)

# The rest of the publish surface: self-contained, fixed-width alternatives
# that never need the ordered-pair treatment above because none of them
# rely on scanning an unbounded gap to a separately-occurring word -- each
# one is anchored to characters immediately adjacent to itself. An audit of
# twelve real publishing commands originally found eleven passing through
# untouched; task-9b's review added docker compose push / docker-compose
# push, helm push, aws s3api put-object, gcloud run deploy, and az webapp up
# (sftp and curl's upload flag are handled separately below).
PUBLISH_RE_PLAIN = re.compile(r"""(?xi)
      \bgh\s+(?: repo\s+(?:create|edit)
               | release\b
               | pr\s+create
               | gist\s+create )
    | \btwine\s+upload\b
    | \bdocker(?:-compose|\s+compose)\s+push\b
    | \bdocker\s+push\b
    | \bhelm\s+push\b
    | \bwrangler\s+(?:deploy|publish)\b
    | \b(?:scp|rsync|sftp)\s
    | \baws\s+s3\s+(?:cp|sync)\b
    | \baws\s+s3api\s+put-object\b
    | \bgcloud\s+run\s+deploy\b
    | \baz\s+webapp\s+up\b
""")


def is_publish_command(blanked_command):
    """True if `blanked_command` (already run through `blank_quoted`)
    invokes anything on the publish surface: git push, a hosting-platform
    deploy, a registry publish (not a --dry-run), a curl upload, or any of
    the other self-contained patterns above.
    """
    if is_git_push(blanked_command):
        return True
    for clause in _clauses(blanked_command):
        if not clause:
            continue
        if _is_hosting_deploy(clause):
            return True
        if PUBLISH_RE_PLAIN.search(clause):
            return True
        if _is_registry_publish(clause):
            return True
        if _CURL_RE.search(clause) and _CURL_UPLOAD_FLAG_RE.search(clause):
            return True
    return False


# Defense in depth alongside the algorithmic fix above: even at O(n), a
# shell command line has no legitimate reason to run past this many
# characters, and this bounds the (now linear, but still real) cost of
# blank_quoted + is_publish_command against a pathologically large
# `command` -- a multi-MB heredoc or embedded log -- regardless of how fast
# the underlying scan is. "cap alone just moves the limit" per the review,
# which is why this is paired with the quadratic-cost fix, not a
# replacement for it.
MAX_COMMAND_CHARS = 2_000_000

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


def _git_env():
    """`os.environ` with GIT_DIR/GIT_WORK_TREE stripped, for every `git`
    subprocess this hook runs.

    Deferred from Task 7's review: if GIT_DIR (or GIT_WORK_TREE) is set in
    the environment -- a parent process, a CI wrapper, or a hostile
    environment -- and points at a DIFFERENT repository, these variables
    override git's normal discovery from `cwd`/`-C` entirely. Every `git`
    call below would then resolve against THAT repo's index and working
    tree instead of `root`: `git ls-files` lists the other repo's files,
    none of them exist under `root`, `open()` raises OSError, and the
    existing `except OSError: continue` skips them without a trace -- the
    real secrets at `root` are never read, and a leaking push is allowed.
    (`repo_root` is exposed to the same override -- `git rev-parse
    --show-toplevel` would report the OTHER repo's toplevel, silently
    redirecting the entire scan there.) Stripping both variables for every
    subprocess call here forces git to resolve strictly from the `cwd`
    actually passed, closing the gap.
    """
    env = dict(os.environ)
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    return env


def repo_root(cwd):
    """Top level of the working tree, so a push from a subdirectory still
    scans everything `git push` is about to send -- not just the slice of
    the tree under `cwd`. None when `cwd` isn't inside a git repo (or git
    can't be run), in which case the caller falls back to `cwd` itself.
    """
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=cwd, env=_git_env(),
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
            ["git", "ls-files", "-z"], cwd=root, env=_git_env(),
            capture_output=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if out.returncode != 0:
        return []
    names = out.stdout.split(b"\0")
    return [n.decode("utf-8", "surrogateescape") for n in names if n]


# Cap on how much of `git log -p` output is actually searched. A huge
# unpushed text-file rewrite could in principle produce a diff of unbounded
# size, all buffered in memory by `capture_output=True`; this bounds memory
# and regex time the same way MAX_BYTES already bounds a single tracked
# file's content below. Secrets live in short, local lines, so truncation
# only risks missing one that happens to sit past 5MB of diff text into a
# single push -- already an enormous unpushed changeset.
MAX_HISTORY_CHARS = 5_000_000

# Generous but bounded: real `git log -p` over a realistic history finishes
# in well under a second (measured in task-8-report.md); this timeout only
# matters for a hung/corrupted git process, where the goal is just to give
# up and fail open rather than block the hook indefinitely. Two attempts can
# run per call (see unpushed_diff), so the worst-case addition to this
# hook's total budget is 2 * HISTORY_TIMEOUT seconds.
HISTORY_TIMEOUT = 10


def unpushed_diff(root):
    """The diff `git push` is about to send, as text -- not just what's at
    HEAD, but every unpushed commit's full patch. A secret added and then
    "fixed" in a later commit is still sent: `git push` transmits the
    objects, so the fix does not un-send the leak.

    Tries `@{upstream}..HEAD` first -- exactly the commits this push would
    add to the remote, so an already-published secret is never re-flagged
    on every later push. Falls back to the last 50 commits when there is no
    upstream (first push on a new branch/repo) so a first push still gets
    *some* history coverage instead of none; 50 is a fixed cap regardless of
    how deep the repo's history actually is, so this branch's cost doesn't
    grow with repo age. "" (no findings) on any git failure -- fail open,
    same direction as every other helper in this file.
    """
    for args in (["log", "-p", "--no-color", "@{upstream}..HEAD"],
                 ["log", "-p", "--no-color", "-n", "50"]):
        try:
            out = subprocess.run(
                ["git"] + args, cwd=root, env=_git_env(),
                capture_output=True, text=True, errors="replace",
                timeout=HISTORY_TIMEOUT,
            )
        except (OSError, subprocess.SubprocessError):
            return ""
        if out.returncode == 0:
            return out.stdout[:MAX_HISTORY_CHARS]
    return ""


# Directories that legitimately can't hold a project's own gitignored .env
# but routinely hold tens of thousands of entries each (dependency trees,
# build output, caches): walking into them costs real time for zero
# security value, since no stack in the catalog ever expects a secret to
# live inside one.
ENV_WALK_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", ".next",
    "dist", "build", ".tox", "target", ".pytest_cache", ".mypy_cache",
}

# Defensive cap on how many files env_files_on_disk will look at, so a
# pathologically large tree not covered by ENV_WALK_SKIP_DIRS still can't
# make this walk unbounded. Far beyond any real project (measured below).
MAX_ENV_WALK_ENTRIES = 200_000


def env_files_on_disk(root):
    """Gitignored `.env` files anywhere under `root`, relative to it.

    Invisible to `git ls-files` by definition -- that's what gitignored
    means -- but vercel, netlify, docker build, scp and rsync all upload
    the whole directory tree, ignored or not. Walked recursively (not just
    `root`'s own top level) because every stack in the catalog can have the
    actual service -- and its `.env` -- sitting inside a subdirectory
    (`apps/api/.env`, `backend/.env`, ...), and a non-git deploy uploads
    that too.
    """
    found = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ENV_WALK_SKIP_DIRS]
        for name in filenames:
            seen += 1
            if seen > MAX_ENV_WALK_ENTRIES:
                return found
            if name == ".env" or (name.startswith(".env.")
                                   and not name.endswith((".example", ".sample"))):
                found.append(os.path.relpath(os.path.join(dirpath, name), root))
    return found


# Programs that treat their next quoted argument as a command STRING to
# execute, rather than as free text -- task-9b review, CRITICAL 1:
# `bash -c "git push origin main"` used to have its payload blanked away
# like any other quoted span, and is_publish_command() never got to see
# it. Content quoted here IS the command being run and must be scanned,
# not blanked.
# Only a short, fixed-size window immediately before the quote is checked
# (see _is_exec_arg) rather than the whole preceding command, so this stays
# O(1) per quote no matter how long `command` is -- scanning an unbounded
# prefix per quote would reintroduce a CRITICAL-2-shaped cost for a command
# containing many quoted spans.
EXEC_ARG_RE = re.compile(r"""(?xi)
      \b(?:bash|sh|zsh|dash|ksh|ash)\s+-c\s*=?\s*$
    | \beval\s*$
    | \bssh\s+\S+\s*$
""")

# Fixed lookback window (characters), not the whole prefix -- see EXEC_ARG_RE.
_EXEC_LOOKBACK = 80

# Hard cap on quote-recursion depth (see blank_quoted). Bounds the worst
# case -- a command crafted as many nested `bash -c "bash -c "..."` wrappers
# -- to O(depth * len(command)) instead of a nesting-depth-proportional
# O(len(command)^2); real commands never nest anywhere close to this deep.
MAX_QUOTE_RECURSION = 20


def _quote_span_end(s, start, quote):
    """Index of the matching closing `quote` character, scanning from
    `start` (just after the opening quote). Returns len(s) if the quote is
    never closed (falls off the end) -- same "unterminated blanks to the
    end of the string" behavior blank_quoted has always had.

    Only DOUBLE-quote spans honor backslash-escaping (`\\"` is a literal
    quote, not the end of the span) -- matching real shell semantics: a
    real shell never lets a backslash escape a single quote (there is no
    way to put a literal `'` inside a `'...'` span at all), but it does let
    `\\"` inside a `"..."` span stay literal. The previous implementation
    treated both quote kinds identically and closed on ANY matching quote
    character regardless of a preceding backslash -- which let an escaped
    quote inside a -m message end quote-tracking early, re-exposing the
    rest of the message as if it sat outside the message entirely and
    fabricating a match (task-9b review, "Important": `git commit -m
    "rename \\"push\\" button"` produced a match that isn't there in the
    real shell command, contradicting this function's own "only suppress,
    never fabricate" contract).
    """
    i, n = start, len(s)
    while i < n:
        c = s[i]
        if quote == '"' and c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == quote:
            return i
        i += 1
    return n


def _unescape_dquote(s):
    """Reverse the escaping a shell applies inside a double-quoted string
    (`\\"` -> `"`, `\\\\` -> `\\`, ...). Used only when recursing into a
    quoted command argument (`bash -c "..."`) so the string handed to the
    recursive blank_quoted call matches what the shell would actually run,
    not what's still typed with escape backslashes in front of it.
    """
    out = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\" and i + 1 < n:
            out.append(s[i + 1])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _is_exec_arg(command, quote_pos):
    """True if the quote opening at `quote_pos` is the argument to a
    program that will execute its contents as a shell command."""
    window = command[max(0, quote_pos - _EXEC_LOOKBACK):quote_pos]
    return bool(EXEC_ARG_RE.search(window))


def blank_quoted(command, _depth=0):
    """`command` with the CONTENTS of every '...'/"..." span replaced by
    spaces (quote characters themselves kept in place) -- EXCEPT a span
    that is itself a command about to be executed (the argument to
    `bash -c`/`sh -c`/`ssh host`/`eval`/...), which is scanned instead,
    recursively, so a publish command nested behind any number of these
    wrappers is still found.

    is_publish_command()'s whole point is to tell "this command publishes something"
    from free text sitting in an argument -- and the single most common
    free-text argument in a git workflow is a commit message. Without any
    blanking, `git commit -m "add push notification support"` would match:
    the word "push" sits right after "git" with nothing but ordinary
    characters in between, exactly what the publish patterns are built to
    tolerate (git's own global flags, docker's registry path, ...).
    Blanking quoted content by default means a publish-shaped word only
    counts when it is actually part of the command being invoked, not part
    of what a flag's value says -- this covers every alternative, not just
    git ("remember to npm publish next week" in a commit message is exactly
    as much a false positive as the push case).

    task-9b review, CRITICAL 1: the previous version blanked EVERY quoted
    span this same way, with no exception -- so `bash -c "git push origin
    main"`, `sh -c '...'`, and `ssh host "..."` all had their payload
    erased before is_publish_command() ever ran, a silent bypass of the whole rule.
    These three (plus `eval`) are the exception: the quote is not prose
    describing a command, it IS the command, so it is scanned (via
    recursion, so a nested `bash -c "ssh host 'git push ...'"` is still
    caught, and a message flag nested INSIDE a wrapper -- `bash -c "git
    commit -m 'mentions npm publish'"` -- still gets its own blanking
    applied at that inner level rather than being left raw just because it
    sits inside an outer wrapper).

    Recursion depth is capped (MAX_QUOTE_RECURSION) and the exec-context
    check only looks at a small fixed window before each quote (see
    _is_exec_arg) -- both defend against the CRITICAL-2 class of cost
    reappearing here via a specially crafted, deeply-nested input.

    Still not real shell parsing (single/double quote nesting rules are
    approximated, not exact), but an unterminated quote still blanks to the
    end of the string either way -- suppressing a potential match, never
    manufacturing one out of quoted text.
    """
    out = []
    i, n = 0, len(command)
    while i < n:
        ch = command[i]
        if ch in ("'", '"'):
            quote = ch
            content_start = i + 1
            close = _quote_span_end(command, content_start, quote)
            inner = command[content_start:close]
            terminated = close < n

            if _is_exec_arg(command, i) and _depth < MAX_QUOTE_RECURSION:
                recurse_src = _unescape_dquote(inner) if quote == '"' else inner
                scanned = blank_quoted(recurse_src, _depth + 1)
            else:
                scanned = " " * len(inner)

            out.append(quote)
            out.append(scanned)
            if terminated:
                out.append(quote)
                i = close + 1
            else:
                i = close
            continue
        out.append(ch)
        i += 1
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
        # to reach is_publish_command() directly and raise TypeError --
        # crashing the hook with a non-zero exit instead of failing open.
        cfi.allow()
    if len(command) > MAX_COMMAND_CHARS:
        # See MAX_COMMAND_CHARS -- bounds worst-case cost regardless of how
        # large an arbitrary `command` string gets.
        command = command[:MAX_COMMAND_CHARS]
    blanked = blank_quoted(command)
    if not is_publish_command(blanked):
        cfi.allow()

    # Applied to the same quote-blanked command as is_publish_command
    # above, for the identical reason: a commit message mentioning "git
    # push" in prose must not count. Getting this right matters in BOTH
    # directions below, not just one -- a false "yes" here skips the .env
    # check (env_files_on_disk), a false "no" skips the history check
    # (unpushed_diff).
    is_git_push_command = is_git_push(blanked)

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

    # A gitignored .env is never sent by `git push` -- that is what
    # gitignored means -- but every OTHER publishing path (vercel, netlify,
    # docker build, scp, rsync, ...) uploads the whole working directory,
    # ignored or not. Scoped to non-git-push specifically so this can never
    # block a `git push` over a secret that command genuinely cannot leak.
    if not is_git_push_command:
        for rel in env_files_on_disk(root):
            findings.append(f"{rel}: local .env would be uploaded by this command")

    # The other direction: `git push` sends the full diff of every commit
    # being pushed, not just what's present at HEAD -- a secret added and
    # then "fixed" in a later commit is still in that diff. Scoped to
    # git-push specifically: none of the other publishing paths transmit
    # git history at all (npm/vercel/docker/etc. ship built artifacts, and
    # `.git` is excluded by every one of their own default ignore rules).
    if is_git_push_command:
        history = unpushed_diff(root)
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(history):
                findings.append("git history (unpushed commits): " + label)
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
