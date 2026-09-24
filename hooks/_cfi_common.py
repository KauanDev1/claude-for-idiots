#!/usr/bin/env python3
"""Shared helpers for the claude-for-idiots PreToolUse hooks.

Every hook imports from here so path handling, glob semantics and the decision
protocol have exactly one implementation. Standard library only.
"""
import json
import os
import posixpath
import re
import sys
from functools import lru_cache

CONFIG_REL = os.path.join(".claude-for-idiots", "config.json")

# Both are attacker-influenced: the event comes over stdin from whatever
# invoked the hook, and config.json can come from a repo the user cloned.
# MAX_JSON_CHARS bounds parse time/memory on a pathologically large payload;
# MAX_JSON_NESTING bounds recursion depth so CPython's recursive-descent
# decoder can never be pushed toward (or past) a RecursionError/C-stack
# overflow in the first place. Both are far beyond any real PreToolUse event.
MAX_JSON_CHARS = 2_000_000
MAX_JSON_NESTING = 200


def _max_nesting_depth(raw):
    """Greatest `[`/`{` nesting depth in `raw`, ignoring string content.

    Iterative, not recursive, so scanning itself can never overflow the
    stack. Used to reject dangerously nested input before it ever reaches
    `json.loads`, since the stdlib decoder recurses once per nesting level.
    """
    depth = 0
    max_depth = 0
    in_string = False
    escape = False
    for ch in raw:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch in "]}":
            depth -= 1
    return max_depth


def _safe_json_loads(raw):
    """Parse JSON defensively. None on ANY problem -- fail open, always.

    Bounds size and nesting before parsing, then wraps the parse itself in a
    broad `except Exception`. That breadth is deliberate here, not a stray
    catch-all: this is the one boundary where attacker-controlled bytes
    (stdin, or config.json from a cloned repo) turn into Python objects, and
    the project's invariant is that no hook may ever exit non-zero, on any
    input. RecursionError (raised by the decoder on deep-but-not-rejected
    nesting) is an Exception subclass, so it is covered without special-casing.
    """
    if not raw or len(raw) > MAX_JSON_CHARS:
        return None
    if _max_nesting_depth(raw) > MAX_JSON_NESTING:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def read_event():
    """Parse the PreToolUse event from stdin. None means: fail open."""
    try:
        raw = sys.stdin.read(MAX_JSON_CHARS + 1)
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    event = _safe_json_loads(raw)
    return event if isinstance(event, dict) else None


def load_config(cwd):
    """Read the project config. None means: fail open."""
    try:
        with open(os.path.join(cwd, CONFIG_REL), encoding="utf-8") as handle:
            raw = handle.read(MAX_JSON_CHARS + 1)
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    config = _safe_json_loads(raw)
    return config if isinstance(config, dict) else None


def section(config, name):
    """config[name] when it is a mapping, {} otherwise. Never raises."""
    value = (config or {}).get(name)
    return value if isinstance(value, dict) else {}


def str_list(value):
    """Coerce a config field into a list of strings, tolerating a bare string."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str) and item]
    return []


def _find_class_end(pattern, start):
    """Index of the `]` that closes the `[...]` class opened at `start`.

    None when there is no matching `]`, in which case the caller treats the
    `[` as a literal character instead of raising.
    """
    length = len(pattern)
    j = start + 1
    if j < length and pattern[j] == "!":
        j += 1
    # A `]` right after `[` or `[!` is a literal member of the class, not
    # its closing bracket (classic glob/POSIX behavior).
    if j < length and pattern[j] == "]":
        j += 1
    while j < length and pattern[j] != "]":
        j += 1
    return j if j < length else None


def _translate_class(glob_class):
    """`[...]` / `[!...]` glob class -> the equivalent regex `[...]` class."""
    body = glob_class[1:-1]
    negate = body.startswith("!")
    if negate:
        body = body[1:]
    body = body.replace("\\", "\\\\")
    if not negate and body.startswith("^"):
        # A literal leading `^` would otherwise flip the regex class to
        # negation, which glob `[...]` (without `!`) never means.
        body = "\\" + body
    return "[" + ("^" if negate else "") + body + "]"


# Round 1 of this fix collapsed a run of the SAME wildcard token repeated
# ("**/" * N). Round 2's own review then found that concatenating any two
# *different* unrestricted-quantifier regex fragments ((?:[^/]+/)*, .*,
# [^/]*) adjacently is exactly as prone to catastrophic backtracking as
# repeating one, and a hand-derived per-run algebraic collapse (checking only
# "is this run one contiguous span of wildcard characters") still missed it:
# a pattern like `("**/" + "*") * 40` re-tokenizes (adjacent "*" characters
# always merge greedily) into several separate `.*`/`(?:[^/]+/)*` fragments
# chained through single-character literal separators, and THAT chain is
# just as exponential -- a run boundary at a literal does not actually bound
# the backtracking, because `.*` freely crosses that literal too.
#
# Rather than keep hunting for more regex shapes that alias to the same
# blowup, matching is done with an explicit DP over (token index, path
# index) instead of building one backtracking regex for the whole pattern.
# This is the "reescrever o matcher para consumir segmento a segmento sem
# regex" option: `re` is still used, but only to test ONE character against
# a `[...]` class -- a fixed-width, non-quantified check that can never
# backtrack -- never to chain multiple unbounded quantifiers together. The
# DP is O(len(pattern) * len(path)) by construction, for ANY pattern shape,
# with no backtracking search space to blow up in the first place.
#
# Both dimensions are capped as defense in depth (a config.json value or a
# tool_input path could in principle still be very long): a pattern or path
# longer than these is treated as "does not match" rather than paying
# unbounded DP cost -- fail open in the same direction as the rest of this
# module (an absurd config value stops that one rule from applying instead
# of blocking the hook). Both ceilings are far beyond any real glob pattern
# or project-relative path.
MAX_GLOB_PATTERN_CHARS = 1024
MAX_GLOB_PATH_CHARS = 4096


class _NeverMatches:
    """compile_glob's result for a pattern over MAX_GLOB_PATTERN_CHARS."""

    __slots__ = ()

    def match(self, path):
        return False


_NEVER_MATCHES = _NeverMatches()


def _parse_glob_tokens(pattern):
    """Tokenize a git-style glob into `(kind, payload)` pairs.

    `**/` matches zero or more leading directories, `**` crosses separators,
    `*` and `?` do not. This is what `fnmatch` gets wrong: it maps every `*`
    to `.*`, so `src/**` never matches `next.config.ts` while `**/x/**` fails
    to match a root-level `x/`. A `[...]` character class is also supported,
    including glob-style negation `[!...]` (translated to a regex `[^...]`
    class, compiled once here and matched against exactly one character at a
    time); an unterminated `[` is treated as a literal so a stray bracket
    never raises `re.error`.
    """
    pattern = pattern.strip().replace("\\", "/")
    tokens = []
    index, length = 0, len(pattern)
    while index < length:
        if pattern.startswith("**/", index):
            tokens.append(("starstar_slash", None))
            index += 3
        elif pattern.startswith("**", index):
            tokens.append(("starstar", None))
            index += 2
        elif pattern[index] == "*":
            tokens.append(("star", None))
            index += 1
        elif pattern[index] == "?":
            tokens.append(("qmark", None))
            index += 1
        elif pattern[index] == "[":
            end = _find_class_end(pattern, index)
            if end is None:
                tokens.append(("lit", pattern[index]))
                index += 1
            else:
                tokens.append(("class", re.compile(_translate_class(pattern[index:end + 1]))))
                index = end + 1
        else:
            tokens.append(("lit", pattern[index]))
            index += 1
    return tokens


def _dp_match(tokens, path):
    """Does the full `tokens` sequence match the full `path`?

    Standard "wildcard matching" dynamic programming, generalized with a
    `starstar_slash` token alongside the usual single-char/`*`/`**` ones.
    `dp` holds, for the tokens consumed so far, every path index reachable
    at that point; each token folds `dp` into a `new_dp` in O(len(path))
    time, so the whole match is O(len(tokens) * len(path)) -- no
    backtracking, so no input can make it slower than that bound.
    """
    n = len(path)
    dp = [False] * (n + 1)
    dp[0] = True
    next_slash = None  # computed lazily, at most once, only if needed

    for kind, payload in tokens:
        if True not in dp:
            return False  # nothing reachable -- no later token can help
        new_dp = [False] * (n + 1)
        if kind == "lit":
            for j in range(1, n + 1):
                new_dp[j] = dp[j - 1] and path[j - 1] == payload
        elif kind == "qmark":
            for j in range(1, n + 1):
                new_dp[j] = dp[j - 1] and path[j - 1] != "/"
        elif kind == "class":
            for j in range(1, n + 1):
                new_dp[j] = dp[j - 1] and payload.match(path[j - 1]) is not None
        elif kind == "star":
            # Zero-or-more non-slash characters: reachable either by taking
            # zero reps from wherever `dp` already reached, or by extending
            # what THIS token just reached by one more non-slash character.
            new_dp[0] = dp[0]
            for j in range(1, n + 1):
                new_dp[j] = dp[j] or (new_dp[j - 1] and path[j - 1] != "/")
        elif kind == "starstar":
            new_dp[0] = dp[0]
            for j in range(1, n + 1):
                new_dp[j] = dp[j] or new_dp[j - 1]
        else:  # starstar_slash: zero-or-more complete "[^/]+/" segments
            if next_slash is None:
                next_slash = [n] * (n + 1)
                for p in range(n - 1, -1, -1):
                    next_slash[p] = p if path[p] == "/" else next_slash[p + 1]
            new_dp = dp[:]
            # A segment starting at `start` is deterministic -- glob "1 or
            # more non-slash chars then /" can only mean "up to the next
            # literal /", there is no ambiguity in where it ends. Walking
            # `start` in increasing order and hopping forward on each hit
            # therefore reaches every valid rep count in one O(n) pass: any
            # position newly marked True is still ahead of `start` (a
            # segment is never empty), so it gets its own turn later in the
            # same loop.
            for start in range(n):
                if new_dp[start] and path[start] != "/" and next_slash[start] < n:
                    new_dp[next_slash[start] + 1] = True
        dp = new_dp
    return dp[n]


class _GlobPattern:
    """compile_glob's result for a pattern within the length cap.

    `.match(path)` mirrors the truthy/falsy contract `matches_any` needs
    from `re.Pattern.match` -- that is the only thing this module (or any
    consumer of `compile_glob`) relies on; nothing calls `.pattern`,
    `.fullmatch()`, or any other `re.Pattern`-specific attribute.
    """

    __slots__ = ("_tokens",)

    def __init__(self, tokens):
        self._tokens = tokens

    def match(self, path):
        if len(path) > MAX_GLOB_PATH_CHARS:
            return False
        return _dp_match(self._tokens, path)


@lru_cache(maxsize=512)
def compile_glob(pattern):
    """Compile a git-style glob pattern for repeated matching.

    Returns an object with a `.match(path) -> bool`-ish method (not a real
    `re.Pattern` -- see `_GlobPattern` and the module-level comment above
    `MAX_GLOB_PATTERN_CHARS` for why). Deliberately not `@lru_cache`d on the
    (pattern, path) pair: patterns repeat across hook invocations (there are
    only ever a handful per project), paths don't, so caching the parse
    here and reusing it across `.match()` calls is what actually pays off.
    """
    if len(pattern) > MAX_GLOB_PATTERN_CHARS:
        return _NEVER_MATCHES
    return _GlobPattern(_parse_glob_tokens(pattern))


def matches_any(rel_path, patterns):
    if not rel_path:
        return False
    return any(compile_glob(p).match(rel_path) for p in str_list(patterns))


def relativize(file_path, cwd):
    """Project-relative POSIX path, or None when outside the project."""
    if not file_path or not isinstance(file_path, str):
        return None
    raw = file_path.replace("\\", "/")
    if os.path.isabs(file_path) or (len(file_path) > 1 and file_path[1] == ":"):
        try:
            raw = os.path.relpath(file_path, cwd).replace(os.sep, "/")
        except ValueError:
            return None
    rel = posixpath.normpath(raw)
    if rel in (".", "..", "") or rel.startswith("../"):
        return None
    return rel


def target_path(tool_input):
    """The file a write-shaped tool aims at, whatever field name it uses."""
    for key in ("file_path", "notebook_path"):
        value = (tool_input or {}).get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def decide(decision, reason):
    """Emit a PreToolUse decision and exit 0."""
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))
    sys.exit(0)


def allow():
    """Silent allow — also the fail-open path."""
    sys.exit(0)
