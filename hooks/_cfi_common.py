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


@lru_cache(maxsize=512)
def compile_glob(pattern):
    """Translate a git-style glob into an anchored regex.

    `**/` matches zero or more leading directories, `**` crosses separators,
    `*` and `?` do not. This is what `fnmatch` gets wrong: it maps every `*`
    to `.*`, so `src/**` never matches `next.config.ts` while `**/x/**` fails
    to match a root-level `x/`. A `[...]` character class is also supported,
    including glob-style negation `[!...]` (translated to regex `[^...]`);
    an unterminated `[` is treated as a literal so a stray bracket never
    raises `re.error`.

    A run of consecutive identical wildcard tokens (`**/`, bare `**`, or `*`)
    collapses to a single emitted fragment instead of one fragment per
    token. Concatenating N copies of `(?:[^/]+/)*` (one per `**/`) is exactly
    equivalent to a single copy -- X* concatenated with itself is still X* as
    a language -- but the repeated nested-quantifier groups make Python's
    backtracking engine explore exponentially many ways to split a
    non-matching path between them. A config.json from a cloned repo is
    attacker-controlled, so a pattern like `"**/" * 40` must stay cheap.
    """
    pattern = pattern.strip().replace("\\", "/")
    out, index, length = [], 0, len(pattern)
    while index < length:
        if pattern.startswith("**/", index):
            out.append(r"(?:[^/]+/)*")
            index += 3
            while pattern.startswith("**/", index):
                index += 3
        elif pattern.startswith("**", index):
            out.append(r".*")
            index += 2
            while pattern.startswith("**", index):
                index += 2
        elif pattern[index] == "*":
            out.append(r"[^/]*")
            index += 1
            while index < length and pattern[index] == "*":
                index += 1
        elif pattern[index] == "?":
            out.append(r"[^/]")
            index += 1
        elif pattern[index] == "[":
            end = _find_class_end(pattern, index)
            if end is None:
                out.append(re.escape(pattern[index]))
                index += 1
            else:
                out.append(_translate_class(pattern[index:end + 1]))
                index = end + 1
        else:
            out.append(re.escape(pattern[index]))
            index += 1
    return re.compile("^" + "".join(out) + "$")


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
