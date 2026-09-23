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


def read_event():
    """Parse the PreToolUse event from stdin. None means: fail open."""
    try:
        event = json.load(sys.stdin)
    except (ValueError, UnicodeDecodeError):
        return None
    return event if isinstance(event, dict) else None


def load_config(cwd):
    """Read the project config. None means: fail open."""
    try:
        with open(os.path.join(cwd, CONFIG_REL), encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, ValueError, UnicodeDecodeError):
        return None
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
    """
    pattern = pattern.strip().replace("\\", "/")
    out, index, length = [], 0, len(pattern)
    while index < length:
        if pattern.startswith("**/", index):
            out.append(r"(?:[^/]+/)*")
            index += 3
        elif pattern.startswith("**", index):
            out.append(r".*")
            index += 2
        elif pattern[index] == "*":
            out.append(r"[^/]*")
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
    if rel in (".", "") or rel.startswith("../"):
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
