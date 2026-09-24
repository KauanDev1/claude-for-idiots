#!/usr/bin/env python3
"""Rule 5 — new code stays inside the chosen architecture.

PreToolUse hook (matcher: Write). Checks NEW code files against the project's
allowed_paths from .claude-for-idiots/config.json. The `architecture.enforce`
mode can be "deny", "ask" or "off". Only polices code-file creation; ignores
docs/config and files that already exist (those are edits, not placements).
Fails open when not configured.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _cfi_common as cfi

# Inverted on purpose: policing an allow-list of extensions silently exempted
# .mjs/.cjs/.astro/.sql/.sh, so Rule 5 did not apply to whole stacks the
# catalog recommends. Anything that is not obviously prose, data or a binary
# is treated as code.
IGNORED_EXT = {
    ".md", ".markdown", ".rst", ".txt", ".adoc",
    ".json", ".jsonc", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".lock", ".csv", ".tsv", ".xml", ".env", ".example", ".sample",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pdf", ".zip", ".gz", ".tar", ".mp3", ".mp4", ".webm",
    ".parquet", ".pkl",
    ".bz2", ".7z", ".rar", ".xz",
}


def _normalize_ext(raw):
    """Best-effort normalize one config-supplied extension token: trim
    whitespace, lowercase, and add the leading dot os.path.splitext always
    returns. Without this, an override entry typed as "TS" or "ts" (missing
    the dot, or in the wrong case) matched nothing at all -- not even the
    extension the author meant to exempt -- and since the override REPLACES
    the whole default list, a one-character typo silently turned Rule 5 into
    "police every file in the project." Returns None for a token that is
    empty after trimming (e.g. a whitespace-only entry)."""
    token = raw.strip().lower()
    if not token:
        return None
    if not token.startswith("."):
        token = "." + token
    return token


def _is_dotenv(rel):
    """.env and its common siblings (.env.local, .env.production, ...) are
    never code, regardless of their trailing "extension". os.path.splitext
    treats a file's leading dot as part of the name, not as a separator, so
    ".env.local" reports its extension as ".local" -- which is not in
    IGNORED_EXT, and used to get denied. This check is unconditional, the
    same way the no-extension check below is: a project's
    ignored_extensions override should never be able to accidentally turn a
    secrets file into a policed "code" file."""
    name = os.path.basename(rel)
    return name == ".env" or name.startswith(".env.")


def is_policed(rel, arch):
    """True when this file counts as code for Rule 5."""
    if _is_dotenv(rel):
        return False
    _, ext = os.path.splitext(rel)
    if not ext:
        # No extension: LICENSE, Dockerfile, Makefile. Too noisy to police.
        return False
    override = cfi.str_list(arch.get("ignored_extensions"))
    if override:
        normalized = {n for n in (_normalize_ext(o) for o in override) if n}
        # Every entry normalized away to nothing (e.g. all whitespace) is a
        # malformed config, not a deliberate "ignore nothing" instruction --
        # fail open to the default list rather than policing everything.
        ignored = normalized or IGNORED_EXT
    else:
        ignored = IGNORED_EXT
    return ext.lower() not in ignored


def main():
    event = cfi.read_event()
    if not event:
        cfi.allow()

    file_path = cfi.target_path(event.get("tool_input"))
    cwd = event.get("cwd") or os.getcwd()
    config = cfi.load_config(cwd)
    if not config:
        cfi.allow()

    arch = cfi.section(config, "architecture")
    # "off" as the default meant a config written without this key silently
    # disabled the rule the skill advertises. "ask" is the safe default: it
    # surfaces the decision instead of swallowing it. Any OTHER value --
    # explicit "off", a typo, or a config field of the wrong type entirely --
    # still fails open here, so a malformed or intentionally-disabled config
    # can never crash the hook or escalate into an accidental deny.
    mode = arch.get("enforce", "ask")
    if mode not in ("deny", "ask"):
        cfi.allow()
    allowed = cfi.str_list(arch.get("allowed_paths"))
    if not allowed:
        cfi.allow()

    rel = cfi.relativize(file_path, cwd)
    if not rel:
        cfi.allow()

    # Only police new code files. Let docs/config and edits-to-existing through.
    if not is_policed(rel, arch):
        cfi.allow()

    # An existing file is an edit, not a placement. Resolve against the
    # EVENT's cwd, never the process cwd — the hook may be invoked anywhere.
    if os.path.exists(os.path.join(cwd, rel)):
        cfi.allow()

    # on_incomplete=True: this hook ALLOWS on a match, so an allowed_paths
    # list too expensive to fully evaluate (see matches_any's docstring)
    # must fail open the same direction as everything else here -- allow,
    # not deny/ask. Without this, an absurd config would turn "the safety
    # net degrades" into "legitimate writes start getting denied".
    if cfi.matches_any(rel, allowed, on_incomplete=True):
        cfi.allow()

    layers = arch.get("layers") or {}
    layer_hint = "\n".join(f"    {k}: {v}" for k, v in layers.items()) or "    (see CLAUDE.md)"
    reason = (
        f"claude-for-idiots Rule 5: '{rel}' is outside the chosen architecture "
        f"({arch.get('name', 'project architecture')}).\n"
        f"Allowed locations: {', '.join(allowed)}\n"
        f"Layers:\n{layer_hint}\n"
        "Place the file in the correct layer, or update `architecture` in "
        ".claude-for-idiots/config.json + CLAUDE.md if this is a deliberate change."
    )
    cfi.decide("deny" if mode == "deny" else "ask", reason)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Last-resort net -- see block_migration_edits.py for the rationale
        # (this codebase has already found three distinct fail-open gaps of
        # this same shape across the three hooks). Never catches the
        # SystemExit that cfi.allow()/cfi.decide() raise.
        sys.exit(0)
