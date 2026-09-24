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
}


def is_policed(rel, arch):
    """True when this file counts as code for Rule 5."""
    _, ext = os.path.splitext(rel)
    if not ext:
        # No extension: LICENSE, Dockerfile, Makefile. Too noisy to police.
        return False
    override = cfi.str_list(arch.get("ignored_extensions"))
    ignored = set(override) if override else IGNORED_EXT
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

    if cfi.matches_any(rel, allowed):
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
    main()
