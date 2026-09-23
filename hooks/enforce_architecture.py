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

CODE_EXT = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".kt",
    ".rb", ".php", ".dart", ".vue", ".svelte", ".cs", ".swift", ".scala",
}


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
    mode = arch.get("enforce", "off")
    allowed = cfi.str_list(arch.get("allowed_paths"))
    if mode == "off" or not allowed:
        cfi.allow()

    rel = cfi.relativize(file_path, cwd)
    if not rel:
        cfi.allow()

    # Only police new code files. Let docs/config and edits-to-existing through.
    _, ext = os.path.splitext(rel)
    if ext.lower() not in CODE_EXT:
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
