# Hooks — the technical guardrails

These three Python scripts add a technical check to rules 1, 5 and 6 on the paths Claude Code most often takes. They run as Claude Code `PreToolUse` hooks: before a tool call runs,
the hook inspects it and can block it.

| Hook | Rule | Matcher | Blocks when… |
|---|---|---|---|
| `block_migration_edits.py` | 1 | `Edit\|Write\|MultiEdit` | the target file matches a protected migration path |
| `enforce_architecture.py` | 5 | `Write` | a **new code file** lands outside `architecture.allowed_paths` |
| `scan_secrets_before_push.py` | 6 | `Bash` | a publishing command (push, `gh repo create`, …) and a tracked file looks like it holds a secret |

## How they're installed (by the skill)

During onboarding the skill:
1. copies these scripts into `<project>/.claude/hooks/`,
2. merges `assets/settings.template.json` into `<project>/.claude/settings.json`,
3. writes `<project>/.claude-for-idiots/config.json`, which the hooks read.

## Contract

- **Input:** the hook event JSON arrives on **stdin** (fields include `cwd`,
  `tool_name`, `tool_input`).
- **Allow:** exit `0` with no output. This is also the **fail-open** default when
  there is no config or the rule doesn't apply.
- **Block:** print
  ```json
  {"hookSpecificOutput":{"hookEventName":"PreToolUse",
    "permissionDecision":"deny","permissionDecisionReason":"…"}}
  ```
  Use `"ask"` instead of `"deny"` for a soft nudge (architecture hook honors
  `architecture.enforce`: `deny` | `ask` | `off`).

## Requirements

- `python3` on PATH (standard library only — no pip installs).

## Extending

`scan_secrets_before_push.py` has a `SECRET_PATTERNS` list — add regexes there.
The architecture and migration hooks are fully driven by `config.json`, so most
tuning is done in config, not code.

## The secrets scanner's escape hatch

A false positive with no way out is how a security hook gets uninstalled
instead of obeyed — so `scan_secrets_before_push.py` reads an optional
`secrets` section of `config.json`:

```json
"secrets": {
  "allowlist_paths": ["tests/fixtures/**"],
  "allow_patterns": ["AKIAIOSFODNN7EXAMPLE"]
}
```

- `allowlist_paths` exempts a whole tracked file by path (same glob syntax
  as `migrations.protected_paths` / `architecture.allowed_paths`).
- `allow_patterns` exempts any line matching one of these regexes, wherever
  it appears (a tracked file or the unpushed-history diff).
- `# cfi:allow-secret` on a line exempts just that line, no config needed —
  put it next to a fixture or a documented example.

Both mechanisms are deliberately narrow: they exempt a specific path or a
specific line, never a whole command or repo, so they can't quietly cancel
out Rule 6. **Never use them for a live credential** — only for test
fixtures and documented examples that were never a real secret to begin
with.
