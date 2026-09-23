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
