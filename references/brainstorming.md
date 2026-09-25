# Aligning before building — the Rule 10 script

This is the full script behind Rule 10 (`references/rules.md`). The rule
itself stays short there, as a pointer; this file is what Claude actually
follows once a request looks like it fires it. The generated `CLAUDE.md`
carries only a short version of the rule — this doc is where the detail lives
(Rule 8: pointers in the always-loaded file, depth on demand).

## 1. Classify: does the project already do this?

One question decides it: **does the project already do what's being asked?**

- Already does it, and it's broken → **bug fix**. Fast path, Rule 10 doesn't apply.
- Already does it, wants it to look or behave slightly different → **tweak**. Fast path.
- Doesn't do it yet → **feature**. Rule 10 applies: align before writing code.

State the classification in one line before acting, so the user can push back
— *"isso me parece feature nova, vou alinhar antes de codar"* (or the
equivalent in the project's configured language). If the user disagrees,
follow their correction; don't argue the taxonomy.

```
fires:      "quero login com Google" · "adiciona carrinho" · "exportar em PDF"
does not:   "arruma esse erro do console" · "muda a cor do botão" · "renomeia calcTotal"
```

The three "fires" examples each add behavior nothing in the project currently
has. The three "does not" examples each touch something that already exists —
an existing error, an existing button, an existing function name.

## 2. Search before asking (Rule 7, moved earlier)

Rule 7 says search before you build. For a feature that fires Rule 10, that
search has to happen **before the options are drafted**, not after the user
picks one — otherwise the options are guesses instead of grounded choices.

Before drafting anything:
1. **Search the codebase** for something that already does this, or nearly does.
2. **Skim `docs/INDEX.md`** for a relevant decision or investigation already on record.
3. **Check `architecture.allowed_paths`** (in `.claude-for-idiots/config.json`)
   for where this feature would have to live.

Whatever this search turns up feeds the options in the next step — "reuse X"
becomes one of the choices, not a footnote raised after the fact.

## 3. Ask as a choice, never an open question

Present the decisions that actually change the outcome — **2 to 4 of them**,
not every possible detail. Each one is a set of options, each option carrying
one line naming its consequence. The user may not know what OAuth is, but they
can choose between "the two ways to log in coexist" and "Google replaces the
current login" once the sentence says what that means for them.

Never ask an open-ended question ("how do you want this to work?") — always
ask "which of these" against options already drafted. Apply the term mode
(below) so each option reads at the user's level.

## 4. Respect the term mode

Before writing the options text:

- **`term_mode: explain`** → read `.claude-for-idiots/glossary.json` first
  (`references/glossary-format.md`). Don't re-explain a term already in it —
  use it bare, or go one level deeper than last time. Register every new term
  the options text introduces.
- **`term_mode: none` or `raw`** → write the options directly, no glossary
  read or write. `none` still paraphrases jargon per its own rule; `raw` uses
  terms as-is.

## 5. Record the answer, then build

Once the user picks (or answers the options directly):

1. Write `.claude-for-idiots/current-feature.json` with the decisions and,
   when known, where the feature will live.
2. **Only then** start implementing.
3. For a feature substantial enough to matter later, also write
   `docs/features/YYYY-MM-DD-<slug>.md` and add its one-line pointer to
   `docs/INDEX.md` (Rule 8) — this is what keeps "why Google login coexists
   with email/password" discoverable instead of lost in chat history.

## 6. The escape hatch

If the user says "just go" / "skip the questions" / the equivalent in the
project's language, don't insist. Write the record anyway, with
`skipped: true`, and proceed. A skip is a valid, respected alignment — not a
bypass to route around.
