# claude-for-idiots

**English** · [Português](README.pt-br.md)

> A [Claude Code](https://claude.com/claude-code) skill that keeps Claude **on
> the rails** — and explains things in plain language, so even a total beginner
> can build real software without getting lost.

---

## How to use

### 1. Install (once)

**Requirements:** Python 3 and [Claude Code](https://claude.com/claude-code).

**macOS / Linux**
```bash
git clone https://github.com/JulioBarbosaS/Claude-For-Idiots.git
cp -r Claude-For-Idiots ~/.claude/skills/claude-for-idiots
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/JulioBarbosaS/Claude-For-Idiots.git
Copy-Item -Recurse Claude-For-Idiots "$env:USERPROFILE\.claude\skills\claude-for-idiots"
```

Then restart Claude Code so it picks up the new skill.

### 2. Turn it on — explicitly

In a Claude Code session, run:

```
/claude-for-idiots
```

**It only runs when you ask for it — on purpose.** Not every project should be
wrapped in these guard-rails: a quick throwaway script, or an existing codebase
that already has its own conventions, are usually better left alone. So this
skill **never takes over by itself** — you switch it on, per project, when you
actually want it.

Once it's on, it asks a few quick questions — your language, your experience
level, whether to use technical terms, and what you want to build — and sets
everything up for that project.

> **Heads-up:**
> - The guided setup takes **~10 minutes** (measured on Opus 4.8) — it asks the
>   questions, picks the stack, installs the tooling and writes the guard-rails.
> - **Beginners:** run Claude Code in **auto mode** (auto-accept permissions)
>   during setup, so you're not interrupted by a permission prompt at every step.
> - **Not yet tested for deployment** — the skill covers local development;
>   deploy workflows are on the roadmap.

### 3. Update (when a new version lands)

```
/claude-for-idiots update
```

Updates the skill itself and — if the current project was configured by it —
brings the project's guard-rails up to date too, **keeping all your choices**.
It tells you what changed before touching anything.

---

## What is this? (in plain words)

You're building something with Claude Code, but:

- it keeps using words you don't understand (and don't feel like looking up), and
- you're not totally sure it's doing things "the right way".

This skill fixes both. When you turn it on, Claude:

- **talks to you the way *you* choose** — no jargon at all, jargon *with* simple
  explanations, or jargon as usual;
- **follows good engineering habits automatically** — tests, safe commits, a real
  folder structure, no leaked passwords — so your project doesn't turn into a mess.

You don't need to know what "migration", "CORS" or "architecture" mean. That's
the whole point. Beginners and experienced devs both use it — it just adapts.

## Why I built this

I was coding with Claude Code and ran into two things that bugged me:

1. It kept throwing around technical words I didn't understand — and honestly
   didn't want to stop and learn right then.
2. I wanted it to just follow the basics of good software — a real architecture,
   tests, careful commits — instead of improvising something different every time.

So I built this to keep Claude **on the rails**. And while I was at it, I made it
friendly enough that someone with **zero coding background** can use Claude
comfortably too.

## What can I build with it?

The skill knows how to pick an architecture for these project types:

| What you want to build | Stack it recommends |
|---|---|
| Website / web app | Next.js (React + TypeScript) |
| Simple static / content site | Astro or plain HTML + CSS + JS |
| REST API or backend service | FastAPI (Python) or NestJS (TypeScript) |
| Full-stack app (UI + API + DB) | Next.js + Postgres (via Prisma) |
| Mobile app (iOS + Android) | Flutter |
| CLI tool / automation script | Python (Typer) or Node (Commander) |
| Data analysis / ML prototype | Python (pandas / scikit-learn / notebooks) |
| Discord / Telegram bot | Python or Node |
| Desktop app | Tauri or Electron |

Advanced users can always choose their own stack — the catalog is just the default.

## Should you use it on your project?

Honest answer: **not always.** The guard-rails cost something — tests, checks
and commits on every feature — so they have to buy you more than they cost.

| Project | Use it? |
|---|---|
| A real app/site/API you'll keep working on (weeks, months) | ✅ Yes — the sweet spot |
| Your first serious project / learning by building something real | ✅ Yes — it was made for this |
| Anything with a database and/or a public repo | ✅ Yes — the migration and secret rules exist for exactly this |
| A quick throwaway script or one-afternoon experiment | ❌ No — plain Claude is faster; the overhead isn't worth it |
| An existing codebase with its own conventions / a team project | ❌ Not yet — the skill assumes a fresh project |

Rule of thumb: **if the project will still matter in two weeks, turn it on; if
it's disposable, don't.** That's also why it only runs when you invoke it
explicitly.

## What it improves

After setup, Claude follows these in **every** session of that project. The ones
marked **(enforced)** are guaranteed by hooks — Claude literally can't break them:

- **No hand-editing database migrations** *(enforced)* — uses the proper
  generator command instead.
- **New files stay inside the chosen architecture** *(enforced)* — nothing dumped
  at random.
- **Secrets never reach the internet** *(enforced)* — keys/passwords stay in a
  local `.env`; anything that publishes is scanned first.
- **Always writes tests** — and asks before running the slow full suite.
- **Commits after each feature** — so you never lose progress.
- **Sanity check after each feature** — lint, the feature's tests, and actually
  booting the app to see it work.
- **Sets up code-quality tools for your stack** (formatter + linter) — the code
  stays clean automatically.
- **Reuses before rebuilding** — checks the codebase (and `docs/`) for something
  that already does the job before writing it again.
- **Keeps a `docs/` folder for big decisions and hard-won lessons** — knowledge
  survives without bloating every session.
- **Knows when to stop guessing** — after two failed fixes it stops, re-reads
  the error, checks versions and researches the web before trying again.
- **For web apps, it can check the browser itself** — loads the page, reads the
  console for hidden errors, takes screenshots (with Playwright set up — it
  offers to configure it).

And it adapts to **you**:

- **Experience level** — beginner / intermediate / advanced: decides how much it
  explains and whether it picks the tech stack for you.
- **Technical terms** — `none` (plain language only) · `explain` (uses the term
  plus a simple explanation that gets deeper as you learn) · `raw` (terms as usual).

**How it sticks:** the setup writes a `CLAUDE.md` (auto-loaded every session) plus
the hooks, so the rules keep working even in long sessions — not just while the
skill is open.

## Repository layout

```
SKILL.md                     # the skill's brain (onboarding + behavior)
references/                  # editable data — extend the skill here
  rules.md                   #   the 9 rules (source of truth)
  stack-catalog.md           #   objective → stack
  architecture-catalog.md    #   stack → idiomatic architecture
  onboarding-flow.md         #   the questions
  glossary-format.md         #   how the "explain" glossary works
  quality-tools.md           #   formatter/linter/type-checker per stack
  browser-verification.md    #   web smoke tests via a real browser
  update-flow.md             #   how /claude-for-idiots update works
assets/                      # what gets written into your project
  CLAUDE.template.md
  config.example.json
  settings.template.json
  docs-INDEX.template.md
  ADR.template.md
hooks/                       # the technical guard-rails (Python)
  block_migration_edits.py   #   migrations
  enforce_architecture.py    #   architecture
  scan_secrets_before_push.py#   secrets
tests/                       # hook test suite (runs in CI on every PR)
```

## Contributing

Forks, issues, and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Adding a new stack or architecture is just editing one data file, not rewriting
the skill.

## License

[MIT](LICENSE) © 2026 Julio Barbosa — permissive and fork-friendly.

> 🇧🇷 [Versão em português](README.pt-br.md).
