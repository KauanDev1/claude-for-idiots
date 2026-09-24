# Architecture catalog — stack → idiomatic architecture

Data file. For each stack, this gives the **idiomatic** layout, the
responsibility of each layer, and a suggested `allowed_paths` list for the
Rule-5 hook. **Edit freely** to refine or add stacks.

The `allowed_paths` below are a **starting point verified against
`tests/fixtures/`** (see `tests/test_real_projects.py`), not a prescription.
During setup, check them against the real project and add whatever else
exists — a scaffold tool's defaults change, and a stack has more than one
legitimate layout (e.g. Next.js with vs. without `--src-dir`).

Golden rules:
- Architecture must be **idiomatic to the stack** — never force MVVM/Clean/etc.
  onto a stack where it fights the framework.
- **Scale depth to size.** Tiny project → flat structure. Don't add layers a
  small project doesn't need; over-engineering is also a mess.
- Once chosen, copy the layout + `allowed_paths` into `config.json` and `CLAUDE.md`.

---

## FastAPI (backend API)

Layered: `routes → services → repositories → models`.

```
app/
  api/routes/        # HTTP endpoints, request/response only
  services/          # business logic
  repositories/      # DB access
  models/            # ORM models / schemas
  core/              # config, settings
tests/
  unit/
  integration/
```
`allowed_paths`: `["app/**", "tests/**", "alembic/**", "scripts/**", "*.py"]`
`enforce`: `deny` (layout is stable)
Migrations tool: Alembic (`alembic/versions/**` protected).
The `*.py` entry covers root-level files every FastAPI project has from day
one: `main.py`, `conftest.py`, task runners like `noxfile.py`. `alembic/**`
and `scripts/**` cover the migration tool and one-off maintenance scripts.

## NestJS (backend API, TypeScript)

Module-per-feature (framework-native): `module → controller → service → repository`.

```
src/
  <feature>/
    <feature>.controller.ts
    <feature>.service.ts
    <feature>.module.ts
  common/
test/
```
`allowed_paths`: `["src/**", "test/**", "*.config.*", "*.ts"]`
`enforce`: `deny` (layout is stable)
`*.config.*` covers root tooling config (`jest.config.js`,
`eslint.config.mjs`); `*.ts` covers other root-level TypeScript such as a
TypeORM `data-source.ts`.

## Next.js (web app / full-stack, React)

Feature-folders + components. **Not MVVM** — React is component + hooks.

`create-next-app` **without** `--src-dir` is the default, and puts the App
Router at `app/` in the project root, not under `src/`. Accept both
layouts — don't force `--src-dir` on a project that didn't opt into it.

```
app/                 # routes (App Router) -- or src/app/ with --src-dir
  api/<route>/route.ts
components/           # reusable UI
lib/                  # helpers, clients
e2e/                  # Playwright/Cypress end-to-end tests
prisma/               # if using Prisma (protect prisma/migrations/**)
```
`allowed_paths`: `["app/**", "src/**", "components/**", "lib/**", "e2e/**",
"tests/**", "prisma/**", "*.config.*", "middleware.ts", "instrumentation.ts",
"*.d.ts"]`
`enforce`: `ask` (root-level configs vary)
If using Prisma: protect `prisma/migrations/**`.

## Flutter (mobile)

Feature-first + a state-management layer. **Here MVVM / BLoC / Riverpod fits.**

```
lib/
  features/<name>/
    presentation/    # widgets (the "View")
    application/     # state / view-models / blocs
    domain/          # entities, use-cases
    data/            # repositories, data sources
  core/
test/
```
`allowed_paths`: `["lib/**", "test/**", "integration_test/**",
"test_driver/**", "tool/**"]`
`enforce`: `deny` (feature-first layout is stable)
`integration_test/` is Flutter's own official integration-test directory
(what `flutter test integration_test` runs) and `test_driver/` is its
legacy driver counterpart — blocking either would put this rule in direct
conflict with Rule 2, which tells the agent to write integration tests
there. `tool/` is the conventional home for one-off build/codegen scripts.

## Python CLI / automation (Typer)

Keep it flat. No layers.

```
src/<pkg>/
  __init__.py
  cli.py             # entrypoint / commands
  <module>.py        # one module per concern
tests/
```
`allowed_paths`: `["src/**", "tests/**", "*.py"]`
`enforce`: `ask` (flat and small — a soft nudge is enough)
`*.py` covers root-level automation scripts (`noxfile.py`, `setup.py`) that
a flat project commonly keeps outside `src/`.

## Data / ML prototype (Python)

Pipeline-style, not app-style.

```
src/
  data/              # loading / cleaning
  features/          # feature engineering
  models/            # training / eval
notebooks/
tests/
```
`allowed_paths`: `["src/**", "tests/**", "notebooks/**", "*.py"]`
`enforce`: `ask` (pipeline stage boundaries are still explorative)
`*.py` covers root-level files common in this template (e.g. `setup.py`,
as in the classic cookiecutter-data-science layout).

## Astro (web app / content site)

Islands architecture: static-first, components hydrate individually.

```
src/
  pages/             # file-based routing (.astro, .md, .mdx)
  components/        # .astro / framework components (React, Vue, ...)
  layouts/
tests/
```
`allowed_paths`: `["src/**", "tests/**", "*.config.*"]`
`enforce`: `ask` (small sites vary a lot in root tooling)

---

## Mapping to the Rule-5 hook

The hook reads `architecture.allowed_paths`, `architecture.layers`, and
`architecture.enforce` (`deny` | `ask` | `off`) from `config.json`. Use `ask`
when you want a soft nudge and `deny` when the layout must be strict.
