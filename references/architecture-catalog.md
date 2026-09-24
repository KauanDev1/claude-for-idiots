# Architecture catalog — stack → idiomatic architecture

Data file. For each stack, this gives the **idiomatic** layout, the
responsibility of each layer, and a suggested `allowed_paths` list for the
Rule-5 hook. **Edit freely** to refine or add stacks.

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
`allowed_paths`: `["app/**", "tests/**"]`
`enforce`: `deny` (layout is stable)
Migrations tool: Alembic (`alembic/versions/**` protected).

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
`allowed_paths`: `["src/**", "test/**"]`
`enforce`: `deny` (layout is stable)

## Next.js (web app / full-stack, React)

Feature-folders + components. **Not MVVM** — React is component + hooks.

```
src/
  app/               # routes (App Router)
  components/        # reusable UI
  features/<name>/   # feature-scoped UI + logic
  lib/               # helpers, clients
  server/            # server actions / API logic
tests/
```
`allowed_paths`: `["src/**", "tests/**"]`
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
`allowed_paths`: `["lib/**", "test/**"]`
`enforce`: `deny` (feature-first layout is stable)

## Python CLI / automation (Typer)

Keep it flat. No layers.

```
src/<pkg>/
  __init__.py
  cli.py             # entrypoint / commands
  <module>.py        # one module per concern
tests/
```
`allowed_paths`: `["src/**", "tests/**"]`
`enforce`: `ask` (flat and small — a soft nudge is enough)

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
`allowed_paths`: `["src/**", "tests/**", "notebooks/**"]`
`enforce`: `ask` (pipeline stage boundaries are still explorative)

---

## Mapping to the Rule-5 hook

The hook reads `architecture.allowed_paths`, `architecture.layers`, and
`architecture.enforce` (`deny` | `ask` | `off`) from `config.json`. Use `ask`
when you want a soft nudge and `deny` when the layout must be strict.
