# claude-for-idiots

[English](README.md) · **Português**

> Uma skill do [Claude Code](https://claude.com/claude-code) que mantém o Claude
> **na linha** — e explica as coisas em linguagem simples, pra que até quem nunca
> programou consiga construir software de verdade sem se perder.

---

## Como usar

### 1. Instalar (uma vez)

**Requisitos:** Python 3 e [Claude Code](https://claude.com/claude-code).

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

Depois reinicie o Claude Code pra ele reconhecer a nova skill.

### 2. Ligar — de forma explícita

Numa sessão do Claude Code, rode:

```
/claude-for-idiots
```

**Ela só roda quando você pede — de propósito.** Nem todo projeto deve ser
embrulhado nesses guard-rails: um script descartável e rápido, ou um projeto que
já existe e tem suas próprias convenções, geralmente é melhor deixar em paz. Por
isso a skill **nunca assume o controle sozinha** — você liga ela, por projeto,
quando realmente quer.

Depois de ligada, ela faz algumas perguntas rápidas — seu idioma, seu nível de
experiência, se deve usar termos técnicos, e o que você quer construir — e prepara
tudo pra aquele projeto.

> **Atenção:**
> - A configuração guiada leva **~10 minutos** (medido no Opus 4.8) — ela faz as
>   perguntas, escolhe a stack, instala as ferramentas e escreve os guard-rails.
> - **Iniciantes:** rodem o Claude Code em **auto mode** (aceitação automática de
>   permissões) durante o setup, pra não serem interrompidos por prompt de
>   permissão a cada passo.
> - **Ainda não testada para deploy** — a skill cobre o desenvolvimento local;
>   fluxos de publicação em produção estão no roadmap.

### 3. Atualizar (quando sair versão nova)

```
/claude-for-idiots update
```

Atualiza a própria skill e — se o projeto atual foi configurado por ela — traz
os guard-rails do projeto pra versão nova também, **mantendo todas as suas
escolhas**. Ele te conta o que mudou antes de tocar em qualquer coisa.

---

## O que é isso? (em palavras simples)

Você está construindo algo com o Claude Code, mas:

- ele fica usando palavras que você não entende (e nem quer parar pra pesquisar), e
- você não tem certeza se ele está fazendo as coisas "do jeito certo".

Essa skill resolve os dois. Quando você liga ela, o Claude:

- **fala com você do jeito que *você* escolher** — sem nenhum termo técnico, com
  os termos *acompanhados* de explicações simples, ou com os termos normalmente;
- **segue boas práticas de engenharia automaticamente** — testes, commits
  seguros, uma estrutura de pastas de verdade, sem vazar senhas — pra o seu
  projeto não virar uma bagunça.

Você não precisa saber o que significam "migration", "CORS" ou "arquitetura". Esse
é exatamente o ponto. Tanto iniciantes quanto pessoas experientes usam — ela só
se adapta.

## Por que eu criei isso

Eu estava programando com o Claude Code e esbarrei em duas coisas que me
incomodavam:

1. Ele ficava jogando palavras técnicas que eu não entendia — e, sinceramente,
   não queria parar pra aprender naquele momento.
2. Eu queria que ele simplesmente seguisse o básico de um bom software — uma
   arquitetura de verdade, testes, commits com cuidado — em vez de improvisar de
   um jeito diferente toda vez.

Então criei isso pra manter o Claude **na linha**. E, já que estava nisso, deixei
amigável o suficiente pra que alguém com **zero experiência em programação**
também consiga usar o Claude tranquilamente.

## O que posso construir com isso?

A skill sabe escolher uma arquitetura para esses tipos de projeto:

| O que você quer construir | Stack recomendada |
|---|---|
| Site / web app | Next.js (React + TypeScript) |
| Site estático / conteúdo simples | Astro ou HTML + CSS + JS puro |
| API REST ou serviço de backend | FastAPI (Python) ou NestJS (TypeScript) |
| App completo (UI + API + banco) | Next.js + Postgres (via Prisma) |
| App mobile (iOS + Android) | Flutter |
| Ferramenta de linha de comando / automação | Python (Typer) ou Node (Commander) |
| Análise de dados / protótipo de ML | Python (pandas / scikit-learn / notebooks) |
| Bot de Discord / Telegram | Python ou Node |
| App desktop | Tauri ou Electron |

Usuários avançados podem sempre escolher a própria stack — o catálogo é só o padrão.

## Devo usar no meu projeto?

Resposta honesta: **nem sempre.** Os guard-rails têm custo — testes, checagens e
commits a cada feature — então eles precisam render mais do que custam.

| Projeto | Usar? |
|---|---|
| Um app/site/API de verdade que você vai continuar mexendo (semanas, meses) | ✅ Sim — é o ponto ideal |
| Seu primeiro projeto sério / aprender construindo algo real | ✅ Sim — foi feita pra isso |
| Qualquer coisa com banco de dados e/ou repositório público | ✅ Sim — as regras de migração e segredo existem exatamente pra isso |
| Script descartável ou experimento de uma tarde | ❌ Não — o Claude puro é mais rápido; o overhead não compensa |
| Codebase que já existe com convenções próprias / projeto de equipe | ❌ Ainda não — a skill assume projeto novo |

Regra de bolso: **se o projeto ainda vai importar daqui a duas semanas, liga; se
é descartável, não liga.** É também por isso que ela só roda quando você invoca
explicitamente.

## O que ele melhora

Depois da configuração, o Claude segue isto em **toda** sessão daquele projeto. Os
itens marcados com **(garantido)** são impostos por hooks — o Claude literalmente
não consegue quebrar:

- **Não edita arquivos de migração na mão** *(garantido)* — usa o comando gerador
  correto.
- **Arquivos novos ficam dentro da arquitetura escolhida** *(garantido)* — nada
  jogado em qualquer canto.
- **Segredos nunca vão pra internet** *(garantido)* — chaves/senhas ficam num
  `.env` local; tudo que publica é varrido antes.
- **Sempre escreve testes** — e pergunta antes de rodar a suíte completa (que é
  lenta).
- **Faz commit a cada feature** — pra você nunca perder progresso.
- **Sanity check depois de cada feature** — lint, os testes da feature, e subir o
  app de verdade pra ver funcionando.
- **Configura ferramentas de qualidade pra sua stack** (formatador + linter) — o
  código fica limpo automaticamente.
- **Reutiliza antes de reconstruir** — procura no código (e na `docs/`) algo que
  já faça o trabalho antes de escrever de novo.
- **Mantém uma pasta `docs/` pra decisões grandes e lições difíceis** — o
  conhecimento sobrevive sem inflar cada sessão.
- **Sabe a hora de parar de chutar** — depois de duas correções falhas, ele para,
  relê o erro, confere versões e pesquisa a fundo na web antes de tentar de novo.
- **Em apps web, consegue checar o navegador sozinho** — abre a página, lê o
  console em busca de erros escondidos, tira screenshots (com o Playwright
  configurado — ele se oferece pra configurar).

E ela se adapta a **você**:

- **Nível de experiência** — iniciante / intermediário / avançado: define o quanto
  ela explica e se escolhe a stack por você.
- **Termos técnicos** — `none` (só linguagem simples) · `explain` (usa o termo +
  uma explicação simples que fica mais profunda conforme você aprende) · `raw`
  (termos normalmente).

**Como isso gruda:** a configuração escreve um `CLAUDE.md` (carregado
automaticamente em toda sessão) mais os hooks, então as regras continuam valendo
até em sessões longas — não só enquanto a skill está aberta.

## Estrutura do repositório

```
SKILL.md                     # o cérebro da skill (onboarding + comportamento)
references/                  # dados editáveis — estenda a skill aqui
  rules.md                   #   as 9 regras (fonte da verdade)
  stack-catalog.md           #   objetivo → stack
  architecture-catalog.md    #   stack → arquitetura idiomática
  onboarding-flow.md         #   as perguntas
  glossary-format.md         #   como funciona o dicionário do modo "explain"
  quality-tools.md           #   formatador/linter/type-checker por stack
  browser-verification.md    #   smoke test web com navegador de verdade
  update-flow.md             #   como o /claude-for-idiots update funciona
assets/                      # o que é escrito no seu projeto
  CLAUDE.template.md
  config.example.json
  settings.template.json
  docs-INDEX.template.md
  ADR.template.md
hooks/                       # os guard-rails técnicos (Python)
  block_migration_edits.py   #   migrações
  enforce_architecture.py    #   arquitetura
  scan_secrets_before_push.py#   segredos
tests/                       # suíte de testes dos hooks (roda no CI a cada PR)
```

## Contribuindo

Forks, issues e PRs são bem-vindos — veja [CONTRIBUTING.md](CONTRIBUTING.md)
(em inglês). Adicionar uma nova stack ou arquitetura é só editar um arquivo de
dados, não reescrever a skill.

## Licença

[MIT](LICENSE) © 2026 Julio Barbosa — permissiva e amigável a forks.
