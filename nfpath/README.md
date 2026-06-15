# nfpath — SMB Intelligence Correlation Engine

`nfpath` is a companion tool for [NullFang](../README.md) that processes SMB scan results through an LLM to extract structured intelligence: credentials, hosts, services, and attack paths.

It reads from a NullFang database (`nfdb.db`), analyzes files via a local or remote LLM, and builds an intelligence graph stored in a separate SQLite database. Output is a terminal REPL for operators and an HTML report for stakeholders.

---

## Requirements

- **NullFang** — run a scan first to populate a `nfdb.db`
- **LLM backend** — one of:
  - [Ollama](https://ollama.com) running locally (default, no API key needed)
  - OpenAI, Anthropic, Groq, or any OpenAI-compatible API (key required)
  - [LiteLLM](https://github.com/BerriAI/litellm) as a local proxy to any provider

---

## Build

```bash
# From the NullFang root directory
go build -o nfpath ./nfpath/

# Windows
go build -o nfpath.exe ./nfpath/
```

---

## Quick Start

```bash
# 1. Pull a model (Ollama)
ollama pull qwen2.5:7b

# 2. Run NullFang to collect data
nullfang -n 192.168.1.0/24 -u operator -p Password123 -m "password,secret,config"

# 3. Analyze the results
nfpath analyze

# 4. Chat with the intelligence
nfpath chat

# 5. Generate HTML report
nfpath report
```

---

## Database Isolation

Each NullFang scan database gets its own nfpath intelligence database, derived automatically:

```
corp_scan.db        → corp_scan_nfpath.db
internal_audit.db   → internal_audit_nfpath.db
```

This prevents intelligence from different engagements from polluting each other.

```bash
# Engagement A
nfpath -nullfang-db corp_scan.db analyze
nfpath -nullfang-db corp_scan.db chat

# Engagement B — completely isolated
nfpath -nullfang-db internal_audit.db analyze

# Review a past engagement explicitly
nfpath -db corp_scan_nfpath.db chat
```

If `--nullfang-db` is not specified, nfpath looks for the default NullFang database:
- **Windows**: `%APPDATA%\nullfang\nfdb.db`
- **Linux**: `~/.local/nullfang/nfdb.db`

---

## Commands

| Command | Description |
|---------|-------------|
| `analyze` | Process all unanalyzed files from the NullFang DB (one-shot, post-scan) |
| `pipeline` | Watch the NullFang DB and analyze new files as they arrive (concurrent with scan) |
| `chat` | Interactive intelligence REPL — ask questions about findings in natural language |
| `report` | Generate a self-contained HTML report with interactive graph |
| `decisions` | Show the decision table: files found but not copied, requiring operator action |
| `status` | Show processing statistics |
| `models` | List models available in the local Ollama instance |
| `config` | Show effective configuration and where each setting came from |

---

## Modes in Detail

### `analyze` — Post-scan batch processing

Processes files in two phases:

**Phase 1 — Copied files**: reads local file content, sends it to the LLM, extracts credentials, hosts, and services into the intelligence DB.

**Phase 2 — Recon-only files**: for files that were found but not copied (NullFang running in `recon` or `search` mode), the LLM infers intelligence from filename, path, extension, and match reason alone — no content required. These go into the **decision table**.

```bash
nfpath -nullfang-db corp_scan.db analyze
nfpath -nullfang-db corp_scan.db analyze -v   # verbose, shows LLM calls
```

### `pipeline` — Concurrent with active scan

Polls the NullFang database while a scan is running. As NullFang copies files and adds them to its DB, nfpath picks them up and processes them in parallel. Uses SQLite WAL mode to avoid locking the scan.

```bash
# Terminal 1 — run scan
nullfang -n 192.168.1.0/24 -u operator -p Password123 -m "password,secret"

# Terminal 2 — process in real time
nfpath -nullfang-db corp_scan.db pipeline --poll 20s
```

### `chat` — Interactive intelligence REPL

Loads the extracted intelligence into the LLM context and opens an interactive session. The LLM answers questions about the findings, suggests attack paths, and explains what was found.

```
nfpath> what credentials give the most access?
nfpath> is there a path to domain admin from what we found?
nfpath> are there any reused passwords across systems?
nfpath> explain what was found in the SQL config files
nfpath> which system should I target first?
```

Built-in commands inside the REPL:

| Command | Description |
|---------|-------------|
| `/decisions` | Show files not copied — pending operator action |
| `/creds` | List all extracted credentials |
| `/hosts` | List discovered hosts and services |
| `/status` | Processing statistics |
| `/refresh` | Reload intelligence context from DB (useful in pipeline mode) |
| `/quit` | Exit |

```bash
nfpath -nullfang-db corp_scan.db chat
nfpath -nullfang-db corp_scan.db chat -max-context-items 15   # for 3B models
```

### `report` — HTML report

Generates a self-contained HTML file with:
- **Executive summary**: risk level, credential count, systems at risk, pending decisions
- **Interactive graph**: force-directed visualization of credentials, hosts, and their relationships (no external dependencies — rendered in-browser with inline canvas JS)
- **Credentials table**: all extracted credentials with confidence levels
- **Hosts & services**: discovered infrastructure
- **Decision table**: files requiring follow-up action

```bash
nfpath -nullfang-db corp_scan.db report
nfpath -nullfang-db corp_scan.db report --report-out engagement_report.html
```

### Decision Table

When NullFang runs in recon or search mode (no file copy), files that match patterns are logged as findings without local copies. nfpath processes these through the LLM using only metadata — filename, path, extension, and match reason — to infer intelligence value and recommended action.

Example decision table entry:

```
[CRITICAL] #1 \\DC01\SYSVOL\scripts\deploy.bat
     Host    : 192.168.1.10
     Matched : keyword: password
     Intel   : Deployment script likely containing hardcoded service account credentials
     Action  : Copy file and run through nfpath analyze
     Status  : pending
```

```bash
nfpath -nullfang-db corp_scan.db decisions
```

---

## LLM Configuration

### Priority order (lowest to highest)

```
~/.nfpath/config.yaml  or  .nfpath.yaml
  ↓ overridden by
Environment variables (NFPATH_LLM_KEY, NFPATH_LLM_URL, ...)
  ↓ overridden by
CLI flags (--llm-url, --llm-model, --llm-provider)
```

> **API keys must never be passed via `--llm-key` in production** — the flag is visible in shell history and `ps` output. Use the environment variable or config file instead.

### Config file

Copy from `nfpath.yaml.example`:

```yaml
# ~/.nfpath/config.yaml
llm:
  url: http://localhost:11434
  model: qwen2.5:7b
  provider: ollama
```

### Environment variables

```bash
export NFPATH_LLM_KEY=sk-...
export NFPATH_LLM_URL=https://api.anthropic.com
export NFPATH_LLM_MODEL=claude-haiku-4-5-20251001
export NFPATH_LLM_PROVIDER=anthropic
```

### Supported providers

| Provider | URL | `--llm-provider` | Notes |
|----------|-----|-----------------|-------|
| Ollama (local) | `http://localhost:11434` | `ollama` | Default. No key needed. |
| OpenAI | `https://api.openai.com` | `openai` | `gpt-4o-mini` recommended for cost |
| Anthropic | `https://api.anthropic.com` | `anthropic` | `claude-haiku-4-5-20251001` fast and cheap |
| Groq | `https://api.groq.com/openai` | `openai` | Free tier, very fast |
| LiteLLM proxy | `http://localhost:4000` | `openai` | Routes to any provider |
| Any OpenAI-compatible | custom URL | `openai` | Together, DeepSeek, Mistral API, etc. |

Provider is auto-detected from the URL when `--llm-provider` is not set:
- URL contains `anthropic.com` → Anthropic
- Key is set, URL is anything else → OpenAI-compatible
- No key → Ollama

### Model recommendations

```bash
nfpath models   # list what's installed in Ollama
```

| Model | Context | Speed | Quality | Use case |
|-------|---------|-------|---------|----------|
| `qwen2.5:3b` | 8K | Fast | Good | Quick scans, low-RAM environments |
| `qwen2.5:7b` | 32K | Medium | Better | Default recommendation |
| `mistral:7b` | 32K | Medium | Better | Complex files with mixed content |
| `gpt-4o-mini` | 128K | Fast | High | Large files, API budget available |
| `claude-haiku-4-5-20251001` | 200K | Fast | High | Best for structured extraction |

For 3B models, limit context to avoid truncation:

```bash
nfpath chat -max-context-items 15
```

### Provider examples

```bash
# Ollama local (default)
nfpath analyze

# OpenAI — key via env var, not CLI
export NFPATH_LLM_KEY=sk-...
nfpath -llm-url https://api.openai.com -llm-model gpt-4o-mini analyze

# Anthropic
export NFPATH_LLM_KEY=sk-ant-...
nfpath -llm-url https://api.anthropic.com -llm-model claude-haiku-4-5-20251001 chat

# Groq (free tier, OpenAI-compatible)
export NFPATH_LLM_KEY=gsk_...
nfpath -llm-url https://api.groq.com/openai -llm-model llama-3.1-8b-instant analyze

# Debug: show effective config
nfpath config
```

---

## All Flags

```
--nullfang-db   string    NullFang database path (default: OS standard location)
--db            string    nfpath intelligence database (default: derived from --nullfang-db)
--llm-url       string    LLM base URL (default: http://localhost:11434)
--llm-model     string    Model name
--llm-key       string    API key (prefer NFPATH_LLM_KEY env var)
--llm-provider  string    auto|ollama|openai|anthropic (default: auto)
--poll          duration  Pipeline mode poll interval (default: 30s)
--report-out    string    HTML report output path (default: nfpath_report.html)
--max-context-items int   Max items per category in chat context (default: 30)
-v                        Verbose output
--config        string    Path to config file
```

---

## Architecture

```
nullfang.db (read-only)
      │
      ├── files with local_path ──→ [LLM: full content analysis]
      │                                    │
      │                              intel_credentials
      │                              intel_hosts
      │                              intel_services
      │                              intel_edges
      │
      └── low_hanging_fruit ───────→ [LLM: metadata inference]
          (recon-only, no copy)            │
                                     intel_decisions
                                     (decision table)
                                           │
                                    ┌──────┴───────┐
                               nfpath chat      HTML report
                             (REPL + LLM)   (graph + tables)
```

---

## License

Same as NullFang. For authorized security assessments only.
