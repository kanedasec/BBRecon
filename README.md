# Recon – Bug Bounty Recon Automation

Recon is a **stateful bug bounty reconnaissance automation framework** designed for long‑running, repeatable, and auditable recon workflows.

This project is **not** a collection of one‑off scripts. It is a recon *system* built around:

* Database‑backed state (no blind re‑scans)
* Incremental pipelines (only process what’s new)
* Clear execution tracking (runs, timestamps, metadata)
* CLI‑driven orchestration
* Tool‑agnostic design

---

## High‑Level Pipeline

```
HackerOne Scope
     ↓
Scope Domains (DB)
     ↓
Subdomain Enumeration
     ↓
Resolved Subdomains (DB)
     ↓
Service Probing (HTTPX)
     ↓
Live Services (DB)
     ↓
Content Discovery
     ↓
Discovered URLs (DB)
```

Each step:

* Is safe to re‑run
* Tracks `first_seen` / `last_seen`
* Writes results incrementally
* Records execution metadata in the `runs` table

---

## Project Structure

```
Recon/
├── recon/
│   ├── cli.py                # CLI entrypoint (Typer)
│   └── pipeline/
│       ├── scope.py          # Scope orchestration
│       ├── subdomains.py     # Subdomain enumeration orchestration
│       ├── probe.py          # Asset / service probing orchestration
│       └── content.py        # Content discovery orchestration
│
├── app/
│   ├── scopeDownload.py      # HackerOne scope ingestion
│   ├── subdomainEnum.py      # Subdomain enumeration logic
│   ├── assetProbing.py       # HTTP probing (httpx)
│   └── contentDiscovery.py   # Crawling + archive discovery
│
├── db/
│   ├── base.py
│   ├── session.py
│   ├── models.py
│   └── repo.py
│
├── artifacts/                # Local tool outputs (ignored by git)
├── requirements.txt
├── .env
└── recon.db                  # SQLite DB (local default)
```

---

## Environment Configuration

Example `.env`:

```
DATABASE_URL=sqlite:///recon.db
PROGRAMS_FILE=programs_list.txt
RESOLVERS_LIST=artifacts/resolvers.txt
ARTIFACTS_DIR=artifacts
CHAOS_API=YOUR_CHAOS_API_KEY
```

---

## CLI Usage

Recon is driven via a single CLI entrypoint:

```
python -m recon.cli run [OPTIONS]
```

### Common Commands

Run full pipeline for all programs listed in `PROGRAMS_FILE`:

```
python -m recon.cli run --all
```

Run full pipeline for a single program:

```
python -m recon.cli run --program fanduel-vdp
```

Run individual steps:

```
python -m recon.cli run --step scope --program fanduel-vdp
python -m recon.cli run --step subdomains --program fanduel-vdp
python -m recon.cli run --step probe --program fanduel-vdp
python -m recon.cli run --step content --program fanduel-vdp
```

Allow interactive fallback (explicit opt‑in):

```
python -m recon.cli run --all --interactive
```

> By default, the CLI is **non‑interactive** and safe for automation.

---

## Pipeline Details

### 1. Scope Download

* Pulls scope directly from HackerOne CSV
* Expands wildcard identifiers (e.g. `*.example.*`)
* Uses only Python stdlib (no pandas)
* Stores scope domains per program

Tracked in DB:

* program
* domain
* first_seen / last_seen

---

### 2. Subdomain Enumeration

Tools:

* subfinder
* assetfinder
* chaos
* massdns (validation)

Features:

* Parallel execution
* DNS validation before persistence
* Root‑domain association

---

### 3. Asset / Service Probing

Tool:

* httpx

Features:

* Probes **only new subdomains** since last run
* Batch‑based execution
* Stores full HTTP metadata (status, title, server, IP)

---

### 4. Content Discovery (Verbose)

Tools:

* katana (active crawling)
* hakrawler (active crawling)
* waybackurls (passive)
* gau (passive)

Behavior:

* Runs only on services with `status_code = 200`
* Two explicit phases:

  * **Active crawling** (service URLs)
  * **Passive discovery** (domains)

Verbose output includes:

* Phase start banners
* Batch progress (X/Y)
* Per‑tool execution time
* URLs collected per tool
* URLs inserted into DB per batch

This makes long‑running discovery **observable and debuggable**.

---

## Database Model Overview

Core entities:

* **Program** – Bug bounty program (e.g. HackerOne team)
* **ScopeDomain** – Root domains in scope
* **Subdomain** – Enumerated and resolved subdomains
* **Service** – Live HTTP services
* **DiscoveredURL** – URLs found via crawling / archives
* **Run** – Execution metadata

All entities track:

* `first_seen`
* `last_seen`

This enables:

* Recon diffs
* Drift detection
* Historical analysis

---

## Design Principles

* Database as source of truth
* Incremental recon (no wasted scans)
* Deterministic pipelines
* Explicit CLI intent
* Minimal external dependencies

This design scales naturally from:

* Single‑program recon
* To multi‑program continuous recon

---

## Diff & Alerting (Implemented)

Recon now includes **native diff & reporting capabilities**, turning the pipeline into a **continuous recon system** instead of a one‑shot scanner.

### What “Diff” Means in Recon

Recon uses **database timestamps (`first_seen`)** as the source of truth.

A diff answers:

> *What is new since a given point in time?*

This works reliably even across crashes, partial runs, or re‑execution of steps.

### Diff Sources

Diffs are calculated for:

* **Subdomains** – new `Subdomain.first_seen`
* **Services** – new HTTP services discovered by httpx
* **Discovered URLs** – new URLs from crawling and archives

### CLI Reporting Command

Generate a diff report directly from the CLI:

```bash
python -m recon.cli report
```

Default behavior:

* Uses the **last finished `content_discovery` run** as reference
* Reports **global changes** across all programs

### Common Examples

Diff since last content discovery run:

```bash
python -m recon.cli report
```

Diff for a specific program:

```bash
python -m recon.cli report --program fanduel-vdp
```

Diff since last 24 hours:

```bash
python -m recon.cli report --since 24h
```

Export results:

```bash
python -m recon.cli report \
  --since 24h \
  --out-json artifacts/diff.json \
  --out-md artifacts/diff.md
```

### Output

Terminal summary:

```
[DIFF] since=2025-12-24T14:48:46Z program=ALL
New subdomains: 12
New services:   7
  status breakdown: {"200": 4, "302": 2, "403": 1}
New URLs:       183 (interesting: 9)
```

### Interesting URL Detection

Recon highlights **high‑signal URLs** automatically, including:

* `/admin`, `/login`, `/auth`
* `/swagger`, `/openapi`, `/graphql`
* exposed `.git` or `.env` paths

This logic lives in:

```
recon/reporting.py
```

and is reused by the CLI and future alerting backends.

### Architecture Notes

* `cli.py` is intentionally **thin** (only Typer commands)
* All reporting logic lives in `recon/reporting.py`
* Reporting uses **lazy imports** to keep CLI startup fast
* Reporting gracefully degrades if optional repo methods are missing

This design allows future integrations (Slack, Telegram, Webhooks)
without changing the CLI interface.

---

## Roadmap

* Alerting backends (Telegram / Slack)
* Scheduled diff execution
* Program‑level foreign keys for precise scoping
* Severity heuristics for discovered URLs
* Automatic ticket / note generation
