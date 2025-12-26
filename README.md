# Recon

**Recon** is a modular, database‑driven reconnaissance pipeline designed for **bug bounty hunters and AppSec engineers** who want *signal over noise*.

Recon focuses on **change detection, asset intelligence, and manual‑testing enablement**, not blind scanning.

---

## Philosophy

Recon is built around a few core principles:

- **DB is the source of truth**
- **Diff > volume**
- **Recon feeds humans, not scanners**
- **Everything is program‑scoped**
- **Tools are replaceable, data is not**

Recon helps you **notice what changed** — new assets, new endpoints, new JavaScript behavior — so vulnerabilities become obvious during manual testing.

---

## High‑Level Architecture

```
CLI (Typer)
  |
  v
Pipeline Steps
  |
  v
Database (SQLAlchemy)
  |
  v
Reports / Burp / Artifacts
```

Core recon loop:

```
scope → subdomains → http → content → js_analysis
   ↑                                         ↓
   └──────── discovered endpoints & assets ──┘
```

---

## Installation

```bash
git clone https://github.com/yourname/recon.git
cd recon
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## CLI Usage

Main entrypoint:

```bash
python -m recon.cli
```

General help:

```bash
python -m recon.cli --help
```

---

## Commands (Man Page)

---

### `run` — Execute Recon Pipeline

Runs one or more pipeline steps for a program.

```bash
recon run --program <program_name>
```

Run a specific step only:

```bash
recon run --program <program_name> --step js_analysis
```

Supported steps:

1. `scope` – Download HackerOne / VDP scope
2. `subdomains` – Enumerate subdomains
3. `dns` – Resolve and normalize DNS
4. `http` – Probe services with httpx
5. `fingerprint` – Technology detection
6. `content` – URL & asset discovery
7. `js_analysis` – JavaScript discovery & inspection

---

### `report` — Diff & Findings Report

Shows what changed since the last run.

```bash
recon report --program <program_name>
```

Examples of reported diffs:
- New subdomains
- New services
- New URLs
- New JS files
- Changed JS files
- New endpoints extracted from JS
- New secret indicators

Export formats:

```bash
recon report --program foo --out-json report.json
recon report --program foo --out-md report.md
```

---

### `burp` — Generate Burp Suite Scope

Generates Burp scope configuration and URL lists.

```bash
recon burp --program <program_name>
```

Options:
- Exclude hosts by HTTP status
- Export alive URLs
- Generate wildcard scope entries

Outputs:
- Burp JSON config
- Plain‑text URL list

---

### `js_analysis` — JavaScript Analysis (Pipeline Step)

This step is part of `run`, but can be executed independently.

What it does:
- Identifies JS assets
- Downloads & caches files
- Computes SHA‑256 hashes
- Extracts:
  - Endpoints
  - API paths
  - Domains
  - Secret indicators (summary only)
- Feeds endpoints back into content discovery

No raw secrets are stored.

---

### `js-scan` — Offline JavaScript Secret Scan

Scans **downloaded JS artifacts on disk** using DB paths.

```bash
recon js-scan --program <program_name>
```

Features:
- Offline (no HTTP requests)
- Program‑scoped
- Masked output only
- Line & column context
- Inspired by SecretFinder

Optional outputs:

```bash
recon js-scan --program foo --out-json artifacts/js_scan.json
recon js-scan --program foo --out-html artifacts/js_scan.html
```

Filtering:
- Scan only changed JS since last run
- Scan specific programs

---

## Pipeline Steps Explained

### 1. Scope Download
Downloads program scope and stores root domains.

**Table:** `scope_domains`

---

### 2. Subdomain Enumeration
Uses tools like:
- `subfinder`
- `assetfinder`

Deduplicates and links subdomains to programs.

**Table:** `subdomains`

---

### 3. DNS Resolution
Resolves discovered subdomains and normalizes results.

---

### 4. HTTP Probing
Uses `httpx` to detect:
- Alive services
- Status codes
- Titles
- Headers
- IPs

**Table:** `services`

---

### 5. Technology Fingerprinting
Detects:
- Frameworks
- WAFs
- Platforms

Diff‑aware across runs.

**Table:** `fingerprints`

---

### 6. Content Discovery
Uses:
- `katana`
- `hakrawler`

Finds:
- URLs
- Endpoints
- Static assets

**Table:** `discovered_urls`

---

### 7. JavaScript Analysis
Two‑layer approach:

#### Layer 1 — JS Discovery
- `.js`, `.mjs`, `.js.map`
- From discovered URLs and services

#### Layer 2 — JS Inspection
- Download & cache
- Hash comparison
- Endpoint extraction
- Secret pattern detection
- Feedback loop into content discovery

**Table:** `js_artifacts`

---

## Data Safety & OPSEC

### Stored
- JS metadata
- Hashes
- File paths
- Secret **types & counts**

### Never Stored
- Raw secrets
- Tokens
- Credentials
- API keys

Recon is designed to be **legally and operationally safe**.

---

## Typical Workflow

```bash
# Initial recon
recon run --program example

# Incremental updates
recon run --program example --step content
recon run --program example --step js_analysis

# Review changes
recon report --program example

# Offline JS review
recon js-scan --program example

# Burp setup
recon burp --program example
```

---

## What Recon Is NOT

- ❌ Not a vulnerability scanner
- ❌ Not a secret harvester
- ❌ Not a one‑shot recon script

Recon is a **recon intelligence engine**.

---

## Final Mental Model

> Recon helps you **never miss what changed** —  
> so you can spend your time breaking the right things.
