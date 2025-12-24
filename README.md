# Recon – Bug Bounty Recon Automation

Recon is a **modular bug bounty reconnaissance automation framework** designed to help security researchers scale and organize recon activities in a **repeatable, auditable, and incremental** way.

The project focuses on:
- Scope ingestion directly from bug bounty platforms
- Structured recon pipelines (scope → subdomains → services → content)
- Incremental runs (only process what is new)
- Strong separation between application logic and persistence
- Traceability via run metadata (who ran what, when, and with which input)

This is **not a one-shot recon script**. It is a recon *system*.

---

## High-Level Flow

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
- Is idempotent
- Stores results in a database
- Tracks `first_seen` / `last_seen`
- Is associated with a `run` record

---

## Project Structure

```
Recon/
├── app/
│   └── application-logic-pythonscripts/
│       ├── scopeDownload.py
│       ├── subdomainEnum.py
│       ├── assetProbing.py
│       └── contentDiscovery.py
│
├── db/
│   └── db-logic-pythonscripts/
│       ├── base.py
│       ├── session.py
│       ├── models.py
│       └── repo.py
│
├── artifacts/
│   ├── resolvers.txt
│   └── (tool outputs)
│
├── .env
├── requirements.txt
└── recon.db (local sqlite by default)
```

---

## Environment Configuration (.env)

Example:

```
DATABASE_URL=sqlite:///recon.db
PROGRAMS_FILE=programs_list.txt
RESOLVERS_LIST=artifacts/resolvers.txt
ARTIFACTS_DIR=artifacts
CHAOS_API=YOUR_CHAOS_API_KEY
```

---

## Database Model Overview

Core entities:

- **Program** – Bug bounty program (e.g. HackerOne team)
- **ScopeDomain** – Root domains in scope per program
- **Subdomain** – Enumerated and DNS-resolved subdomains
- **Service** – Live HTTP services (httpx results)
- **DiscoveredURL** – URLs found via crawling and archives
- **Run** – Execution metadata for every pipeline step

All entities track:
- `first_seen`
- `last_seen`

This enables **diff-based recon** instead of blind rescans.

---

## Pipeline Steps

### 1. Scope Download

**File:** `scopeDownload.py`

- Downloads scope CSV directly from HackerOne
- Expands wildcards (`*.example.*` → allowed TLDs)
- Stores root domains per program
- Tracks scope drift over time

Run:

```
python scopeDownload.py
```

---

### 2. Subdomain Enumeration

**File:** `subdomainEnum.py`

Tools used:
- subfinder
- assetfinder
- chaos
- massdns (validation)

Features:
- Parallel enumeration per root domain
- DNS validation before storage
- Subdomains linked to their root domain

Run:

```
python subdomainEnum.py
```

---

### 3. Asset / Service Probing

**File:** `assetProbing.py`

Tool used:
- httpx

Key design choices:
- Only probes **new subdomains** since last run
- Batch-based execution for resilience
- Stores full HTTP metadata

Run:

```
python assetProbing.py
```

---

### 4. Content Discovery

**File:** `contentDiscovery.py`

Tools used:
- katana
- hakrawler
- waybackurls
- gau

Input:
- Only services with `status_code = 200`

Output:
- Live crawled URLs
- Passive archive URLs
- Source attribution per URL

Run:

```
python contentDiscovery.py
```

---

## Design Philosophy

- **Stateful recon** instead of flat files
- **Incremental execution** (new-only processing)
- **Tool-agnostic pipelines**
- **Database as source of truth**
- **Automation-friendly, analyst-friendly**

This structure scales from:
- Single-program recon
- To multi-program continuous recon

---

## Roadmap (High Level)

- Parameterized pipelines (per program / per domain)
- Technology fingerprinting
- Screenshotting
- Vulnerability modules
- Reporting & diff exports
- Scheduler / daemon mode

---

## Disclaimer

This tool is intended for **authorized security testing only**.
Use exclusively on targets you own or have explicit permission to test.

