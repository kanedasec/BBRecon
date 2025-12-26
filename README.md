# BBRecon

BBRecon is a **stateful reconnaissance pipeline** designed for bug bounty, VDP, and AppSec workflows.
Instead of ad‑hoc scripts, Recon treats reconnaissance as a **repeatable data pipeline** with history, diffs, and reporting.

The goal is not just to find assets once, but to:

* Continuously discover **new attack surface**
* Track **what changed** since the last run
* Prioritize **high‑value findings** (new hosts, services, technologies, URLs)

---

## High‑level Architecture

Recon follows a **pipeline architecture**, where each step:

* Reads input from the database
* Executes external tools
* Writes normalized results back to the database
* Records execution metadata (`runs` table)

```
scope → subdomains → probe → fingerprint → content → report
```

All orchestration lives in `recon/pipeline/`.
The CLI (`recon/cli.py`) is intentionally thin and only wires commands to pipeline steps.

---

## Project Structure

```
Recon/
├── recon/
│   ├── cli.py                # Typer CLI (run, report)
│   ├── pipeline/             # Pipeline steps (orchestration)
│   │   ├── scope.py
│   │   ├── subdomains.py
│   │   ├── probe.py
│   │   ├── fingerprint.py
│   │   └── content.py
│   ├── reporting.py          # Diff & alerting logic
│   └── __init__.py
│
├── db/
│   ├── base.py
│   ├── models.py             # SQLAlchemy models
│   ├── repo.py               # DB access layer
│   └── session.py
│
├── artifacts/                # Generated outputs (ignored by git)
├── requirements.txt
└── README.md
```

---

## Database‑Driven by Design

Recon stores **everything** in a database:

* Scope domains
* Subdomains
* HTTP services
* Technology fingerprints
* Discovered URLs
* Pipeline runs

This enables:

* Incremental runs ("only new since last time")
* Accurate diffing
* Alerting and reporting
* Future integrations (dashboards, notifications)

---

## Pipeline Steps

### 1️⃣ Scope Discovery (`scope`)

Downloads in‑scope assets from HackerOne programs and normalizes them.

* Source: HackerOne CSV
* Output table: `scopes`
* Deduplicated per program

```bash
python -m recon.cli run --step scope --program example_vdp
```

---

### 2️⃣ Subdomain Enumeration (`subdomains`)

Enumerates subdomains for scoped root domains.

Tools used:

* `subfinder`

* `assetfinder`

* `chaos`

* `massdns` (validation)

* Output table: `subdomains`

* Tracks `first_seen` / `last_seen`

```bash
python -m recon.cli run --step subdomains
```

---

### 3️⃣ Asset Probing (`probe`)

Probes discovered subdomains using **httpx**.

* Determines live services

* Collects metadata (status, title, server, IP, etc.)

* Only probes **new subdomains** since last run

* Output table: `services`

```bash
python -m recon.cli run --step probe
```

---

### 4️⃣ Technology Fingerprinting (`fingerprint`)

Enriches live services with detected technologies.

* Tool: `httpx -tech-detect`
* Runs only on **new services** since last fingerprint run

Examples of detected tech:

* nginx, apache

* react, vue

* grafana, kibana

* wordpress

* Output table: `fingerprints`

```bash
python -m recon.cli run --step fingerprint
```

---

### 5️⃣ Content Discovery (`content`)

Discovers endpoints and URLs using active and passive techniques.

Active crawling:

* `katana`
* `hakrawler`

Passive discovery:

* `waybackurls`

* `gau`

* Input: `services(status_code=200)`

* Output table: `discovered_urls`

Highly verbose by design to support long‑running scans.

```bash
python -m recon.cli run --step content
```

---

### 6️⃣ Diff & Reporting (`report`)

Generates a **diff report** showing what’s new since a given time reference.

Supports:

* `last` run
* Relative times (`24h`, `7d`, `30m`)
* Program‑scoped or global reports

Outputs:

* New subdomains
* New services (with status breakdown)
* New discovered URLs
* Highlighted **interesting URLs** (admin, login, graphql, etc.)

```bash
python -m recon.cli report --since last
python -m recon.cli report --since 24h --program example_vdp
```

Optional exports:

```bash
python -m recon.cli report --since last \
  --out-json artifacts/diff.json \
  --out-md artifacts/diff.md
```

---

## Interesting URL Detection

Recon automatically highlights URLs matching high‑value patterns:

* `/admin`, `/login`, `/auth`
* `/swagger`, `/openapi`, `/api-docs`
* `/graphql`
* `/.git`, `/.env`

This helps prioritize manual testing quickly.

---

## CLI Usage

### Run full pipeline

```bash
python -m recon.cli run --program example_vdp
```

### Run a single step

```bash
python -m recon.cli run --step probe
```

### Global (no program scoping)

```bash
python -m recon.cli run --all
```

---

## Design Principles

* **Stateful**: every result has history
* **Incremental**: new‑only by default
* **Tool‑agnostic**: easy to swap tools
* **CLI‑first**: but scheduler‑ready
* **No monolithic scripts**

Recon is built to scale from personal bug bounty usage to team‑level AppSec monitoring.

---

## Roadmap

* [x] Stateful pipeline
* [x] Diff & reporting
* [x] Tech fingerprinting
* [ ] JS files scan
* [ ] Vulnerabilities scan
* [ ] Alerting (Telegram / Slack)
* [ ] Scheduler / cron wrapper
* [ ] Dashboard export

---

## Disclaimer

This project is intended for **authorized security testing only**.
Always respect program rules and legal boundaries.
