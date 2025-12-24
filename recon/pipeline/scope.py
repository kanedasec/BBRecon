from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

from db.session import get_session
from db.repo import ReconRepo

load_dotenv()

ALLOWED_TLDS = {"com", "net", "org", "io", "co", "app"}
PROGRAMS_FILE = os.getenv("PROGRAMS_FILE")


def expand_identifier(identifier: str, allowed_tlds: set[str]) -> set[str]:
    identifier = identifier.strip().lstrip("*.")

    if identifier.endswith(".*"):
        base = identifier[:-2]
        return {f"{base}.{tld}" for tld in allowed_tlds}

    return {identifier}


def _download_scope_csv(program: str) -> str:
    url = f"https://hackerone.com/teams/{program}/assets/download_csv.csv"
    print(f"[SCOPE] Requesting CSV: {url}")

    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.text


def scope_download(program: str) -> list[str]:
    """
    Downloads HackerOne scope CSV and returns list of normalized domains (root scope).
    """
    try:
        csv_text = _download_scope_csv(program)
    except requests.exceptions.HTTPError as e:
        print(f"[SCOPE][HTTP] {e}")
        return []
    except requests.exceptions.ConnectionError:
        print("[SCOPE][NET] Connection error")
        return []
    except requests.exceptions.Timeout:
        print("[SCOPE][NET] Timeout")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[SCOPE][NET] Request failed: {e}")
        return []

    print("[SCOPE] Parsing CSV rows...")
    parsed_domains: set[str] = set()

    reader = csv.DictReader(StringIO(csv_text))
    for row in reader:
        asset_type = (row.get("asset_type") or "").strip().upper()
        identifier = (row.get("identifier") or "").strip()

        if not identifier:
            continue

        if asset_type in ("WILDCARD", "URL"):
            parsed_domains.update(expand_identifier(identifier, ALLOWED_TLDS))

    out = sorted(parsed_domains)
    print(f"[SCOPE] Extracted {len(out)} unique scope identifiers")
    return out


def _programs_from_file() -> list[str]:
    if PROGRAMS_FILE and Path(PROGRAMS_FILE).exists():
        with open(PROGRAMS_FILE, "r", encoding="utf-8") as f:
            programs = [line.strip() for line in f if line.strip()]
        return programs
    return []


def run_scope_download(
    program: Optional[str] = None,
    run_all: bool = False,
    interactive: bool = False,
) -> None:
    """
    Pipeline step:
      - If program provided: downloads scope for that single program
      - Else if run_all: uses PROGRAMS_FILE list (multi-program)
      - Else if interactive: prompts for program name
      - Else: fails fast (no prompt)
    """
    programs: list[str] = []

    if program:
        programs = [program]
    elif run_all:
        programs = _programs_from_file()
        if not programs and interactive:
            p = input("[SCOPE] PROGRAMS_FILE missing/empty. Enter one program: ").strip()
            if p:
                programs = [p]
    else:
        # not run_all, no explicit program
        if interactive:
            p = input("[SCOPE] Enter program (HackerOne team): ").strip()
            if p:
                programs = [p]

    if not programs:
        print("[SCOPE] No programs provided. Use --program, or --all, or --interactive.")
        return

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(step="scope_download", meta={"programs": programs, "programs_file": PROGRAMS_FILE})

        for prog in programs:
            print(f"\n[SCOPE] Program: {prog}")
            domains = scope_download(prog)
            if not domains:
                print(f"[SCOPE] No domains extracted for {prog} (or request failed).")
                continue

            new_count = repo.upsert_scopes(program=prog, domains=domains)
            print(f"[SCOPE][DB] scopes saved. New domains: {new_count}")

        repo.finish_run(run_id)
