from __future__ import annotations

import csv
import os
from dotenv import load_dotenv
from pathlib import Path
from typing import List
from io import StringIO

import requests

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


def scope_download(program: str) -> List[str]:
    url = f"https://hackerone.com/teams/{program}/assets/download_csv.csv"

    try:
        print("Making request to:", url)
        response = requests.get(url=url, timeout=30)
        response.raise_for_status()

    except requests.exceptions.HTTPError as e:
        print(f"HTTP error: {e}")
        return []

    except requests.exceptions.ConnectionError:
        print("Connection error: unable to reach the server")
        return []

    except requests.exceptions.Timeout:
        print("Request timed out")
        return []

    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return []

    print("Parsing CSV")

    parsed_domains: set[str] = set()

    # HackerOne returns a CSV with headers like: asset_type, identifier, ...
    reader = csv.DictReader(StringIO(response.text))

    for row in reader:
        asset_type = (row.get("asset_type") or "").strip().upper()
        identifier = (row.get("identifier") or "").strip()

        if not identifier:
            continue

        if asset_type in ("WILDCARD", "URL"):
            parsed_domains.update(expand_identifier(identifier, ALLOWED_TLDS))

    identifiers = sorted(parsed_domains)

    print(identifiers)
    print(f"[OK] Saved {len(identifiers)} scope domains for {program}")

    return identifiers


def scopeDownload() -> None:
    if PROGRAMS_FILE and Path(PROGRAMS_FILE).exists():
        with open(PROGRAMS_FILE, "r", encoding="utf-8") as file:
            programs_list = [line.strip() for line in file if line.strip()]
            print("--> Programs:", programs_list)
    else:
        programs_list = [
            input(
                "No PROGRAMS_FILE found (or PROGRAMS_FILE not set). "
                "Write a single program (ex: hotmartvdp) or cancel and create a programs file:\n"
            ).strip()
        ]
        programs_list = [p for p in programs_list if p]

    if not programs_list:
        print("[!] No programs provided. Exiting.")
        return

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(step="scope_download", meta={"programs_file": PROGRAMS_FILE})

        for program in programs_list:
            print("--> Program:", program)

            domains = scope_download(program)
            if not domains:
                continue

            new_count = repo.upsert_scopes(program=program, domains=domains)
            print(f"[DB] scopes saved. New domains: {new_count}")

        repo.finish_run(run_id)


if __name__ == "__main__":
    scopeDownload()
