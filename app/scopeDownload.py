from __future__ import annotations
from datetime import datetime, timezone
from db.session import get_session
from db.repo import ReconRepo
import requests
import pandas as pd
from io import StringIO
import os
from dotenv import load_dotenv
from pathlib import Path
from typing import List


load_dotenv()

ALLOWED_TLDS = {"com","net","org","io","co","app"}
DOMAINS_LIST = os.getenv("DOMAINS_LIST")
PROGRAMS_FILE = os.getenv("PROGRAMS_FILE")


def expand_identifier(identifier: str, allowed_tlds: set[str]) -> set[str]:
    identifier = identifier.strip().lstrip("*.")

    if identifier.endswith(".*"):
        base = identifier[:-2]
        return {f"{base}.{tld}" for tld in allowed_tlds}

    return {identifier}

def scope_download(program: str) -> List:
    url = f"https://hackerone.com/teams/{program}/assets/download_csv.csv"
    output_file = f"artifacts/{program}_scope.txt"

    try:
        print("Making request to: ", url)
        response = requests.get(url=url)
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
    df = pd.read_csv(StringIO(response.text))

    parsed_domains: set[str] = set()

    for asset_type in ("WILDCARD", "URL"):
        identifiers = (
            df.loc[df["asset_type"] == asset_type, "identifier"]
            .dropna()
            .astype(str)
        )

        for identifier in identifiers:
            parsed_domains.update(
                expand_identifier(identifier, ALLOWED_TLDS)
            )

    identifiers = sorted(parsed_domains)

    print(identifiers)

    print(f"[OK] Saved {len(identifiers)} scope domains for {program}")

    return identifiers

def scopeDownload():
    if Path(PROGRAMS_FILE).exists():
        with open(PROGRAMS_FILE, "r") as file:
            programs_list = [line.strip() for line in file if line.strip()]
            print("--> Programs: ", programs_list)
    else:
        programs_list = [input("No 'programs_list.txt' file found in directory." \
        " Write a single program (ex: hotmartvdp) or cancel and create a program file: \n")]

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(step="scope_download", meta={"programs_file": PROGRAMS_FILE})

        for program in programs_list:
            print("--> Program: ", program)

            domains = scope_download(program)  
            if not domains:
                continue

            new_count = repo.upsert_scopes(program=program, domains=domains)

            with open(DOMAINS_LIST, "a", encoding="utf-8") as f:
                for d in domains:
                    f.write(d + "\n")

            print(f"[DB] scopes saved. New domains: {new_count}")

        repo.finish_run(run_id)

if __name__ == "__main__":
    scopeDownload()