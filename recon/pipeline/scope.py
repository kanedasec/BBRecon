from __future__ import annotations

from pathlib import Path
from typing import Optional

import os
from dotenv import load_dotenv

from db.session import get_session
from db.repo import ReconRepo
from app.scopeDownload import scope_download

load_dotenv()

PROGRAMS_FILE = os.getenv("PROGRAMS_FILE")


def _read_programs_file(path: str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_scope_download(
    program: Optional[str] = None,
    run_all: bool = False,
    interactive: bool = False,
) -> None:
    """
    Non-interactive by default.

    - If program is provided: runs only for that program
    - Else if run_all=True: requires PROGRAMS_FILE to exist (no prompting unless interactive=True)
    """
    # Single program path (never interactive)
    if program and not run_all:
        domains = scope_download(program)
        if not domains:
            print(f"[!] No domains downloaded for program={program}")
            return

        with get_session() as session:
            repo = ReconRepo(session)
            run_id = repo.start_run(step="scope_download", meta={"program": program, "mode": "single"})
            new_count = repo.upsert_scopes(program=program, domains=domains)
            repo.finish_run(run_id)

        print(f"[OK] program={program} scope saved. New domains: {new_count}")
        return

    # All programs path
    if not PROGRAMS_FILE:
        raise RuntimeError("PROGRAMS_FILE is not set in .env. Example: PROGRAMS_FILE=programs_list.txt")

    programs = _read_programs_file(PROGRAMS_FILE)

    if not programs:
        if interactive:
            # explicit opt-in only
            p = input("No programs file found or it's empty. Enter a single HackerOne team name: ").strip()
            programs = [p] if p else []
        else:
            raise RuntimeError(
                f"PROGRAMS_FILE not found or empty: {PROGRAMS_FILE}. "
                f"Create it with one program per line, or run with --program <name>."
            )

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(step="scope_download", meta={"programs_file": PROGRAMS_FILE, "mode": "file"})

        total_new = 0
        for prog in programs:
            print("--> Program:", prog)
            domains = scope_download(prog)
            if not domains:
                continue
            total_new += repo.upsert_scopes(program=prog, domains=domains)

        repo.finish_run(run_id)

    print(f"[OK] scope_download finished. Programs={len(programs)} | Total new domains={total_new}")
