from __future__ import annotations

import json
import subprocess
from typing import Iterable

from db.session import get_session
from db.repo import ReconRepo


def chunks(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def normalize_targets(targets: Iterable[str]) -> list[str]:
    out = []
    seen = set()
    for t in targets:
        t = (t or "").strip()
        if not t:
            continue
        if t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def httpx_tech_detect(urls: list[str]) -> list[dict]:
    """
    Uses httpx -tech-detect and returns json rows.
    """
    urls = normalize_targets(urls)
    if not urls:
        return []

    cmd = [
        "httpx",
        "-silent",
        "-json",
        "-follow-redirects",
        "-tech-detect",
    ]

    for u in urls:
        cmd.extend(["-u", u])

    r = subprocess.run(cmd, capture_output=True, text=True)

    if r.returncode != 0:
        err = (r.stderr or "").strip()
        print(f"[FAIL] httpx -tech-detect exited {r.returncode}: {err[:300]}")
        return []

    rows: list[dict] = []
    for line in (r.stdout or "").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def extract_fingerprints(httpx_rows: list[dict], program_id: int | None) -> list[dict]:
    """
    Converts httpx rows into items for repo.upsert_fingerprints()
    """
    items: list[dict] = []

    for row in httpx_rows or []:
        service_url = (row.get("url") or "").strip()
        if not service_url:
            continue

        tech = row.get("tech")

        tech_list: list[str] = []
        if isinstance(tech, list):
            tech_list = [t for t in tech if isinstance(t, str) and t.strip()]
        elif isinstance(tech, str) and tech.strip():
            tech_list = [tech.strip()]

        for t in tech_list:
            items.append(
                {
                    "program_id": program_id,
                    "service_url": service_url,
                    "tech": t,
                    "source": "httpx-tech-detect",
                    "evidence": None,
                }
            )

    return items


def run_fingerprinting(
    program: str | None,
    run_all: bool,
    batch_size: int = 300,
) -> None:
    """
    Fingerprint new services since the last fingerprinting run.
    Program scoping is "soft" for now: we set program_id on fingerprints if program provided,
    but the selection of services is global (filtered by service status_code + first_seen).
    """
    pid: int | None = None
    with get_session() as session:
        repo = ReconRepo(session)
        if program:
            p = repo.get_or_create_program(program)
            pid = p.id

        last_dt = repo.get_last_finished_run_time("fingerprinting")
        targets = repo.list_services_for_fingerprinting(only_new_after=last_dt)

    targets = normalize_targets(targets)
    if not targets:
        print("[OK] No new services to fingerprint.")
        return

    print(f"[+] Fingerprinting {len(targets)} NEW services using httpx -tech-detect...")

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(
            step="fingerprinting",
            meta={
                "input": "db.services",
                "new_only_since": last_dt.isoformat() if last_dt else None,
                "batch_size": batch_size,
                "targets": len(targets),
                "program": program,
            },
        )

        total_rows = 0
        total_new = 0
        failed_batches = 0

        for batch in chunks(targets, batch_size):
            print(f"[+] httpx -tech-detect batch size={len(batch)}")
            rows = httpx_tech_detect(batch)
            if not rows:
                failed_batches += 1
                continue

            total_rows += len(rows)
            items = extract_fingerprints(rows, program_id=pid)
            if items:
                total_new += repo.upsert_fingerprints(items)

        repo.finish_run(run_id)

    print(f"[DB] fingerprinting complete. httpx rows={total_rows} | new fingerprints={total_new}")
    if failed_batches:
        print(f"[WARN] failed/empty batches: {failed_batches}")
