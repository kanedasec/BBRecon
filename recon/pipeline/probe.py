from __future__ import annotations

import json
import subprocess
from typing import Iterable, Optional

from db.session import get_session
from db.repo import ReconRepo


def chunks(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def normalize_targets(targets: Iterable[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    for t in targets:
        t = (t or "").strip().lower().rstrip(".")
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)

    return out


def probe_targets(targets: list[str], threads: int = 200, timeout: int = 5, retries: int = 1) -> list[dict]:
    targets = normalize_targets(targets)
    if not targets:
        print("[PROBE] No targets to probe")
        return []

    print(f"[PROBE] httpx: probing {len(targets)} targets (via stdin -l /dev/stdin)")

    cmd = [
        "httpx",
        "-silent",
        "-json",
        "-include-chain",
        "-follow-redirects",
        "-threads", str(threads),
        "-timeout", str(timeout),
        "-retries", str(retries),
        "-l", "/dev/stdin",
    ]

    stdin_text = "\n".join(targets) + "\n"
    r = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True)

    if r.returncode != 0:
        err = (r.stderr or "").strip()
        print(f"[PROBE][FAIL] httpx exit={r.returncode}: {err[:300]}")
        return []

    results: list[dict] = []
    for line in (r.stdout or "").splitlines():
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    print(f"[PROBE][OK] httpx rows={len(results)}")
    return results


def run_asset_probing(
    program: Optional[str] = None,
    run_all: bool = False,
    batch_size: int = 500,
) -> None:
    """
    Pipeline step:
      - determines which subdomains to probe (new since last run)
      - runs httpx in batches
      - upserts services
    """
    with get_session() as session:
        repo = ReconRepo(session)

        last_probe_time = repo.get_last_finished_run_time("asset_probing")

        # If you want program-scoped probing, use root_domains -> subdomains_for_root_domains
        if program and not run_all:
            root_domains = repo.list_scope_domains(program=program)
            if not root_domains:
                print(f"[PROBE] No scopes found for program={program}. Run scope step first.")
                return

            if last_probe_time is None:
                subdomains = repo.list_subdomains_for_root_domains(root_domains)
            else:
                subdomains = repo.list_subdomains_for_root_domains(root_domains, only_new_after=last_probe_time)
        else:
            if last_probe_time is None:
                subdomains = repo.list_subdomains()
            else:
                subdomains = repo.list_subdomains_first_seen_after(last_probe_time)

    subdomains = normalize_targets(subdomains)

    if not subdomains:
        print("[PROBE] No new subdomains to probe.")
        return

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(
            step="asset_probing",
            meta={
                "input": "db.subdomains",
                "program": program if program and not run_all else None,
                "new_only": True,
                "batch_size": batch_size,
                "target_count": len(subdomains),
            },
        )

        total_new_services = 0
        total_results = 0
        failed_batches = 0

        for batch in chunks(subdomains, batch_size):
            batch_results = probe_targets(batch)
            if not batch_results:
                failed_batches += 1
                continue

            total_results += len(batch_results)
            total_new_services += repo.upsert_services(batch_results, program=program)

        repo.finish_run(run_id)

    print(f"[PROBE][DONE] targets={len(subdomains)} batch_size={batch_size}")
    print(f"[PROBE][DONE] httpx_rows={total_results} new_services={total_new_services} failed_batches={failed_batches}")
