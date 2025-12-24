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
    # normalize + dedupe (prevents wasted args and weird trailing dots)
    out = []
    seen = set()
    for t in targets:
        t = (t or "").strip().lower().rstrip(".")
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


def probe_targets(targets: list[str]) -> list[dict]:
    targets = normalize_targets(targets)
    if not targets:
        print("[!] No targets to probe")
        return []

    print(f"[+] Running HTTPX for {len(targets)} targets (via -u)...")

    cmd = [
        "httpx",
        "-silent",
        "-json",
        "-include-chain",
        "-follow-redirects",
    ]

    for t in targets:
        cmd.extend(["-u", t])

    r = subprocess.run(cmd, capture_output=True, text=True)

    if r.returncode != 0:
        # show some context, but don't crash the whole run
        err = (r.stderr or "").strip()
        print(f"[FAIL] httpx exited with code {r.returncode}: {err[:300]}")
        return []

    results: list[dict] = []
    for line in r.stdout.splitlines():
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    print(f"[+++OK] HTTPX returned {len(results)} results")
    return results


if __name__ == "__main__":
    BATCH_SIZE = 500  # safe default

    # 1) Determine "new subdomains" since last asset_probing run
    with get_session() as session:
        repo = ReconRepo(session)

        last_probe_time = repo.get_last_finished_run_time("asset_probing")
        if last_probe_time is None:
            subdomains = repo.list_subdomains()
        else:
            subdomains = repo.list_subdomains_first_seen_after(last_probe_time)

    subdomains = normalize_targets(subdomains)

    if not subdomains:
        print("[OK] No new subdomains to probe.")
        raise SystemExit(0)

    # 2) Start run + probe in batches + write services as we go
    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(
            step="asset_probing",
            meta={
                "input": "db.subdomains",
                "mode": "httpx -u",
                "new_only": True,
                "batch_size": BATCH_SIZE,
                "target_count": len(subdomains),
            },
        )

        total_new_services = 0
        total_results = 0
        failed_batches = 0

        for batch in chunks(subdomains, BATCH_SIZE):
            batch_results = probe_targets(batch)

            if not batch_results:
                failed_batches += 1
                continue

            total_results += len(batch_results)

            # store this batch immediately (keeps memory low and resilient)
            total_new_services += repo.upsert_services(batch_results)

        repo.finish_run(run_id)

    print(f"[DB] Probed {len(subdomains)} NEW subdomains in batches of {BATCH_SIZE}")
    print(f"[DB] HTTPX rows parsed: {total_results}")
    print(f"[DB] New services saved: {total_new_services}")
    if failed_batches:
        print(f"[WARN] Failed/empty httpx batches: {failed_batches}")
