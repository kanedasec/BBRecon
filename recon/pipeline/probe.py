from __future__ import annotations

from typing import Optional

from db.session import get_session
from db.repo import ReconRepo

from app.assetProbing import probe_targets, chunks, normalize_targets


def run_asset_probing(program: Optional[str] = None, run_all: bool = False, batch_size: int = 500) -> None:
    """
    Probe services with httpx.
    - If program is provided: probes subdomains whose root_domain matches that program's scopes
      (best-effort scoping with current schema)
    - Else: current global behavior (new-only since last run)
    """
    with get_session() as session:
        repo = ReconRepo(session)

        last_probe_time = repo.get_last_finished_run_time("asset_probing")

        if program and not run_all:
            # Best-effort scoping: get program scope domains, then subdomains by root_domain
            scope_domains = repo.list_scope_domains(program=program)
            if not scope_domains:
                print(f"[!] No scope domains for program={program}. Run scope first.")
                return

            # Pull subdomains per root_domain in scope
            subdomains = repo.list_subdomains_for_root_domains(scope_domains, only_new_after=last_probe_time)
            meta = {"input": f"db.subdomains(program={program})", "program": program, "new_only": True, "batch_size": batch_size}
        else:
            # Global mode
            if last_probe_time is None:
                subdomains = repo.list_subdomains()
            else:
                subdomains = repo.list_subdomains_first_seen_after(last_probe_time)

            meta = {"input": "db.subdomains(all)", "program": None, "new_only": True, "batch_size": batch_size}

    subdomains = normalize_targets(subdomains)

    if not subdomains:
        print("[OK] No new subdomains to probe.")
        return

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(step="asset_probing", meta={**meta, "target_count": len(subdomains)})

        total_new_services = 0
        total_results = 0
        failed_batches = 0

        for batch in chunks(subdomains, batch_size):
            batch_results = probe_targets(batch)
            if not batch_results:
                failed_batches += 1
                continue

            total_results += len(batch_results)
            total_new_services += repo.upsert_services(batch_results)

        repo.finish_run(run_id)

    print(f"[DB] Probed {len(subdomains)} NEW subdomains in batches of {batch_size}")
    print(f"[DB] HTTPX rows parsed: {total_results}")
    print(f"[DB] New services saved: {total_new_services}")
    if failed_batches:
        print(f"[WARN] Failed/empty httpx batches: {failed_batches}")
