from __future__ import annotations

from typing import Optional

from db.session import get_session
from db.repo import ReconRepo

from app.subdomainEnum import collect_subdomains_by_root, check_dns_with_massdns


def run_subdomain_enum(program: Optional[str] = None, run_all: bool = False, max_parallel: int = 5) -> None:
    """
    Enumerate subdomains for scope domains from DB.
    - If program is provided: runs only that program
    - If run_all=True or program is None: runs across ALL scope domains (global)
    """
    with get_session() as session:
        repo = ReconRepo(session)

        if program and not run_all:
            domains = repo.list_scope_domains(program=program)
            meta = {"input": f"db.scopes(program={program})", "domains_count": len(domains), "program": program}
        else:
            domains = repo.list_scope_domains()
            meta = {"input": "db.scopes(all)", "domains_count": len(domains), "program": None}

    if not domains:
        print("[!] No scope domains found in DB. Run scope step first.")
        return

    print(f"[+] Enumerating subdomains for {len(domains)} scope domains...")

    candidates_by_root = collect_subdomains_by_root(domains, max_parallel=max_parallel)
    total_candidates = sum(len(v) for v in candidates_by_root.values())
    print(f"[+] Candidate subdomains collected (pre-DNS): {total_candidates}")

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(step="subdomain_enum", meta=meta)

        total_new = 0
        total_resolved = 0

        for root_domain, candidates in candidates_by_root.items():
            resolved = check_dns_with_massdns(candidates)
            total_resolved += len(resolved)
            total_new += repo.upsert_subdomains(resolved, root_domain=root_domain)

            print(f"[+] {root_domain}: resolved={len(resolved)} total_new_so_far={total_new}")

        repo.finish_run(run_id)

    print(f"[DB] subdomains saved. Total resolved: {total_resolved} | Total NEW subdomains: {total_new}")
