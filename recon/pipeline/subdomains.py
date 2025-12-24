from __future__ import annotations

import json
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from tempfile import NamedTemporaryFile
from typing import Dict, Optional, Sequence, Set, Tuple

from dotenv import load_dotenv

from db.session import get_session
from db.repo import ReconRepo

load_dotenv()

CHAOS_API_KEY = os.getenv("CHAOS_API")
RESOLVERS = os.getenv("RESOLVERS_LIST")
ARTIFACTS_DIR = os.getenv("ARTIFACTS_DIR", "artifacts")


def _pipeline_one_root(domain: str) -> Tuple[str, int, str, str]:
    outputs: list[str] = []
    errors: list[str] = []

    print(f"[SUBDOMAINS] subfinder: {domain}")
    r1 = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    outputs.append(r1.stdout or "")
    errors.append(r1.stderr or "")
    if r1.returncode != 0:
        return domain, r1.returncode, "", (r1.stderr or "")

    print(f"[SUBDOMAINS] assetfinder: {domain}")
    r2 = subprocess.run(["assetfinder", "--subs-only", domain], capture_output=True, text=True)
    outputs.append(r2.stdout or "")
    errors.append(r2.stderr or "")
    if r2.returncode != 0:
        return domain, r2.returncode, "", (r2.stderr or "")

    print(f"[SUBDOMAINS] chaos: {domain}")
    r3 = subprocess.run(["chaos", "-d", domain, "-key", CHAOS_API_KEY, "-silent"], capture_output=True, text=True)
    outputs.append(r3.stdout or "")
    errors.append(r3.stderr or "")
    if r3.returncode != 0:
        return domain, r3.returncode, "", (r3.stderr or "")

    combined_out = "".join(outputs)
    combined_err = "".join(e for e in errors if e)

    return domain, 0, combined_out, combined_err


def _collect_candidates(domains: list[str], max_parallel: int) -> Dict[str, Set[str]]:
    candidates_by_root: Dict[str, Set[str]] = {}

    with ThreadPoolExecutor(max_workers=max_parallel) as ex:
        futures = [ex.submit(_pipeline_one_root, d) for d in domains]

        for fut in as_completed(futures):
            root_domain, code, out, err = fut.result()

            if code == 0 and out:
                bucket = candidates_by_root.setdefault(root_domain, set())
                before = len(bucket)
                for line in out.splitlines():
                    s = line.strip().lower().rstrip(".")
                    if s:
                        bucket.add(s)
                after = len(bucket)
                print(f"[SUBDOMAINS][OK] {root_domain}: +{after - before} (deduped={after})")
            else:
                print(f"[SUBDOMAINS][FAIL] {root_domain}: {(err or '').strip()[:200]}")

    return candidates_by_root


def _massdns_resolve(subdomains: Set[str]) -> Set[str]:
    if not subdomains:
        return set()

    if not RESOLVERS or not os.path.exists(RESOLVERS):
        raise FileNotFoundError(f"RESOLVERS_LIST file not found: {RESOLVERS}")

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    out_json_path = os.path.join(ARTIFACTS_DIR, "massdns_out.json")

    with NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as tmp:
        for s in sorted(subdomains):
            tmp.write(s + "\n")
        tmp_path = tmp.name

    print(f"[SUBDOMAINS] massdns: resolving {len(subdomains)} candidates...")
    subprocess.run(
        ["massdns", "-r", RESOLVERS, "-t", "A", "-o", "J", "--flush", "-w", out_json_path, tmp_path],
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )

    try:
        os.remove(tmp_path)
    except OSError:
        pass

    resolved: set[str] = set()
    with open(out_json_path, "r", encoding="utf-8") as infile:
        for line in infile:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            if entry.get("status") == "NOERROR":
                dns = (entry.get("name") or "").rstrip(".").lower()
                if dns:
                    resolved.add(dns)

    # optional cleanup (you were deleting it)
    try:
        os.remove(out_json_path)
    except OSError:
        pass

    print(f"[SUBDOMAINS] massdns: resolved={len(resolved)}")
    return resolved


def run_subdomain_enum(
    program: Optional[str] = None,
    run_all: bool = False,
    max_parallel: int = 5,
) -> None:
    """
    Pipeline step:
      - Reads scope roots from DB (optionally filtered by program)
      - Runs subfinder/assetfinder/chaos + massdns
      - Upserts Subdomain with root_domain (+ program if provided)
    """
    with get_session() as session:
        repo = ReconRepo(session)

        if program and not run_all:
            roots = repo.list_scope_domains(program=program)
        else:
            roots = repo.list_scope_domains()

    if not roots:
        print("[SUBDOMAINS] No scope domains found. Run scope step first.")
        return

    print(f"[SUBDOMAINS] Enumerating roots={len(roots)} max_parallel={max_parallel}")

    candidates_by_root = _collect_candidates(roots, max_parallel=max_parallel)
    total_candidates = sum(len(v) for v in candidates_by_root.values())
    print(f"[SUBDOMAINS] Candidates collected (pre-DNS): {total_candidates}")

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(
            step="subdomain_enum",
            meta={
                "input": "db.scopes",
                "program": program if program and not run_all else None,
                "roots": len(roots),
                "max_parallel": max_parallel,
            },
        )

        total_new = 0
        total_resolved = 0

        for root_domain, candidates in candidates_by_root.items():
            resolved = _massdns_resolve(candidates)
            total_resolved += len(resolved)

            # program tag is optional: if you pass program, repo can store program_id (Option A stuff)
            new_here = repo.upsert_subdomains(resolved, root_domain=root_domain, program=program if program and not run_all else None)
            total_new += new_here

            print(f"[SUBDOMAINS][DB] {root_domain}: resolved={len(resolved)} new={new_here}")

        repo.finish_run(run_id)

    print(f"[SUBDOMAINS][DONE] resolved_total={total_resolved} new_total={total_new}")
