from __future__ import annotations

import os
import subprocess
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from tempfile import NamedTemporaryFile
from typing import Dict, Tuple, Set

from db.session import get_session
from db.repo import ReconRepo

from dotenv import load_dotenv


load_dotenv()

CHAOS_API_KEY = os.getenv("CHAOS_API")
RESOLVERS = os.getenv("RESOLVERS_LIST")
ARTIFACTS_DIR = os.getenv("ARTIFACTS_DIR", "artifacts")


def read_domains_from_db() -> list[str]:
    with get_session() as session:
        repo = ReconRepo(session)
        return repo.list_scope_domains()


def pipeline(domain: str) -> Tuple[str, int, str, str]:
    outputs: list[str] = []
    errors: list[str] = []

    print(f"[+] Running Subfinder for: {domain}...")
    r1 = subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True)
    outputs.append(r1.stdout)
    errors.append(r1.stderr)
    if r1.returncode != 0:
        return domain, r1.returncode, "", r1.stderr
    print(f"[+++OK] Subfinder for: {domain}!")

    print(f"[+] Running Assetfinder for: {domain}...")
    r2 = subprocess.run(["assetfinder", "--subs-only", domain], capture_output=True, text=True)
    outputs.append(r2.stdout)
    errors.append(r2.stderr)
    if r2.returncode != 0:
        return domain, r2.returncode, "", r2.stderr
    print(f"[+++OK] Assetfinder for: {domain}!")

    print(f"[+] Running Chaos for: {domain}...")
    r3 = subprocess.run(["chaos", "-d", domain, "-key", CHAOS_API_KEY, "-silent"], capture_output=True, text=True)
    outputs.append(r3.stdout)
    errors.append(r3.stderr)
    if r3.returncode != 0:
        return domain, r3.returncode, "", r3.stderr
    print(f"[+++OK] Chaos for: {domain}!")

    combined_out = "".join(outputs)
    combined_err = "".join(e for e in errors if e)

    return domain, 0, combined_out, combined_err


def collect_subdomains_by_root(domains: list[str], max_parallel: int) -> Dict[str, Set[str]]:
    """
    Returns mapping: root_domain -> candidate subdomains (pre-DNS validation)
    """
    candidates_by_root: Dict[str, Set[str]] = {}

    with ThreadPoolExecutor(max_workers=max_parallel) as ex:
        futures = [ex.submit(pipeline, d) for d in domains]

        for fut in as_completed(futures):
            root_domain, code, out, err = fut.result()

            if code == 0 and out:
                bucket = candidates_by_root.setdefault(root_domain, set())
                count = 0
                for line in out.splitlines():
                    s = line.strip().lower().rstrip(".")
                    if s:
                        bucket.add(s)
                        count += 1
                print(f"[OK] {root_domain} -> +{count} lines (deduped: {len(bucket)})")
            else:
                print(f"[FAIL] {root_domain}: {err.strip()}")

    return candidates_by_root


def check_dns_with_massdns(subdomains: Set[str]) -> Set[str]:
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

    print(f"[+] Running massdns for {len(subdomains)} candidates...")
    subprocess.run(
        ["massdns", "-r", RESOLVERS, "-t", "A", "-o", "J", "--flush", "-w", out_json_path, tmp_path],
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    print("[+++OK] Massdns finished!")

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

    print("[+] Cleaning temporary files: ")
    os.remove(out_json_path)

    return resolved


def subdomainEnum(max_parallel: int = 5) -> None:
    domains = read_domains_from_db()
    if not domains:
        print("[!] No scope domains found in DB. Run scopeDownload first.")
        return

    print(f"[+] Enumerating subdomains for {len(domains)} scope domains (DB input)...")

    candidates_by_root = collect_subdomains_by_root(domains, max_parallel=max_parallel)
    total_candidates = sum(len(v) for v in candidates_by_root.values())
    print(f"[+] Candidate subdomains collected (pre-DNS): {total_candidates}")

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(step="subdomain_enum", meta={"input": "db.scopes", "domains_count": len(domains)})

        total_new = 0
        total_resolved = 0

        for root_domain, candidates in candidates_by_root.items():
            resolved = check_dns_with_massdns(candidates)
            total_resolved += len(resolved)

            # ✅ Here is the key: upsert with root_domain set
            total_new += repo.upsert_subdomains(resolved, root_domain=root_domain)

            print(f"[+] {root_domain}: resolved={len(resolved)} new={total_new}")

        repo.finish_run(run_id)

    print(f"[DB] subdomains saved. Total resolved: {total_resolved} | Total NEW subdomains: {total_new}")


if __name__ == "__main__":
    subdomainEnum(max_parallel=5)
