from __future__ import annotations

import subprocess
import time
from typing import Iterable, Optional
from urllib.parse import urlparse

from db.session import get_session
from db.repo import ReconRepo


def chunked(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def get_host(u: str) -> str:
    try:
        p = urlparse(u)
        return (p.hostname or "").lower()
    except Exception:
        return ""


def now_ms() -> int:
    return int(time.time() * 1000)


def ms_to_s(ms: int) -> float:
    return round(ms / 1000.0, 2)


def banner(title: str) -> None:
    print("\n" + "=" * 90)
    print(title)
    print("=" * 90)


def run_cmd_capture_lines(
    cmd: list[str],
    stdin_text: str | None = None,
    timeout: int | None = None,
    label: str = "",
) -> list[str]:
    start = now_ms()
    pretty = label or " ".join(cmd[:2])

    print(f"[START] {pretty} | timeout={timeout}s")

    try:
        r = subprocess.run(
            cmd,
            input=stdin_text,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        dur = ms_to_s(now_ms() - start)
        print(f"[TIMEOUT] {pretty} exceeded {timeout}s | duration={dur}s")
        return []

    dur = ms_to_s(now_ms() - start)

    if r.returncode != 0:
        err = (r.stderr or "").strip()
        print(f"[FAIL] {pretty} exited {r.returncode} | duration={dur}s | err={err[:200]}")
        return []

    lines = [line.strip() for line in (r.stdout or "").splitlines() if line.strip()]
    print(f"[OK] {pretty} | duration={dur}s | lines={len(lines)}")
    return lines


def katana(urls: list[str]) -> list[str]:
    stdin = "\n".join(urls) + "\n"
    cmd = ["katana", "-silent", "-d", "2", "-c", "10", "-timeout", "10", "-rate-limit", "50"]
    return run_cmd_capture_lines(cmd, stdin_text=stdin, timeout=300, label="katana (active crawl)")


def hakrawler(urls: list[str]) -> list[str]:
    stdin = "\n".join(urls) + "\n"
    cmd = ["hakrawler", "-d", "3", "-u", "-dr", "-timeout", "10"]
    return run_cmd_capture_lines(cmd, stdin_text=stdin, timeout=300, label="hakrawler (active crawl)")


def wayback(domains: list[str]) -> list[str]:
    stdin = "\n".join(domains) + "\n"
    return run_cmd_capture_lines(["waybackurls"], stdin_text=stdin, timeout=300, label="waybackurls (passive)")


def gau(domains: list[str]) -> list[str]:
    stdin = "\n".join(domains) + "\n"
    return run_cmd_capture_lines(
        ["gaux", "--blacklist", "png,jpg,gif,css", "--threads", "5"],
        stdin_text=stdin,
        timeout=300,
        label="gau (passive)",
    )


def normalize_urls(lines: Iterable[str]) -> list[str]:
    out = []
    seen = set()
    for u in lines:
        u = u.strip()
        if not u:
            continue
        if not (u.startswith("http://") or u.startswith("https://")):
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def store(repo: ReconRepo, urls: list[str], source: str, program: str | None = None) -> int:
    items = [{"url": u, "source": source} for u in urls]
    if not items:
        return 0
    return repo.upsert_discovered_urls(items, program=program)



def run_content_discovery(
    program: Optional[str] = None,
    run_all: bool = False,
    batch_urls: int = 10,
    batch_domains: int = 200,
) -> None:
    banner("CONTENT DISCOVERY – START")

    # 1) Input from DB (status_code 200)
    with get_session() as session:
        repo = ReconRepo(session)

        service_urls = repo.list_service_urls(status_code=200)

    if not service_urls:
        print("[CONTENT] No status_code=200 services to run discovery on.")
        return

    service_urls = sorted(set(service_urls))
    domains = sorted({get_host(u) for u in service_urls if get_host(u)})

    print(f"[INPUT] services(status_code=200): {len(service_urls)}")
    print(f"[INPUT] unique domains derived: {len(domains)}")
    print(f"[CONFIG] batch_urls={batch_urls} | batch_domains={batch_domains}")

    overall_start = now_ms()

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(
            step="content_discovery",
            meta={
                "input": "db.services(status_code=200)",
                "services": len(service_urls),
                "domains": len(domains),
                "batch_urls": batch_urls,
                "batch_domains": batch_domains,
                "program": program if program and not run_all else None,
            },
        )

        total_new = 0

        # --- active crawling ---
        banner("PHASE 1 – ACTIVE CRAWLING (katana + hakrawler)")
        batches = list(chunked(service_urls, batch_urls))
        for idx, batch in enumerate(batches, start=1):
            print(f"\n[BATCH] Active {idx}/{len(batches)} | urls_in_batch={len(batch)}")

            k = normalize_urls(katana(batch))
            h = normalize_urls(hakrawler(batch))

            print(f"[NORM] katana={len(k)} | hakrawler={len(h)}")

            added_k = store(repo, k, "katana", program=program)
            added_h = store(repo, h, "hakrawler", program=program)

            total_new += (added_k + added_h)
            print(f"[DB] added katana={added_k} | added hakrawler={added_h} | total_new={total_new}")

        # --- passive discovery ---
        banner("PHASE 2 – PASSIVE DISCOVERY (waybackurls + gau)")
        batches_d = list(chunked(domains, batch_domains))
        for idx, batch in enumerate(batches_d, start=1):
            print(f"\n[BATCH] Passive {idx}/{len(batches_d)} | domains_in_batch={len(batch)}")

            w = normalize_urls(wayback(batch))
            g = normalize_urls(gau(batch))

            print(f"[NORM] wayback={len(w)} | gau={len(g)}")

            added_w = store(repo, w, "waybackurls", program=program)
            added_g = store(repo, g, "gau", program=program)

            total_new += (added_w + added_g)
            print(f"[DB] added wayback={added_w} | added gau={added_g} | total_new={total_new}")

        repo.finish_run(run_id)

    dur = ms_to_s(now_ms() - overall_start)
    banner("CONTENT DISCOVERY – DONE")
    print(f"[SUMMARY] duration={dur}s | new_urls_saved={total_new}")
