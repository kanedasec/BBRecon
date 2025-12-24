from __future__ import annotations

import subprocess
import time
from urllib.parse import urlparse
from typing import Iterable, Tuple

from db.session import get_session
from db.repo import ReconRepo


def chunked(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


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
    cmd = [
        "katana",
        "-silent",
        "-d", "2",
        "-c", "10",
        "-timeout", "10",
        "-rate-limit", "50",
    ]
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


def store(repo: ReconRepo, urls: list[str], source: str) -> int:
    items = [{"url": u, "source": source} for u in urls]
    if not items:
        return 0
    return repo.upsert_discovered_urls(items)


if __name__ == "__main__":
    BATCH_URLS = 10        # crawling tools can be heavy
    BATCH_DOMAINS = 200    # archive tools are lighter

    banner("CONTENT DISCOVERY – START")

    # 1) Input from DB (status_code 200)
    with get_session() as session:
        repo = ReconRepo(session)
        service_urls = repo.list_service_urls(status_code=200)

    if not service_urls:
        print("[OK] No status_code=200 services to run discovery on.")
        raise SystemExit(0)

    service_urls = sorted(set(service_urls))
    domains = sorted({get_host(u) for u in service_urls if get_host(u)})

    print(f"[INPUT] services(status_code=200): {len(service_urls)}")
    print(f"[INPUT] unique domains derived from services: {len(domains)}")
    print(f"[CONFIG] BATCH_URLS={BATCH_URLS} | BATCH_DOMAINS={BATCH_DOMAINS}")

    overall_start = now_ms()

    # 2) Start run + store as we go
    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(
            step="content_discovery",
            meta={
                "input": "db.services(status_code=200)",
                "services": len(service_urls),
                "domains": len(domains),
                "batch_urls": BATCH_URLS,
                "batch_domains": BATCH_DOMAINS,
            },
        )

        total_new = 0
        total_katana = 0
        total_hakrawler = 0
        total_wayback = 0
        total_gau = 0

        # --- live crawling (katana + hakrawler) ---
        banner("PHASE 1 – ACTIVE CRAWLING (katana + hakrawler)")
        batches = list(chunked(service_urls, BATCH_URLS))
        for idx, batch in enumerate(batches, start=1):
            print(f"\n[BATCH] Active {idx}/{len(batches)} | urls_in_batch={len(batch)}")

            k_raw = katana(batch)
            h_raw = hakrawler(batch)

            k = normalize_urls(k_raw)
            h = normalize_urls(h_raw)

            print(f"[NORM] katana urls={len(k)} | hakrawler urls={len(h)}")

            added_k = store(repo, k, "katana")
            added_h = store(repo, h, "hakrawler")

            total_katana += len(k)
            total_hakrawler += len(h)
            total_new += (added_k + added_h)

            print(f"[DB] added katana={added_k} | added hakrawler={added_h} | total_new={total_new}")

        # --- passive/archive (wayback + gau) ---
        banner("PHASE 2 – PASSIVE DISCOVERY (waybackurls + gau)")
        batches_d = list(chunked(domains, BATCH_DOMAINS))
        for idx, batch in enumerate(batches_d, start=1):
            print(f"\n[BATCH] Passive {idx}/{len(batches_d)} | domains_in_batch={len(batch)}")

            w_raw = wayback(batch)
            g_raw = gau(batch)

            w = normalize_urls(w_raw)
            g = normalize_urls(g_raw)

            print(f"[NORM] wayback urls={len(w)} | gau urls={len(g)}")

            added_w = store(repo, w, "waybackurls")
            added_g = store(repo, g, "gau")

            total_wayback += len(w)
            total_gau += len(g)
            total_new += (added_w + added_g)

            print(f"[DB] added wayback={added_w} | added gau={added_g} | total_new={total_new}")

        repo.finish_run(run_id)

    dur = ms_to_s(now_ms() - overall_start)
    banner("CONTENT DISCOVERY – DONE")
    print(f"[SUMMARY] duration={dur}s")
    print(f"[SUMMARY] collected: katana={total_katana} | hakrawler={total_hakrawler} | wayback={total_wayback} | gau={total_gau}")
    print(f"[SUMMARY] new URLs saved to DB: {total_new}")
