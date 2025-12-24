from __future__ import annotations

import subprocess
from urllib.parse import urlparse
from typing import Iterable

from db.session import get_session
from db.repo import ReconRepo


def chunked(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i:i+size]


def get_host(u: str) -> str:
    try:
        p = urlparse(u)
        return (p.hostname or "").lower()
    except Exception:
        return ""


def run_cmd_capture_lines(
    cmd: list[str],
    stdin_text: str | None = None,
    timeout: int | None = None,
) -> list[str]:
    try:
        r = subprocess.run(
            cmd,
            input=stdin_text,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {' '.join(cmd[:2])} exceeded {timeout}s")
        return []

    if r.returncode != 0:
        err = (r.stderr or "").strip()
        print(f"[FAIL] {' '.join(cmd[:2])} exited {r.returncode}: {err[:200]}")
        return []

    return [line.strip() for line in (r.stdout or "").splitlines() if line.strip()]

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
    return run_cmd_capture_lines(cmd, stdin_text=stdin, timeout=300)


def hakrawler(urls: list[str]) -> list[str]:
    # Hakrawler reads from stdin
    stdin = "\n".join(urls) + "\n"
    return run_cmd_capture_lines(["hakrawler", "-d", "3", "-u", "-dr", "-timeout", "10"], stdin_text=stdin)


def wayback(domains: list[str]) -> list[str]:
    stdin = "\n".join(domains) + "\n"
    return run_cmd_capture_lines(["waybackurls"], stdin_text=stdin)


def gau(domains: list[str]) -> list[str]:
    stdin = "\n".join(domains) + "\n"
    return run_cmd_capture_lines(["gaux", "--blacklist", "png,jpg,gif,css", "--threads", "5"], stdin_text=stdin)


def normalize_urls(lines: Iterable[str]) -> list[str]:
    out = []
    seen = set()
    for u in lines:
        u = u.strip()
        if not u:
            continue
        # basic filter: keep http(s) only
        if not (u.startswith("http://") or u.startswith("https://")):
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


if __name__ == "__main__":
    BATCH_URLS = 10        # crawling tools can be heavy
    BATCH_DOMAINS = 200    # archive tools are lighter

    # 1) Input from DB (status_code 200)
    with get_session() as session:
        repo = ReconRepo(session)
        service_urls = repo.list_service_urls(status_code=200)

    if not service_urls:
        print("[OK] No status_code=200 services to run discovery on.")
        raise SystemExit(0)

    service_urls = sorted(set(service_urls))
    domains = sorted({get_host(u) for u in service_urls if get_host(u)})

    # 2) Start run + store as we go
    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(
            step="content_discovery",
            meta={
                "input": "db.services(status_code=200)",
                "services": len(service_urls),
                "domains": len(domains),
            },
        )

        total_new = 0

        # --- live crawling (katana + hakrawler) ---
        for batch in chunked(service_urls, BATCH_URLS):
            k = normalize_urls(katana(batch))
            h = normalize_urls(hakrawler(batch))

            items = [{"url": u, "source": "katana"} for u in k] + [{"url": u, "source": "hakrawler"} for u in h]
            total_new += repo.upsert_discovered_urls(items)

        # --- passive/archive (wayback + gau) ---
        for batch in chunked(domains, BATCH_DOMAINS):
            w = normalize_urls(wayback(batch))
            g = normalize_urls(gau(batch))

            items = [{"url": u, "source": "waybackurls"} for u in w] + [{"url": u, "source": "gau"} for u in g]
            total_new += repo.upsert_discovered_urls(items)

        repo.finish_run(run_id)

    print(f"[DB] content_discovery complete. New URLs saved: {total_new}")
