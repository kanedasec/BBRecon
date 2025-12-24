from __future__ import annotations

from typing import Optional

from db.session import get_session
from db.repo import ReconRepo

from app.contentDiscovery import (
    get_host,
    chunked,
    normalize_urls,
    katana,
    hakrawler,
    wayback,
    gau,
)


def run_content_discovery(program: Optional[str] = None, run_all: bool = False) -> None:
    """
    Content discovery:
    - active crawling on status_code=200 services
    - passive discovery via archives
    Program-scoped best-effort:
    - If program specified, only consider services whose fqdn matches subdomains under that program's scope roots.
    """
    BATCH_URLS = 10
    BATCH_DOMAINS = 200

    with get_session() as session:
        repo = ReconRepo(session)

        if program and not run_all:
            scope_domains = repo.list_scope_domains(program=program)
            if not scope_domains:
                print(f"[!] No scope domains for program={program}. Run scope first.")
                return

            # services by joining via fqdn in subdomains under those roots (best-effort)
            service_urls = repo.list_service_urls_scoped(scope_domains=scope_domains, status_code=200)
            meta = {"input": f"db.services(program={program}, status_code=200)", "program": program, "services": len(service_urls)}
        else:
            service_urls = repo.list_service_urls(status_code=200)
            meta = {"input": "db.services(all, status_code=200)", "program": None, "services": len(service_urls)}

    if not service_urls:
        print("[OK] No status_code=200 services to run discovery on.")
        return

    service_urls = sorted(set(service_urls))
    domains = sorted({get_host(u) for u in service_urls if get_host(u)})

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(step="content_discovery", meta={**meta, "domains": len(domains)})

        total_new = 0

        for batch in chunked(service_urls, BATCH_URLS):
            k = normalize_urls(katana(batch))
            h = normalize_urls(hakrawler(batch))
            items = [{"url": u, "source": "katana"} for u in k] + [{"url": u, "source": "hakrawler"} for u in h]
            total_new += repo.upsert_discovered_urls(items)

        for batch in chunked(domains, BATCH_DOMAINS):
            w = normalize_urls(wayback(batch))
            g = normalize_urls(gau(batch))
            items = [{"url": u, "source": "waybackurls"} for u in w] + [{"url": u, "source": "gau"} for u in g]
            total_new += repo.upsert_discovered_urls(items)

        repo.finish_run(run_id)

    print(f"[DB] content_discovery complete. New URLs saved: {total_new}")
