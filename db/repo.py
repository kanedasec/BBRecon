from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from typing import Iterable, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from .models import (
    Run,
    Program,
    ScopeDomain,
    Subdomain,
    Service,
    DiscoveredURL,
    Fingerprint,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_domain(s: str) -> str:
    s = (s or "").strip().lower()
    return s.rstrip(".")


class ReconRepo:
    def __init__(self, session):
        self.session = session

    # ----------------------
    # Internal helpers
    # ----------------------
    def _program_id(self, program: str | None) -> int | None:
        """
        Read-only lookup. Does NOT create programs.
        """
        if not program:
            return None

        name = normalize_domain(program)

        p = self.session.execute(
            select(Program).where(Program.name == name)
        ).scalar_one_or_none()

        return p.id if p else None

    # ----------------------
    # Runs
    # ----------------------
    def start_run(self, step: str, meta: Optional[dict] = None) -> int:
        r = Run(step=step, meta_json=json.dumps(meta or {}, ensure_ascii=False))
        self.session.add(r)
        self.session.flush()
        return r.id

    def finish_run(self, run_id: int) -> None:
        r = self.session.get(Run, run_id)
        if r:
            r.finished_at = utcnow()
            self.session.add(r)

    # ----------------------
    # Programs
    # ----------------------
    def get_or_create_program(self, name: str, platform: str = "hackerone") -> Program:
        name = normalize_domain(name)
        existing = self.session.execute(
            select(Program).where(Program.name == name)
        ).scalar_one_or_none()
        if existing:
            return existing

        p = Program(name=name, platform=platform)
        self.session.add(p)
        self.session.flush()
        return p

    # ----------------------
    # Scopes
    # ----------------------
    def upsert_scopes(self, program: str, domains: Sequence[str]) -> int:
        now = utcnow()
        p = self.get_or_create_program(program)

        cleaned = [normalize_domain(d) for d in domains if normalize_domain(d)]
        cleaned = sorted(set(cleaned))
        if not cleaned:
            return 0

        existing_rows = self.session.execute(
            select(ScopeDomain.domain).where(
                ScopeDomain.program_id == p.id,
                ScopeDomain.domain.in_(cleaned),
            )
        ).scalars().all()
        existing_set = set(existing_rows)

        new_items = [d for d in cleaned if d not in existing_set]
        for d in new_items:
            self.session.add(
                ScopeDomain(
                    program_id=p.id,
                    domain=d,
                    first_seen=now,
                    last_seen=now,
                )
            )

        # touch last_seen for all seen this run
        rows = self.session.execute(
            select(ScopeDomain).where(
                ScopeDomain.program_id == p.id,
                ScopeDomain.domain.in_(cleaned),
            )
        ).scalars().all()
        for row in rows:
            row.last_seen = now
            self.session.add(row)

        return len(new_items)

    def list_scope_domains(self, program: str | None = None) -> list[str]:
        q = select(ScopeDomain.domain)

        if program:
            # ✅ normalize + lookup by normalized name
            pid = self._program_id(program)
            if pid is None:
                return []
            q = q.where(ScopeDomain.program_id == pid)

        rows = self.session.execute(q).scalars().all()
        return sorted(set(rows))

    # ----------------------
    # Subdomains
    # ----------------------
    def upsert_subdomains(
        self,
        subdomains: Iterable[str],
        root_domain: str | None = None,
        program: str | None = None,
    ) -> int:
        now = utcnow()

        cleaned = [normalize_domain(s) for s in subdomains if normalize_domain(s)]
        cleaned = sorted(set(cleaned))
        if not cleaned:
            return 0

        pid: int | None = None
        if program:
            p = self.get_or_create_program(program)
            pid = p.id

        existing_rows = self.session.execute(
            select(Subdomain.fqdn).where(Subdomain.fqdn.in_(cleaned))
        ).scalars().all()
        existing_set = set(existing_rows)

        new_items = [fqdn for fqdn in cleaned if fqdn not in existing_set]
        new_count = 0

        # Insert new
        for fqdn in new_items:
            try:
                self.session.add(
                    Subdomain(
                        program_id=pid,
                        fqdn=fqdn,
                        root_domain=normalize_domain(root_domain) if root_domain else None,
                        first_seen=now,
                        last_seen=now,
                    )
                )
                self.session.flush()
                new_count += 1

            except IntegrityError:
                # someone else inserted / or stale existing_set
                self.session.rollback()

                row = self.session.execute(
                    select(Subdomain).where(Subdomain.fqdn == fqdn)
                ).scalar_one()

                row.last_seen = now
                if root_domain and not row.root_domain:
                    row.root_domain = normalize_domain(root_domain)
                if pid is not None and row.program_id is None:
                    row.program_id = pid

                self.session.add(row)
                self.session.flush()

        # Touch all seen
        rows = self.session.execute(
            select(Subdomain).where(Subdomain.fqdn.in_(cleaned))
        ).scalars().all()

        for row in rows:
            row.last_seen = now
            if root_domain and not row.root_domain:
                row.root_domain = normalize_domain(root_domain)
            if pid is not None and row.program_id is None:
                row.program_id = pid
            self.session.add(row)

        return new_count

    def list_subdomains(self, root_domain=None, only_recent_days=None):
        q = select(Subdomain.fqdn, Subdomain.last_seen)
        if root_domain:
            q = q.where(Subdomain.root_domain == root_domain)

        rows = self.session.execute(q).all()

        if only_recent_days is not None:
            cutoff = utcnow() - timedelta(days=int(only_recent_days))
            rows = [r for r in rows if r.last_seen and r.last_seen >= cutoff]

        return sorted(set(r.fqdn for r in rows))

    def list_subdomains_for_root_domains(
        self,
        root_domains: Sequence[str],
        only_new_after: datetime | None = None,
    ) -> list[str]:
        roots = sorted({normalize_domain(d) for d in (root_domains or []) if normalize_domain(d)})
        if not roots:
            return []

        q = select(Subdomain.fqdn).where(Subdomain.root_domain.in_(roots))
        if only_new_after is not None:
            q = q.where(Subdomain.first_seen > only_new_after)

        rows = self.session.execute(q).scalars().all()
        return sorted(set(rows))

    def get_last_finished_run_time(self, step: str) -> datetime | None:
        row = self.session.execute(
            select(Run)
            .where(Run.step == step)
            .where(Run.finished_at.is_not(None))
            .order_by(Run.finished_at.desc())
            .limit(1)
        ).scalar_one_or_none()

        return row.finished_at if row else None

    def list_subdomains_first_seen_after(self, dt: datetime) -> list[str]:
        rows = self.session.execute(
            select(Subdomain.fqdn).where(Subdomain.first_seen > dt)
        ).scalars().all()
        return sorted(set(rows))

    def list_new_subdomains_since(self, dt: datetime, root_domains: list[str] | None = None) -> list[str]:
        q = select(Subdomain.fqdn).where(Subdomain.first_seen > dt)
        if root_domains:
            q = q.where(Subdomain.root_domain.in_(root_domains))
        rows = self.session.execute(q).scalars().all()
        return sorted(set(rows))

    # ----------------------
    # Services (httpx)
    # ----------------------
    def upsert_services(self, httpx_results: Sequence[dict], program: str | None = None) -> int:
        now = utcnow()

        pid: int | None = None
        if program:
            p = self.get_or_create_program(program)
            pid = p.id

        normalized: list[dict] = []
        for r in httpx_results or []:
            url = str(r.get("url", "")).strip()
            if not url:
                continue
            normalized.append(r)

        if not normalized:
            return 0

        urls = sorted({str(r.get("url", "")).strip() for r in normalized if r.get("url")})
        existing_rows = self.session.execute(
            select(Service.url).where(Service.url.in_(urls))
        ).scalars().all()
        existing_set = set(existing_rows)

        new_count = 0

        for r in normalized:
            url = str(r.get("url", "")).strip()
            if not url:
                continue

            if url not in existing_set:
                svc = Service(
                    program_id=pid,
                    url=url,
                    fqdn=normalize_domain(str(r.get("input") or r.get("host") or "")) or None,
                    scheme=r.get("scheme"),
                    host=r.get("host"),
                    port=str(r.get("port")) if r.get("port") is not None else None,
                    title=r.get("title"),
                    webserver=r.get("webserver"),
                    content_type=r.get("content_type"),
                    status_code=int(r["status_code"])
                    if "status_code" in r and str(r["status_code"]).isdigit()
                    else None,
                    ip=r.get("host_ip"),
                    first_seen=now,
                    last_seen=now,
                )
                self.session.add(svc)
                new_count += 1
            else:
                svc = self.session.execute(select(Service).where(Service.url == url)).scalar_one()
                svc.last_seen = now
                svc.title = r.get("title") or svc.title
                svc.webserver = r.get("webserver") or svc.webserver
                svc.content_type = r.get("content_type") or svc.content_type
                svc.ip = r.get("host_ip") or svc.ip

                # backfill program_id if missing
                if pid is not None and svc.program_id is None:
                    svc.program_id = pid

                self.session.add(svc)

        return new_count

    def list_service_urls(
        self,
        status_code: int | None = 200,
        program: str | None = None,
    ) -> list[str]:
        """
        Returns service URLs filtered by status_code and optional program.
        If status_code is None, returns all URLs.
        """
        q = select(Service.url)

        if status_code is not None:
            q = q.where(Service.status_code == status_code)

        if program is not None:
            pid = self._program_id(program)
            if pid is None:
                return []
            q = q.where(Service.program_id == pid)

        rows = self.session.execute(q).scalars().all()
        return sorted(set(rows))

    def list_new_services_since(
        self,
        dt: datetime,
        fqdn_list: list[str] | None = None,
        program: str | None = None,
    ) -> list[tuple[str, int | None]]:
        q = select(Service.url, Service.status_code).where(Service.first_seen > dt)

        if fqdn_list:
            q = q.where(Service.fqdn.in_(fqdn_list))

        if program is not None:
            pid = self._program_id(program)
            if pid is None:
                return []
            q = q.where(Service.program_id == pid)

        rows = self.session.execute(q).all()
        return sorted(set(rows))

    def list_service_hosts_by_status(
        self,
        status_codes: list[int],
        program: str | None = None,
    ) -> list[str]:
        """
        Returns distinct Service.fqdn (hosts) where status_code is in status_codes.
        If program is provided, filters by Service.program_id.
        """
        if not status_codes:
            return []

        q = select(Service.fqdn).where(Service.fqdn.is_not(None))
        q = q.where(Service.status_code.in_(status_codes))

        if program is not None:
            pid = self._program_id(program)
            if pid is None:
                return []
            q = q.where(Service.program_id == pid)

        rows = self.session.execute(q).scalars().all()
        return sorted({normalize_domain(r) for r in rows if r})

    def list_all_service_hosts(self, program: str | None = None) -> list[str]:
        """
        Returns distinct Service.fqdn for all services (optionally by program).
        """
        q = select(Service.fqdn).where(Service.fqdn.is_not(None))

        if program is not None:
            pid = self._program_id(program)
            if pid is None:
                return []
            q = q.where(Service.program_id == pid)

        rows = self.session.execute(q).scalars().all()
        return sorted({normalize_domain(r) for r in rows if r})

    def list_service_host_triples_by_status(
        self,
        status_codes: Sequence[int],
        program: str | None = None,
    ) -> list[tuple[str, int, str]]:
        """
        Returns distinct (fqdn, port, scheme) for services matching status_codes,
        optionally filtered by program.
        Output is normalized for Burp scope generation:
          - scheme: http/https (fallback https)
          - port: int (fallback 80/443 based on scheme)
        """
        if not status_codes:
            return []

        q = select(Service.fqdn, Service.port, Service.scheme).where(Service.fqdn.is_not(None))
        q = q.where(Service.status_code.in_(list(status_codes)))

        if program is not None:
            pid = self._program_id(program)
            if pid is None:
                return []
            q = q.where(Service.program_id == pid)

        rows = self.session.execute(q).all()

        out: set[tuple[str, int, str]] = set()
        for fqdn, port, scheme in rows:
            host = normalize_domain(fqdn or "")
            if not host:
                continue

            sch = (scheme or "").lower()
            if sch not in ("http", "https"):
                sch = "https"

            p = 443 if sch == "https" else 80
            if port and str(port).isdigit():
                p = int(port)

            out.add((host, p, sch))

        return sorted(out)

    # ----------------------
    # Fingerprinting
    # ----------------------
    def list_services_for_fingerprinting(
        self,
        only_new_after: datetime | None = None,
        status_codes: Sequence[int] = (200, 301, 302, 401, 403),
        program: str | None = None,
    ) -> list[str]:
        q = select(Service.url).where(Service.status_code.in_(list(status_codes)))

        if only_new_after is not None:
            q = q.where(Service.first_seen > only_new_after)

        if program is not None:
            pid = self._program_id(program)
            if pid is None:
                return []
            q = q.where(Service.program_id == pid)

        rows = self.session.execute(q).scalars().all()
        return sorted(set(rows))

    def list_new_fingerprints_since(
        self,
        dt: datetime,
        service_urls: list[str] | None = None,
    ) -> list[tuple[str, str]]:
        q = select(Fingerprint.service_url, Fingerprint.tech).where(Fingerprint.first_seen > dt)

        if service_urls:
            q = q.where(Fingerprint.service_url.in_(service_urls))

        rows = self.session.execute(q).all()
        return sorted(set(rows))

    def list_all_fingerprints(self) -> list[tuple[str, str]]:
        rows = self.session.execute(select(Fingerprint.service_url, Fingerprint.tech)).all()
        return sorted(set(rows))

    def upsert_fingerprints(self, items: list[dict]) -> int:
        """
        items: [{"service_url": "...", "tech": "nginx", "source":"httpx-tech-detect", "evidence": None, "program_id": pid}]
        Unique: (service_url, tech)
        """
        now = utcnow()
        new_count = 0

        for it in items or []:
            service_url = (it.get("service_url") or "").strip()
            tech = (it.get("tech") or "").strip().lower()
            if not service_url or not tech:
                continue

            pid = it.get("program_id")
            pid = int(pid) if isinstance(pid, int) or (isinstance(pid, str) and str(pid).isdigit()) else None

            try:
                self.session.add(
                    Fingerprint(
                        program_id=pid,
                        service_url=service_url,
                        tech=tech,
                        source=it.get("source"),
                        evidence=it.get("evidence"),
                        first_seen=now,
                        last_seen=now,
                    )
                )
                self.session.flush()
                new_count += 1

            except IntegrityError:
                self.session.rollback()

                row = self.session.execute(
                    select(Fingerprint).where(
                        Fingerprint.service_url == service_url,
                        Fingerprint.tech == tech,
                    )
                ).scalar_one()

                row.last_seen = now
                if it.get("source") and not row.source:
                    row.source = it["source"]
                if it.get("evidence") and not row.evidence:
                    row.evidence = it["evidence"]
                if pid is not None and row.program_id is None:
                    row.program_id = pid

                self.session.add(row)
                self.session.flush()

        return new_count

    # ----------------------
    # Discovered URLs
    # ----------------------
    def upsert_discovered_urls(self, items: list[dict], program: str | None = None) -> int:
        now = utcnow()

        pid: int | None = None
        if program:
            p = self.get_or_create_program(program)
            pid = p.id

        normalized_items: list[dict] = []
        seen = set()
        for it in items or []:
            u = (it.get("url") or "").strip()
            if not u:
                continue
            if u in seen:
                continue
            seen.add(u)
            normalized_items.append(
                {
                    "url": u,
                    "source": it.get("source"),
                    "service_url": it.get("service_url"),
                }
            )

        if not normalized_items:
            return 0

        urls = [it["url"] for it in normalized_items]

        existing_rows = self.session.execute(
            select(DiscoveredURL).where(DiscoveredURL.url.in_(urls))
        ).scalars().all()
        existing_map = {row.url: row for row in existing_rows}

        new_count = 0

        for it in normalized_items:
            u = it["url"]
            row = existing_map.get(u)

            if row is None:
                self.session.add(
                    DiscoveredURL(
                        program_id=pid,
                        url=u,
                        source=it.get("source"),
                        service_url=it.get("service_url"),
                        first_seen=now,
                        last_seen=now,
                    )
                )
                new_count += 1
            else:
                row.last_seen = now

                if it.get("source") and not row.source:
                    row.source = it["source"]
                if it.get("service_url") and not row.service_url:
                    row.service_url = it["service_url"]

                # backfill program_id if missing
                if pid is not None and row.program_id is None:
                    row.program_id = pid

                self.session.add(row)

        self.session.flush()
        return new_count

    def list_new_discovered_urls_since(
        self,
        dt: datetime,
        program: str | None = None,
    ) -> list[tuple[str, str | None]]:
        q = select(DiscoveredURL.url, DiscoveredURL.source).where(DiscoveredURL.first_seen > dt)

        if program is not None:
            pid = self._program_id(program)
            if pid is None:
                return []
            q = q.where(DiscoveredURL.program_id == pid)

        rows = self.session.execute(q).all()
        return sorted(set(rows))
