from __future__ import annotations
import json
from datetime import datetime, timezone, timedelta
from typing import Iterable, Optional, Sequence
from sqlalchemy import select
from .models import Run, Program, ScopeDomain, Subdomain, Service, DiscoveredURL


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def normalize_domain(s: str) -> str:
    s = (s or "").strip().lower()
    return s.rstrip(".")


class ReconRepo:
    def __init__(self, session):
        self.session = session

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
        existing = self.session.execute(select(Program).where(Program.name == name)).scalar_one_or_none()
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

        # fetch existing scope domains for this program
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

        # update last_seen for all seen this run
        if cleaned:
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

        # Resolve program_id if program provided
        pid: int | None = None
        if program:
            p = self.get_or_create_program(program)
            pid = p.id

        # Pre-fetch existing FQDNs (fast path)
        existing_rows = self.session.execute(
            select(Subdomain.fqdn).where(Subdomain.fqdn.in_(cleaned))
        ).scalars().all()
        existing_set = set(existing_rows)

        new_items = [fqdn for fqdn in cleaned if fqdn not in existing_set]
        new_count = 0

        # Insert new items one-by-one with flush to avoid deferred UNIQUE surprises
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
                self.session.flush()  # forces INSERT now, catches UNIQUE immediately
                new_count += 1

            except IntegrityError:
                # Another insert already won (or fqdn exists but wasn't in our existing_set).
                # Rollback current failed INSERT and upsert as update.
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

        # Touch last_seen (and fill missing fields) for ALL cleaned fqdn seen now
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

    def list_scope_domains(self, program: str | None = None) -> list[str]:
        """
        Returns scope domains. If program is None, returns all scope domains across programs.
        """
        q = select(ScopeDomain.domain)

        if program:
            p = self.session.execute(select(Program).where(Program.name == program)).scalar_one_or_none()
            if not p:
                return []
            q = q.where(ScopeDomain.program_id == p.id)

        rows = self.session.execute(q).scalars().all()
        # dedupe + stable output
        return sorted(set(rows))

    def list_subdomains(self, root_domain=None, only_recent_days=None):
        q = select(Subdomain.fqdn, Subdomain.last_seen)
        if root_domain:
            q = q.where(Subdomain.root_domain == root_domain)

        rows = self.session.execute(q).all()

        if only_recent_days is not None:
            cutoff = utcnow() - timedelta(days=int(only_recent_days))
            rows = [r for r in rows if r.last_seen and r.last_seen >= cutoff]

        return sorted(set(r.fqdn for r in rows))
    
    def list_subdomains_for_root_domains(self, root_domains: Sequence[str], only_new_after: datetime | None = None) -> list[str]:
        roots = sorted({normalize_domain(d) for d in (root_domains or []) if normalize_domain(d)})
        if not roots:
            return []

        q = select(Subdomain.fqdn).where(Subdomain.root_domain.in_(roots))
        if only_new_after is not None:
            q = q.where(Subdomain.first_seen > only_new_after)

        rows = self.session.execute(q).scalars().all()
        return sorted(set(rows))


    def get_last_finished_run_time(self, step: str) -> datetime | None:
        """
        Returns the started_at of the most recent finished run for `step`.
        Using started_at is usually enough; you can switch to finished_at if you prefer.
        """
        row = self.session.execute(
            select(Run)
            .where(Run.step == step)
            .where(Run.finished_at.is_not(None))
            .order_by(Run.finished_at.desc())
            .limit(1)
        ).scalar_one_or_none()

        return row.finished_at if row else None

    def list_subdomains_first_seen_after(self, dt: datetime) -> list[str]:
        """
        Returns subdomains that are NEW since `dt` (based on first_seen).
        """
        rows = self.session.execute(
            select(Subdomain.fqdn)
            .where(Subdomain.first_seen > dt)
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
    def upsert_services(self, httpx_results: Sequence[dict]) -> int:
        """
        Expects list[dict] from httpx -json output.
        Uses `url` as unique key.
        """
        now = utcnow()
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
                # insert new
                svc = Service(
                    url=url,
                    fqdn=normalize_domain(str(r.get("input") or r.get("host") or "")) or None,
                    scheme=r.get("scheme"),
                    host=r.get("host"),
                    port=str(r.get("port")) if r.get("port") is not None else None,
                    title=r.get("title"),
                    webserver=r.get("webserver"),
                    content_type=r.get("content_type"),
                    status_code=int(r["status_code"]) if "status_code" in r and str(r["status_code"]).isdigit() else None,
                    ip=r.get("host_ip"),
                    first_seen=now,
                    last_seen=now,
                )
                self.session.add(svc)
                new_count += 1
            else:
                # update existing
                svc = self.session.execute(select(Service).where(Service.url == url)).scalar_one()
                svc.last_seen = now
                # keep latest known metadata (optional)
                svc.title = r.get("title") or svc.title
                svc.webserver = r.get("webserver") or svc.webserver
                svc.content_type = r.get("content_type") or svc.content_type
                svc.ip = r.get("host_ip") or svc.ip
                self.session.add(svc)

        return new_count
    
    def list_service_urls(self, status_code: int = 200) -> list[str]:
        rows = self.session.execute(
            select(Service.url).where(Service.status_code == status_code)
        ).scalars().all()
        return sorted(set(rows))
    
    def list_service_urls_scoped(self, scope_domains: Sequence[str], status_code: int = 200) -> list[str]:
        roots = sorted({normalize_domain(d) for d in (scope_domains or []) if normalize_domain(d)})
        if not roots:
            return []

        # Pull subdomains under these roots
        sub_rows = self.session.execute(
            select(Subdomain.fqdn).where(Subdomain.root_domain.in_(roots))
        ).scalars().all()
        sub_set = sorted(set(sub_rows))
        if not sub_set:
            return []

        rows = self.session.execute(
            select(Service.url)
            .where(Service.status_code == status_code)
            .where(Service.fqdn.in_(sub_set))
        ).scalars().all()
        return sorted(set(rows))
    
    def list_new_services_since(self, dt: datetime, fqdn_list: list[str] | None = None) -> list[tuple[str, int | None]]:
        q = select(Service.url, Service.status_code).where(Service.first_seen > dt)
        if fqdn_list:
            q = q.where(Service.fqdn.in_(fqdn_list))
        rows = self.session.execute(q).all()
        # returns list of (url, status_code)
        return sorted(set(rows))


    # ----------------------
    # Discovered Urls
    # ----------------------

    def upsert_discovered_urls(self, items: list[dict]) -> int:
        now = utcnow()

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
                {"url": u, "source": it.get("source"), "service_url": it.get("service_url")}
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
                self.session.add(row)

        self.session.flush()

        return new_count
    
    def list_new_discovered_urls_since(self, dt: datetime) -> list[tuple[str, str | None]]:
        q = select(DiscoveredURL.url, DiscoveredURL.source).where(DiscoveredURL.first_seen > dt)
        rows = self.session.execute(q).all()
        return sorted(set(rows))

    
   

