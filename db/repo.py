from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from typing import Iterable, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from pathlib import Path

from .models import (
    Run,
    Program,
    ScopeDomain,
    Subdomain,
    Service,
    DiscoveredURL,
    Fingerprint,
    JSArtifact,
    JSArtifactVersion,
    NucleiFinding,
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
            q = q.where(Subdomain.root_domain == normalize_domain(root_domain))

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
            pid = self.get_or_create_program(program).id

        # 1) normalize + dedupe by url (last one wins)
        by_url: dict[str, dict] = {}
        for r in httpx_results or []:
            url = str(r.get("url", "")).strip()
            if not url:
                continue
            by_url[url] = r

        if not by_url:
            return 0

        urls = list(by_url.keys())

        # 2) fetch existing services from DB
        existing = self.session.execute(
            select(Service).where(Service.url.in_(urls))
        ).scalars().all()
        existing_map = {s.url: s for s in existing}

        # 3) ALSO consider pending (unflushed) inserts in this session (autoflush=False)
        #    This prevents duplicates across batches in the same run.
        for obj in list(self.session.new):
            if isinstance(obj, Service) and getattr(obj, "url", None):
                existing_map.setdefault(obj.url, obj)

        new_count = 0

        for url, r in by_url.items():
            svc = existing_map.get(url)

            if svc is None:
                svc = Service(
                    program_id=pid,
                    url=url,
                    fqdn=normalize_domain(str(r.get("input") or r.get("host") or "")) or None,
                    scheme=(r.get("scheme") or None),
                    host=(r.get("host") or None),
                    port=str(r.get("port")) if r.get("port") is not None else None,
                    title=r.get("title"),
                    webserver=r.get("webserver"),
                    content_type=r.get("content_type"),
                    status_code=int(r["status_code"]) if str(r.get("status_code", "")).isdigit() else None,
                    ip=r.get("host_ip"),
                    first_seen=now,
                    last_seen=now,
                )
                self.session.add(svc)

                # Flush per insert so we catch UNIQUE conflicts immediately
                # (instead of failing at commit after multiple batches).
                try:
                    self.session.flush()
                    new_count += 1
                    existing_map[url] = svc
                except IntegrityError:
                    # Another batch/run inserted it (or it already existed but we didn't see it).
                    self.session.rollback()

                    existing_row = self.session.execute(
                        select(Service).where(Service.url == url)
                    ).scalar_one()

                    existing_row.last_seen = now
                    existing_row.title = r.get("title") or existing_row.title
                    existing_row.webserver = r.get("webserver") or existing_row.webserver
                    existing_row.content_type = r.get("content_type") or existing_row.content_type
                    existing_row.ip = r.get("host_ip") or existing_row.ip
                    if pid is not None and existing_row.program_id is None:
                        existing_row.program_id = pid

                    self.session.add(existing_row)
                    self.session.flush()
                    existing_map[url] = existing_row

            else:
                svc.last_seen = now
                svc.title = r.get("title") or svc.title
                svc.webserver = r.get("webserver") or svc.webserver
                svc.content_type = r.get("content_type") or svc.content_type
                svc.ip = r.get("host_ip") or svc.ip
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

    # ----------------------
    # JS Analyzers
    # ----------------------

    def list_js_candidate_urls(
            self,
            program: str | None = None,
    ) -> list[str]:
        """
        JS candidates from discovered_urls + services (scoped by program if provided).
        Includes .js .mjs .js.map and query variants.
        """
        pid = self._program_id(program) if program is not None else None
        if program is not None and pid is None:
            return []

        def _is_js(u: str) -> bool:
            u = (u or "").lower()
            return (
                    u.endswith(".js")
                    or u.endswith(".mjs")
                    or u.endswith(".js.map")
                    or ".js?" in u
                    or ".mjs?" in u
                    or ".js.map?" in u
            )

        q1 = select(DiscoveredURL.url)
        q2 = select(Service.url)

        if pid is not None:
            q1 = q1.where(DiscoveredURL.program_id == pid)
            q2 = q2.where(Service.program_id == pid)

        urls: list[str] = []
        urls += self.session.execute(q1).scalars().all()
        urls += self.session.execute(q2).scalars().all()

        return sorted({u for u in urls if u and _is_js(u)})

    def list_missing_js_artifacts(self, urls: list[str]) -> list[str]:
        """
        Given candidate urls, return those that are missing in js_artifacts
        OR exist but have no cached local path.
        """
        if not urls:
            return []

        rows = self.session.execute(
            select(JSArtifact.url, JSArtifact.path).where(JSArtifact.url.in_(urls))
        ).all()

        have_path: set[str] = set()
        seen: set[str] = set()
        for u, p in rows:
            if u:
                seen.add(u)
                if p:
                    have_path.add(u)

        # Missing if:
        # - not in table at all, OR
        # - in table but path is null/empty
        missing = []
        for u in urls:
            if u not in seen or u not in have_path:
                missing.append(u)

        return missing

    def upsert_js_artifact(
            self,
            url: str,
            sha256: str | None,
            size_bytes: int | None,
            content_type: str | None,
            path: str | None,
            program: str | None = None,
            changed: bool = False,
    ) -> None:
        """
        Upsert a JSArtifact. If sha changes, updates last_changed_at.
        Also backfills program_id if missing.
        """
        now = utcnow()

        pid: int | None = None
        if program:
            pid = self.get_or_create_program(program).id

        url = (url or "").strip()
        if not url:
            return

        try:
            self.session.add(
                JSArtifact(
                    program_id=pid,
                    url=url,
                    sha256=sha256,
                    size_bytes=size_bytes,
                    content_type=content_type,
                    path=path,
                    first_seen=now,
                    last_seen=now,
                    last_changed_at=now if changed else None,
                )
            )
            self.session.flush()
            return
        except IntegrityError:
            self.session.rollback()

        row = self.session.execute(
            select(JSArtifact).where(JSArtifact.url == url)
        ).scalar_one_or_none()

        if row is None:
            # Create a new artifact row (true upsert)
            row = JSArtifact(
                program_id=pid,
                url=url,
                sha256=sha256,
                size_bytes=size_bytes,
                content_type=content_type,
                path=path,
                first_seen=now,
                last_seen=now,
                last_changed_at=now if changed else None,
                has_secrets=False,
                secret_count=0,
                secret_types="",
            )
            self.session.add(row)
            self.session.flush()
            return row

        # Existing row: update
        row.last_seen = now

        # Update metadata if present
        if size_bytes is not None:
            row.size_bytes = size_bytes
        if content_type:
            row.content_type = content_type
        if path:
            row.path = path

        # Detect change by sha difference (or explicit changed=True)
        if sha256 and row.sha256 != sha256:
            row.sha256 = sha256
            row.last_changed_at = now
        elif changed:
            # if caller says "changed" but sha didn't differ, still mark change
            row.last_changed_at = now

        self.session.flush()
        return row


    def mark_js_secrets(
            self,
            js_url: str,
            has_secrets: bool,
            secret_types: list[str] | None = None,
            secret_count: int = 0,
            program: str | None = None,
    ) -> None:
        """
        Stores only the SUMMARY on JSArtifact:
          - has_secrets (bool)
          - secret_types (comma-separated string)
          - secret_count (int)

        This avoids storing raw secrets.
        """
        js_url = (js_url or "").strip()
        if not js_url:
            return

        pid = self._program_id(program) if program else None

        types_str: str | None = None
        if secret_types:
            types_str = ",".join(sorted({t.strip().lower() for t in secret_types if t.strip()})) or None

        row = self.session.execute(
            select(JSArtifact).where(JSArtifact.url == js_url)
        ).scalar_one_or_none()

        if row is None:
            # Create stub so we don’t lose the signal
            self.upsert_js_artifact(
                url=js_url,
                sha256=None,
                size_bytes=None,
                content_type=None,
                path=None,
                program=program,
                changed=False,
            )
            row = self.session.execute(
                select(JSArtifact).where(JSArtifact.url == js_url)
            ).scalar_one()

        row.has_secrets = bool(has_secrets)
        row.secret_types = types_str
        row.secret_count = int(secret_count or 0)
        row.last_seen = utcnow()

        # optional: backfill program_id
        if pid is not None and row.program_id is None:
            row.program_id = pid

        self.session.add(row)
        self.session.flush()

    def list_js_artifact_paths(
            self,
            program: str | None = None,
            only_with_secrets: bool | None = None,
            only_changed_after: datetime | None = None,
            limit: int | None = None,
    ) -> list[tuple[str, str]]:
        """
        Returns list of (js_url, local_path) for downloaded JS artifacts.

        Program-scoped:
          - include any artifact whose path is under artifacts/js/<program>/
          - OR whose URL is in the program's JS candidate set
        Uses real Path prefix checks (no fragile LIKE substring assumptions).
        """
        q = select(JSArtifact.url, JSArtifact.path).where(
            JSArtifact.path.is_not(None),
            JSArtifact.path != "",
        )

        if only_with_secrets is True:
            q = q.where(JSArtifact.has_secrets.is_(True))
        elif only_with_secrets is False:
            q = q.where(JSArtifact.has_secrets.is_(False))

        if only_changed_after is not None:
            q = q.where(JSArtifact.last_changed_at.is_not(None))
            q = q.where(JSArtifact.last_changed_at > only_changed_after)

        q = q.order_by(JSArtifact.last_seen.desc())

        rows = self.session.execute(q).all()
        out: list[tuple[str, str]] = [(u, p) for (u, p) in rows if u and p]

        if program is not None:
            prog = normalize_domain(program)
            base = Path("artifacts/js") / prog
            base_abs = base.resolve()

            # candidate URL set (may be small but cheap to include)
            cand = set(self.list_js_candidate_urls(program=program))

            filtered: list[tuple[str, str]] = []
            for js_url, path in out:
                try:
                    p = Path(path).expanduser().resolve()
                except Exception:
                    p = None

                in_prog_dir = False
                if p is not None:
                    try:
                        # True if p is within base_abs
                        p.relative_to(base_abs)
                        in_prog_dir = True
                    except Exception:
                        in_prog_dir = False

                if in_prog_dir or js_url in cand:
                    filtered.append((js_url, path))

            out = filtered

        if limit is not None:
            out = out[: int(limit)]

        return out

    def list_js_signals_since(
            self,
            since_dt: datetime,
            program: str | None = None,
    ) -> list[tuple[str, bool, bool, int, str | None]]:
        """
        Returns JS scoring signals since `since_dt`.

        Output tuples:
          (js_url, changed, has_secrets, secret_count, secret_types)

        'changed' means last_changed_at > since_dt.
        Also includes newly first_seen > since_dt (even if last_changed_at is null).
        """
        pid = self._program_id(program) if program is not None else None
        if program is not None and pid is None:
            return []

        q = select(
            JSArtifact.url,
            JSArtifact.last_changed_at,
            JSArtifact.first_seen,
            JSArtifact.has_secrets,
            JSArtifact.secret_count,
            JSArtifact.secret_types,
        )

        if pid is not None:
            q = q.where(JSArtifact.program_id == pid)

        # include either new artifacts or changed ones
        q = q.where(
            (JSArtifact.first_seen > since_dt)
            | ((JSArtifact.last_changed_at.is_not(None)) & (JSArtifact.last_changed_at > since_dt))
        )

        q = q.order_by(JSArtifact.last_seen.desc())

        rows = self.session.execute(q).all()
        out: list[tuple[str, bool, bool, int, str | None]] = []
        for url, last_changed_at, first_seen, has_secrets, secret_count, secret_types in rows:
            changed = bool(last_changed_at and last_changed_at > since_dt)
            out.append((url, changed, bool(has_secrets), int(secret_count or 0), secret_types))
        return out

    def record_js_artifact_version(
            self,
            js_url: str,
            sha256: str,
            extracted: dict,
            program: str | None = None,
    ) -> None:
        """
        Persist a JS semantic snapshot keyed by sha256.

        - Ensures a JSArtifact exists (upserts)
        - Inserts a JSArtifactVersion (unique on artifact_id+sha)
        """
        # Ensure artifact exists with correct sha
        self.upsert_js_artifact(
            url=js_url,
            sha256=sha256,
            size_bytes=extracted.get("size_bytes"),
            content_type=extracted.get("content_type"),
            path=extracted.get("path"),
            program=program,
            changed=False,
        )

        artifact = self.session.execute(
            select(JSArtifact).where(JSArtifact.url == js_url)
        ).scalar_one()

        payload = json.dumps(extracted, ensure_ascii=False, sort_keys=True)

        # Use a savepoint: avoid rolling back the whole JS run if this version already exists
        with self.session.begin_nested():
            try:
                self.session.add(
                    JSArtifactVersion(
                        js_artifact_id=artifact.id,
                        sha256=sha256,
                        extracted_json=payload,
                    )
                )
                self.session.flush()
            except IntegrityError:
                # Version already recorded; ignore safely
                pass

    def list_js_semantic_changes_since(
            self,
            since_dt: datetime,
            program: str | None = None,
    ) -> list[dict]:
        """
        For JS artifacts changed since `since_dt`, returns semantic diffs based on the
        latest two stored JSArtifactVersion snapshots.

        Output item:
          {
            "url": str,
            "new_sha256": str,
            "old_sha256": str,
            "changed_at": iso str | None,
            "endpoints_added": [...],
            "endpoints_removed": [...],
            "domains_added": [...],
            "domains_removed": [...],
            "secret_types_added": [...],
            "secret_types_removed": [...],
          }
        """
        pid = self._program_id(program) if program is not None else None
        if program is not None and pid is None:
            return []

        q = select(JSArtifact).where(
            (JSArtifact.last_changed_at.is_not(None)) & (JSArtifact.last_changed_at > since_dt)
        )
        if pid is not None:
            q = q.where(JSArtifact.program_id == pid)

        artifacts = self.session.execute(q).scalars().all()
        out: list[dict] = []

        for a in artifacts:
            # Fetch last two versions for this artifact
            vq = (
                select(JSArtifactVersion)
                .where(JSArtifactVersion.js_artifact_id == a.id)
                .order_by(JSArtifactVersion.created_at.desc())
                .limit(2)
            )
            versions = self.session.execute(vq).scalars().all()
            if len(versions) < 2:
                continue

            new_v, old_v = versions[0], versions[1]
            try:
                new_j = json.loads(new_v.extracted_json)
                old_j = json.loads(old_v.extracted_json)
            except Exception:
                continue

            def to_set(obj: dict, key: str) -> set[str]:
                v = obj.get(key) or []
                if not isinstance(v, list):
                    return set()
                return {str(x) for x in v if x}

            new_end = to_set(new_j, "endpoints")
            old_end = to_set(old_j, "endpoints")
            new_dom = to_set(new_j, "domains")
            old_dom = to_set(old_j, "domains")
            new_sec = to_set(new_j, "secret_types")
            old_sec = to_set(old_j, "secret_types")

            out.append({
                "url": a.url,
                "new_sha256": new_v.sha256,
                "old_sha256": old_v.sha256,
                "changed_at": a.last_changed_at.isoformat() if a.last_changed_at else None,
                "endpoints_added": sorted(new_end - old_end),
                "endpoints_removed": sorted(old_end - new_end),
                "domains_added": sorted(new_dom - old_dom),
                "domains_removed": sorted(old_dom - new_dom),
                "secret_types_added": sorted(new_sec - old_sec),
                "secret_types_removed": sorted(old_sec - new_sec),
            })

        # Sort most “impactful” diffs first
        out.sort(
            key=lambda x: (
                    len(x["endpoints_added"]) + len(x["endpoints_removed"])
                    + len(x["domains_added"]) + len(x["domains_removed"])
                    + len(x["secret_types_added"]) + len(x["secret_types_removed"])
            ),
            reverse=True,
        )
        return out

# ----------------------
   # Nuclei findings
   # ----------------------
    def upsert_nuclei_findings(self, findings: Sequence[dict], program: str | None = None) -> int:
        """
        Stores (deduped) nuclei findings.

        Unique: (template_id, matched)
        """
        now = utcnow()

        pid: int | None = None
        if program:
            pid = self.get_or_create_program(program).id

        # 1) normalize + dedupe input by unique key (template_id, matched)
        by_key: dict[tuple[str, str], dict] = {}
        for f in findings or []:
            if not isinstance(f, dict):
                continue

            template_id = str(f.get("template-id") or f.get("template_id") or "").strip()

            matched = f.get("matched")
            if matched is None:
                matched = f.get("matched-at") or f.get("matched_at")
            matched = str(matched).strip() if matched is not None else ""

            if not template_id or not matched:
                continue

            by_key[(template_id, matched)] = f

        if not by_key:
            return 0

        keys = list(by_key.keys())

        # 2) fetch existing from DB (ORed list for sqlite friendliness)
        conds = []
        for (tid, m) in keys:
            conds.append((NucleiFinding.template_id == tid) & (NucleiFinding.matched == m))

        existing_rows = []
        if conds:
            from sqlalchemy import or_
            existing_rows = self.session.execute(
                select(NucleiFinding).where(or_(*conds))
            ).scalars().all()

        existing_map: dict[tuple[str, str], NucleiFinding] = {
            (r.template_id, r.matched): r for r in existing_rows
        }

        # 3) ALSO consider pending (unflushed) inserts in this session (autoflush=False)
        for obj in list(self.session.new):
            if isinstance(obj, NucleiFinding) and getattr(obj, "template_id", None) and getattr(obj, "matched", None):
                existing_map.setdefault((obj.template_id, obj.matched), obj)

        new_count = 0

        for (template_id, matched), f in by_key.items():
            info = f.get("info") or {}
            if not isinstance(info, dict):
                info = {}

            template_name = info.get("name") or f.get("template") or f.get("name")
            severity = info.get("severity")
            tags = info.get("tags")
            if isinstance(tags, list):
                tags = ",".join([str(t) for t in tags if t is not None][:50])
            elif tags is not None:
                tags = str(tags)

            description = info.get("description")
            if isinstance(description, str) and len(description) > 1024:
                description = description[:1021] + "..."

            reference = info.get("reference")
            if isinstance(reference, list):
                reference = "\n".join([str(r) for r in reference][:20])
            elif reference is not None:
                reference = str(reference)

            host = f.get("host")
            if host is not None:
                host = str(host).strip()

            ftype = f.get("type")
            if ftype is not None:
                ftype = str(ftype).strip()

            row = existing_map.get((template_id, matched))

            if row is None:
                row = NucleiFinding(
                    program_id=pid,
                    template_id=template_id,
                    template_name=template_name,
                    severity=(str(severity).lower() if severity else None),
                    host=host or None,
                    matched=matched,
                    type=ftype or None,
                    tags=tags,
                    description=description,
                    reference=reference,
                    matched_at=f.get("matched-at") or f.get("matched_at"),
                    first_seen=now,
                    last_seen=now,
                )
                self.session.add(row)

                # Flush per insert to avoid blowing up at the end
                try:
                    self.session.flush()
                    existing_map[(template_id, matched)] = row
                    new_count += 1
                except IntegrityError:
                    # If another batch/run inserted it, recover and update last_seen.
                    self.session.rollback()
                    existing = self.session.execute(
                        select(NucleiFinding).where(
                            NucleiFinding.template_id == template_id,
                            NucleiFinding.matched == matched,
                        )
                    ).scalar_one()

                    existing.last_seen = now
                    if pid is not None and existing.program_id is None:
                        existing.program_id = pid
                    if host and not existing.host:
                        existing.host = host
                    if template_name and not existing.template_name:
                        existing.template_name = template_name
                    if severity and not existing.severity:
                        existing.severity = str(severity).lower()
                    if tags and not existing.tags:
                        existing.tags = tags
                    if ftype and not existing.type:
                        existing.type = ftype
                    if description and not existing.description:
                        existing.description = description
                    if reference and not existing.reference:
                        existing.reference = reference

                    self.session.add(existing)
                    self.session.flush()
                    existing_map[(template_id, matched)] = existing

            else:
                row.last_seen = now
                if pid is not None and row.program_id is None:
                    row.program_id = pid

                # best-effort fill missing fields
                if host and not row.host:
                    row.host = host
                if template_name and not row.template_name:
                    row.template_name = template_name
                if severity and not row.severity:
                    row.severity = str(severity).lower()
                if tags and not row.tags:
                    row.tags = tags
                if ftype and not row.type:
                    row.type = ftype
                if description and not row.description:
                    row.description = description
                if reference and not row.reference:
                    row.reference = reference

                self.session.add(row)

        return new_count

    def list_new_nuclei_findings_since(
       self,
       dt: datetime,
       program: str | None = None,
   ) -> list[tuple[str, str, str | None]]:
       """Return (matched_url, template_id, severity) for new findings since dt."""
       q = select(NucleiFinding.matched, NucleiFinding.template_id, NucleiFinding.severity).where(
           NucleiFinding.first_seen > dt
       )

       if program is not None:
           pid = self._program_id(program)
           if pid is None:
               return []
           q = q.where(NucleiFinding.program_id == pid)

       rows = self.session.execute(q).all()
       return sorted(set(rows))