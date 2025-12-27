from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from db.session import get_session
from db.repo import ReconRepo
from recon.interest_scoring import InterestScorer, rank

INTERESTING_PATTERNS = [
    r"/admin\b", r"/administrator\b", r"/manage\b", r"/console\b",
    r"/login\b", r"/signin\b", r"/auth\b", r"/oauth\b",
    r"/swagger\b", r"/openapi\b", r"/api-docs\b",
    r"/graphql\b",
    r"/.git\b", r"/.env\b",
]

HIGH_VALUE_TECH = {
    "grafana",
    "kibana",
    "jenkins",
    "gitlab",
    "gitlab ci",
    "sonarqube",
    "nexus",
    "harbor",
    "vault",
    "keycloak",
    "kong",
    "istio",
    "argo",
    "argocd",
    "airflow",
    "splunk",
}


def norm_tech(s: str) -> str:
    return (s or "").strip().lower()


def find_interesting(urls: list[str]) -> list[str]:
    out = []
    for u in urls:
        for pat in INTERESTING_PATTERNS:
            if re.search(pat, u, flags=re.IGNORECASE):
                out.append(u)
                break
    return out


def parse_since(since: str, last_dt: Optional[datetime]) -> datetime:
    """
    since:
      - 'last' -> use last_dt (must exist)
      - '24h', '7d', '30m' -> relative
      - ISO datetime -> datetime.fromisoformat(...)
    """
    since = (since or "").strip().lower()

    if since == "last":
        if last_dt is None:
            raise ValueError(
                "No previous finished run found for the selected step. "
                "Use since=24h / 7d / 30m or an ISO timestamp."
            )
        return last_dt

    m = re.fullmatch(r"(\d+)\s*([smhd])", since)
    if m:
        n = int(m.group(1))
        unit = m.group(2)
        delta = {
            "s": timedelta(seconds=n),
            "m": timedelta(minutes=n),
            "h": timedelta(hours=n),
            "d": timedelta(days=n),
        }[unit]
        return datetime.now(timezone.utc) - delta

    # ISO parse
    dt = datetime.fromisoformat(since)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def ensure_parent(path: str) -> None:
    Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def summarize_statuses(rows: list[tuple[str, Optional[int]]]) -> dict:
    counts: dict[str, int] = {}
    for _, sc in rows:
        key = str(sc) if sc is not None else "None"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def md_report(
    since_dt,
    program,
    step_ref,
    new_subdomains,
    new_services,
    new_urls_rows,
    interesting_urls,
    tech_supported,
    new_tech,
    high_value_tech_hits,
    js_semantic_changes=None,
) -> str:
    js_semantic_changes = js_semantic_changes or []
    sc_counts = summarize_statuses(new_services)

    lines: list[str] = []
    lines.append("# Recon Diff Report")
    lines.append("")
    lines.append(f"- **Since:** `{since_dt.isoformat()}`")
    lines.append(f"- **Program:** `{program or 'ALL'}`")
    lines.append(f"- **Step reference (for since=last):** `{step_ref}`")
    lines.append("")

    lines.append("## Summary")
    lines.append(f"- New subdomains: **{len(new_subdomains)}**")
    lines.append(f"- New services: **{len(new_services)}**")
    lines.append(f"- New URLs: **{len(new_urls_rows)}** (interesting: **{len(interesting_urls)}**)")
    if tech_supported:
        lines.append(f"- New technologies: **{len(new_tech)}** (high-value hits: **{len(high_value_tech_hits)}**)")
    else:
        lines.append("- New technologies: **N/A** (repo/db does not support fingerprints yet)")
    lines.append("")

    if js_semantic_changes:
        lines.append("## JS semantic changes")
        lines.append("")
        for ch in js_semantic_changes[:50]:
            lines.append(f"### {ch['url']}")
            lines.append(f"- old: `{ch['old_sha256']}`")
            lines.append(f"- new: `{ch['new_sha256']}`")
            if ch["endpoints_added"]:
                lines.append(f"- endpoints added: {len(ch['endpoints_added'])}")
            if ch["endpoints_removed"]:
                lines.append(f"- endpoints removed: {len(ch['endpoints_removed'])}")
            if ch["domains_added"]:
                lines.append(f"- domains added: {len(ch['domains_added'])}")
            if ch["secret_types_added"]:
                lines.append(f"- secret types added: {', '.join(ch['secret_types_added'])}")
            lines.append("")

    if sc_counts:
        lines.append("### Service Status Codes")
        for k, v in sc_counts.items():
            lines.append(f"- `{k}`: {v}")
        lines.append("")

    if interesting_urls:
        lines.append("## Interesting URLs")
        for u in interesting_urls[:50]:
            lines.append(f"- {u}")
        if len(interesting_urls) > 50:
            lines.append(f"- ... (+{len(interesting_urls) - 50} more)")
        lines.append("")

    if tech_supported:
        lines.append("## 🧪 Technology Changes")
        lines.append("")
        lines.append(f"Total new technology observations: **{len(new_tech)}**")
        lines.append("")

        if high_value_tech_hits:
            lines.append("### 🚨 High-value technology hits")
            lines.append("")
            lines.append("| Technology | Service |")
            lines.append("|---|---|")
            for service_url, tech in high_value_tech_hits[:200]:
                lines.append(f"| `{tech}` | {service_url} |")
            if len(high_value_tech_hits) > 200:
                lines.append(f"\n- ... (+{len(high_value_tech_hits) - 200} more)")
            lines.append("")

        if new_tech:
            lines.append("### New technologies detected")
            lines.append("")
            lines.append("| Service | Technology |")
            lines.append("|---|---|")
            for service_url, tech in new_tech[:500]:
                lines.append(f"| {service_url} | `{tech}` |")
            if len(new_tech) > 500:
                lines.append(f"\n- ... (+{len(new_tech) - 500} more)")
            lines.append("")

    lines.append("## New Subdomains")
    for s in new_subdomains[:100]:
        lines.append(f"- {s}")
    if len(new_subdomains) > 100:
        lines.append(f"- ... (+{len(new_subdomains) - 100} more)")
    lines.append("")

    lines.append("## New Services")
    for url, sc in new_services[:100]:
        lines.append(f"- `{sc}` {url}")
    if len(new_services) > 100:
        lines.append(f"- ... (+{len(new_services) - 100} more)")
    lines.append("")

    lines.append("## New Discovered URLs")
    for url, src in new_urls_rows[:200]:
        if src:
            lines.append(f"- [{src}] {url}")
        else:
            lines.append(f"- {url}")
    if len(new_urls_rows) > 200:
        lines.append(f"- ... (+{len(new_urls_rows) - 200} more)")
    lines.append("")

    return "\n".join(lines)


@dataclass
class DiffReport:
    since_dt: datetime
    program: Optional[str]
    step_ref: str
    top_interest: list[dict]

    new_subdomains: list[str]
    new_services: list[tuple[str, Optional[int]]]
    new_urls: list[tuple[str, Optional[str]]]

    interesting_urls: list[str]
    status_breakdown: dict

    tech_supported: bool
    new_tech: list[tuple[str, str]]
    high_value_tech_hits: list[tuple[str, str]]
    js_semantic_changes: list[dict]


    def to_payload(self) -> dict:
        payload = {
            "since": self.since_dt.isoformat(),
            "program": self.program,
            "step_ref": self.step_ref,
            "counts": {
                "new_subdomains": len(self.new_subdomains),
                "new_services": len(self.new_services),
                "new_urls": len(self.new_urls),
                "interesting_urls": len(self.interesting_urls),
            },
            "status_breakdown": self.status_breakdown,
            "new_subdomains": self.new_subdomains,
            "new_services": [{"url": url, "status_code": sc} for url, sc in self.new_services],
            "new_urls": [{"url": url, "source": src} for url, src in self.new_urls],
            "interesting_urls": self.interesting_urls,
        }

        payload["top_interest"] = self.top_interest
        payload["tech_supported"] = self.tech_supported
        payload["counts"]["js_semantic_changes"] = len(self.js_semantic_changes)
        payload["js_semantic_changes"] = self.js_semantic_changes

        if self.tech_supported:
            payload["counts"]["new_tech"] = len(self.new_tech)
            payload["counts"]["high_value_tech_hits"] = len(self.high_value_tech_hits)
            payload["new_tech"] = [{"service_url": u, "tech": t} for u, t in self.new_tech]
            payload["high_value_tech_hits"] = [{"service_url": u, "tech": t} for u, t in self.high_value_tech_hits]

        return payload


def build_report(program: Optional[str], since: str, step_ref: str = "content_discovery") -> DiffReport:
    """
    Build a diff report using DB state.

    Requires repo methods:
      - list_new_subdomains_since(dt, root_domains=None)
      - list_new_services_since(dt, fqdn_list=None)
      - list_new_discovered_urls_since(dt)
      - list_subdomains_for_root_domains(root_domains)
      - list_scope_domains(program=...)
      - get_last_finished_run_time(step)

    For Tech Diff:
      - list_new_fingerprints_since(dt, service_urls=None) -> list[(service_url, tech)]
        (If not present, report still works; tech_supported=False)
    """
    with get_session() as session:
        repo = ReconRepo(session)
        last_dt = repo.get_last_finished_run_time(step_ref)

    since_dt = parse_since(since, last_dt)

    root_domains: Optional[list[str]] = None
    scoped_subdomains: Optional[list[str]] = None

    with get_session() as session:
        repo = ReconRepo(session)

        if program:
            root_domains = repo.list_scope_domains(program=program)
            if not root_domains:
                raise ValueError(f"No scope domains found for program={program}. Run scope first.")

            scoped_subdomains = repo.list_subdomains_for_root_domains(root_domains) or []

        # core diffs
        new_subdomains = repo.list_new_subdomains_since(since_dt, root_domains=root_domains)
        new_services = repo.list_new_services_since(since_dt, fqdn_list=scoped_subdomains)
        new_urls_rows = repo.list_new_discovered_urls_since(since_dt)
        js_semantic_changes = repo.list_js_semantic_changes_since(since_dt, program=program)

        # tech diff (optional, depends on repo/db support)
        tech_supported = hasattr(repo, "list_new_fingerprints_since")
        new_tech_rows: list[tuple[str, str]] = []
        high_value_hits: list[tuple[str, str]] = []

        if tech_supported:
            # Scope tech diff to "new services since dt" when available
            service_urls = [u for (u, _sc) in new_services] if new_services else None
            try:
                new_tech_rows = repo.list_new_fingerprints_since(since_dt, service_urls=service_urls) or []
            except TypeError:
                # In case your repo signature is list_new_fingerprints_since(dt) only
                new_tech_rows = repo.list_new_fingerprints_since(since_dt) or []

            # Normalize + dedupe
            dedup = sorted({(svc, norm_tech(tech)) for svc, tech in new_tech_rows if svc and tech})
            new_tech_rows = dedup

            high_value_hits = [(svc, tech) for svc, tech in new_tech_rows if tech in HIGH_VALUE_TECH]

    new_urls = [u for u, _src in new_urls_rows]
    interesting = find_interesting(new_urls)
    status_breakdown = summarize_statuses(new_services)

    scorer = InterestScorer()
    items = []

    # URLs
    interesting_set = set(interesting)
    for url, src in new_urls_rows:
        items.append(scorer.score_url(url=url, is_interesting=(url in interesting_set), source=src))

    # Services
    for svc_url, sc in new_services:
        items.append(scorer.score_service(url=svc_url, status_code=sc))

    # High-value tech
    for svc_url, tech in high_value_hits:
        items.append(scorer.score_tech(service_url=svc_url, tech=tech))

    # JS signals (new/changed since)
    js_signals = []
    if hasattr(repo, "list_js_signals_since"):
        js_signals = repo.list_js_signals_since(since_dt, program=program)

    for js_url, changed, has_secrets, secret_count, secret_types in (js_signals or []):
        items.append(
            scorer.score_js(
                js_url=js_url,
                changed=changed,
                has_secrets=has_secrets,
                secret_count=secret_count,
                secret_types=secret_types,
            )
        )

    top_interest = [it.to_dict() for it in rank(items, top=20)]

    return DiffReport(
        since_dt=since_dt,
        program=program,
        step_ref=step_ref,
        new_subdomains=new_subdomains,
        new_services=new_services,
        new_urls=new_urls_rows,
        interesting_urls=interesting,
        status_breakdown=status_breakdown,
        tech_supported=tech_supported,
        new_tech=new_tech_rows,
        high_value_tech_hits=high_value_hits,
        top_interest=top_interest,
        js_semantic_changes=js_semantic_changes,
    )


def write_json(report: DiffReport, out_path: str) -> None:
    ensure_parent(out_path)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report.to_payload(), f, ensure_ascii=False, indent=2)


def write_md(report: DiffReport, out_path: str) -> None:
    ensure_parent(out_path)
    md = md_report(
        since_dt=report.since_dt,
        program=report.program,
        step_ref=report.step_ref,
        new_subdomains=report.new_subdomains,
        new_services=report.new_services,
        new_urls_rows=report.new_urls,
        interesting_urls=report.interesting_urls,
        new_tech=report.new_tech,
        high_value_tech_hits=report.high_value_tech_hits,
        tech_supported=report.tech_supported,
        js_semantic_changes=getattr(report, "js_semantic_changes", []),  # ✅ ADD THIS
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)

