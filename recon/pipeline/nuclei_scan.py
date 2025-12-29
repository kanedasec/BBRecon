from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from db.session import get_session
from db.repo import ReconRepo


def banner(title: str) -> None:
    print("\n" + "=" * 90)
    print(title)
    print("=" * 90)


def parse_since(s: str, repo: ReconRepo) -> Optional[datetime]:
    """Parse --since argument."""
    s = (s or "").strip().lower()
    if s in ("", "none"):
        return None
    if s == "24h":
        return datetime.now(timezone.utc) - timedelta(hours=24)
    if s == "7d":
        return datetime.now(timezone.utc) - timedelta(days=7)
    if s == "last":
        dt = repo.get_last_finished_run_time("nuclei")
        return dt
    # ISO timestamp
    try:
        return datetime.fromisoformat(s)
    except Exception:
        raise ValueError("Invalid since. Use last|24h|7d|none|ISO timestamp")


INTERESTING_URL_RE_HINTS = (
    "/admin",
    "/login",
    "/oauth",
    "/swagger",
    "/graphql",
    "/api",
    "/.git",
    "/.env",
)


def _is_interesting(u: str) -> bool:
    u = (u or "").lower()
    return any(h in u for h in INTERESTING_URL_RE_HINTS)


@dataclass
class NucleiRunConfig:
    program: Optional[str]
    mode: str
    since: str
    templates: Optional[str]
    tags: Optional[str]
    severity: str
    include_info: bool
    rate_limit: int
    concurrency: int
    timeout: int
    only_interesting_urls: bool
    nuclei_bin: str


def collect_targets(repo: ReconRepo, cfg: NucleiRunConfig) -> list[str]:
    since_dt = parse_since(cfg.since, repo)

    targets: list[str] = []

    if cfg.mode in ("services", "both"):
        if since_dt is None:
            # Full scan (still scoped)
            targets += repo.list_service_urls(status_code=200, program=cfg.program)
            targets += repo.list_service_urls(status_code=301, program=cfg.program)
            targets += repo.list_service_urls(status_code=302, program=cfg.program)
            targets += repo.list_service_urls(status_code=401, program=cfg.program)
            targets += repo.list_service_urls(status_code=403, program=cfg.program)
        else:
            targets += [u for (u, _st) in repo.list_new_services_since(since_dt, program=cfg.program)]

    if cfg.mode in ("urls", "both"):
        if since_dt is None:
            targets += [u for (u, _src) in repo.list_new_discovered_urls_since(datetime.fromtimestamp(0, tz=timezone.utc), program=cfg.program)]
        else:
            targets += [u for (u, _src) in repo.list_new_discovered_urls_since(since_dt, program=cfg.program)]

    # De-dupe + optional filter
    out: list[str] = []
    seen: set[str] = set()
    for t in targets:
        t = (t or "").strip()
        if not t:
            continue
        if t in seen:
            continue
        if cfg.only_interesting_urls and cfg.mode in ("urls", "both"):
            # If it's a URL target, filter it. Service URLs still included.
            if t.startswith("http") and not _is_interesting(t):
                continue
        seen.add(t)
        out.append(t)
    return out


def nuclei_cmd(cfg: NucleiRunConfig, targets_file: str) -> list[str]:
    cmd = [
        cfg.nuclei_bin,
        "-l",
        targets_file,
        "-jsonl",
        "-silent",
        "-rl",
        str(int(cfg.rate_limit)),
        "-c",
        str(int(cfg.concurrency)),
        "-timeout",
        str(int(cfg.timeout)),
    ]

    if cfg.templates:
        cmd += ["-t", cfg.templates]
    if cfg.tags:
        cmd += ["-tags", cfg.tags]

    # Nuclei uses: -severity info,low,medium,high,critical
    sev = cfg.severity
    if cfg.include_info:
        if "info" not in sev:
            sev = "info," + sev
    cmd += ["-severity", sev]

    return cmd


def run_nuclei_and_parse(cmd: list[str]) -> list[dict]:
    """Run nuclei and parse JSONL output (best-effort)."""
    print(f"[CMD] {' '.join(cmd)}")
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    findings: list[dict] = []
    assert p.stdout is not None

    for line in p.stdout:
        line = (line or "").strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            # Some nuclei output can be non-JSON; ignore.
            continue

    _stderr = (p.stderr.read() if p.stderr else "")
    rc = p.wait()
    if rc != 0:
        print(f"[WARN] nuclei exited {rc}. stderr (first 300 chars): {_stderr.strip()[:300]}")

    return findings


def run_nuclei_scan(
    program: str | None = None,
    mode: str = "both",
    since: str = "last",
    templates: str | None = None,
    tags: str | None = None,
    severity: str = "low,medium,high,critical",
    include_info: bool = False,
    rate_limit: int = 50,
    concurrency: int = 10,
    timeout: int = 10,
    only_interesting_urls: bool = True,
    nuclei_bin: str = "nuclei",
):
    """
    Change-based nuclei execution.

    Defaults are conservative for bug bounty recon:
      - runs only on NEW targets since the last nuclei run (since=last)
      - focuses on service URLs + discovered URLs (mode=both)
      - stores a summarized finding record in DB (no raw response bodies)
    """
    if mode not in ("services", "urls", "both"):
        raise ValueError("mode must be services|urls|both")

    banner("NUCLEI — change-based scan")

    cfg = NucleiRunConfig(
        program=program,
        mode=mode,
        since=since,
        templates=templates,
        tags=tags,
        severity=severity,
        include_info=include_info,
        rate_limit=rate_limit,
        concurrency=concurrency,
        timeout=timeout,
        only_interesting_urls=only_interesting_urls,
        nuclei_bin=nuclei_bin,
    )

    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(
            step="nuclei",
            meta={
                "program": program,
                "mode": mode,
                "since": since,
                "templates": templates,
                "tags": tags,
                "severity": severity,
                "include_info": include_info,
                "rate_limit": rate_limit,
                "concurrency": concurrency,
                "timeout": timeout,
                "only_interesting_urls": only_interesting_urls,
            },
        )

        targets = collect_targets(repo, cfg)
        if not targets:
            print("[OK] No targets for nuclei (did anything change since last run?).")
            repo.finish_run(run_id)
            return

        print(f"[TARGETS] {len(targets)}")

        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            for t in targets:
                f.write(t + "\n")
            targets_file = f.name

        try:
            cmd = nuclei_cmd(cfg, targets_file)
            findings = run_nuclei_and_parse(cmd)
            new_count = repo.upsert_nuclei_findings(findings, program=program)
            print(f"[DB] nuclei findings stored. new={new_count} total_lines={len(findings)}")
        finally:
            try:
                Path(targets_file).unlink(missing_ok=True)
            except Exception:
                pass

        repo.finish_run(run_id)