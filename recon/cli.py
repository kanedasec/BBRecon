from __future__ import annotations

import typer
from typing import Optional

app = typer.Typer(no_args_is_help=True)


@app.command()
def run(
    step: str = typer.Option("all", help="scope|subdomains|probe|fingerprint|content|js|all"),
    program: Optional[str] = typer.Option(None, help="HackerOne team/program name"),
    all: bool = typer.Option(False, help="Run without program scoping"),
    interactive: bool = typer.Option(False, help="Allow interactive prompts (fallback)"),
    max_parallel: int = typer.Option(5, help="Parallelism for subdomain enum"),
    batch_size: int = typer.Option(500, help="Batch size for httpx probing"),
    fp_batch_size: int = typer.Option(300, help="Batch size for httpx -tech-detect"),
):
    from recon.pipeline.scope import run_scope_download
    from recon.pipeline.subdomains import run_subdomain_enum
    from recon.pipeline.probe import run_asset_probing
    from recon.pipeline.fingerprint import run_fingerprinting
    from recon.pipeline.content import run_content_discovery
    from recon.pipeline.js_analysis import run_js_analysis

    if step == "all":
        run_scope_download(program=program, run_all=all, interactive=interactive)
        run_subdomain_enum(program=program, run_all=all, max_parallel=max_parallel)
        run_asset_probing(program=program, run_all=all, batch_size=batch_size)
        run_fingerprinting(program=program, run_all=all, batch_size=fp_batch_size)
        run_content_discovery(program=program, run_all=all)
        run_js_analysis(program=program)
        return

    elif step == "scope":
        run_scope_download(program=program, run_all=all, interactive=interactive)
    elif step == "subdomains":
        run_subdomain_enum(program=program, run_all=all, max_parallel=max_parallel)
    elif step == "probe":
        run_asset_probing(program=program, run_all=all, batch_size=batch_size)
    elif step == "fingerprint":
        run_fingerprinting(program=program, run_all=all, batch_size=fp_batch_size)
    elif step == "content":
        run_content_discovery(program=program, run_all=all)
    elif step == "js":
        run_js_analysis(program=program)
    else:
        raise typer.BadParameter("Invalid step. Use scope|subdomains|probe|fingerprint|content|all")


@app.command()
def report(
    program: Optional[str] = typer.Option(None, help="Program (HackerOne team). If omitted, report is global."),
    since: str = typer.Option("last", help="last|24h|7d|30m|ISO timestamp"),
    step: str = typer.Option("content_discovery", help="Step used when since=last"),
    out_json: Optional[str] = typer.Option(None, help="Write JSON report to a file (e.g. artifacts/diff.json)"),
    out_md: Optional[str] = typer.Option(None, help="Write Markdown report to a file (e.g. artifacts/diff.md)"),
):
    """
    Diff & reporting: show what's new since a time reference, and optionally export JSON/Markdown.
    Includes tech diff if your DB/repo supports it (repo.list_new_fingerprints_since).
    """
    from recon.reporting import build_report, write_json, write_md

    try:
        rep = build_report(program=program, since=since, step_ref=step)
    except ValueError as e:
        raise typer.BadParameter(str(e))

    typer.echo(f"\n[DIFF] since={rep.since_dt.isoformat()} program={rep.program or 'ALL'} step_ref={rep.step_ref}")
    typer.echo(f"New subdomains: {len(rep.new_subdomains)}")
    typer.echo(f"New services:   {len(rep.new_services)}")
    if rep.status_breakdown:
        typer.echo(f"  status breakdown: {rep.status_breakdown}")
    typer.echo(f"New URLs:       {len(rep.new_urls)} (interesting: {len(rep.interesting_urls)})")

    if getattr(rep, "tech_supported", False):
        typer.echo(f"New tech:       {len(rep.new_tech)} (high-value: {len(rep.high_value_tech_hits)})")
        if rep.high_value_tech_hits:
            typer.echo("\nHigh-value tech hits (top 15):")
            for svc, tech in rep.high_value_tech_hits[:15]:
                typer.echo(f" - [{tech}] {svc}")
    else:
        typer.echo("New tech:       N/A (fingerprinting not enabled in DB/repo)")

    if rep.interesting_urls:
        typer.echo("\nTop interesting URLs:")
        for u in rep.interesting_urls[:15]:
            typer.echo(f" - {u}")

    if out_json:
        write_json(rep, out_json)
        typer.echo(f"\n[OK] Wrote JSON report: {out_json}")

    if out_md:
        write_md(rep, out_md)
        typer.echo(f"[OK] Wrote Markdown report: {out_md}")

@app.command()
def burp(
    program: str = typer.Option(..., help="Program (HackerOne team/program name)"),
    exclude_status: Optional[int] = typer.Option(403, help="Exclude hosts that returned this status (set none to disable)"),
    out_config: Optional[str] = typer.Option(None, help="Output Burp config JSON path"),
    export_urls_status: Optional[int] = typer.Option(None, help="Also export URLs with this status (e.g. 200)"),
    out_urls: Optional[str] = typer.Option(None, help="Output URLs list path (one URL per line)"),
):
    """
    Generate Burp scope config + (optional) export URL lists from DB services.
    """
    from recon.burp import (
        write_burp_config,
        export_alive_urls,
        default_burp_filename,
        default_urls_filename,
    )

    if not out_config:
        out_config = default_burp_filename(program)

    cfg_path = write_burp_config(program=program, out_path=out_config, exclude_hosts_status=exclude_status)
    typer.echo(f"[OK] Burp config written: {cfg_path}")

    if export_urls_status is not None:
        if not out_urls:
            out_urls = default_urls_filename(program, int(export_urls_status))

        urls_path = export_alive_urls(program=program, out_path=out_urls, status_code=int(export_urls_status))
        typer.echo(f"[OK] URLs list written: {urls_path}")

@app.command("secret-scan")
def secret_scan(
    program: Optional[str] = typer.Option(None, help="Program (HackerOne team). If omitted, scan global."),
    only_with_secrets_flag: Optional[bool] = typer.Option(None,
                                                          help="True: scan only artifacts flagged has_secrets; False: only non-flagged; None: all."),
    only_changed_since: str = typer.Option("none", help="none|last-js|24h|7d|ISO timestamp"),
    limit: Optional[int] = typer.Option(None, help="Max number of JS files to scan"),
    max_hits_per_file: int = typer.Option(200, help="Max hits per file"),
    out_json: Optional[str] = typer.Option(None, help="Write JSON report path"),
    out_html: Optional[str] = typer.Option(None, help="Write HTML report path"),
    repair_missing: bool = typer.Option(False, help="Re-download missing JS artifacts before scanning"),
    artifacts_dir: str = typer.Option("artifacts/js", help="Base folder for JS cache (used for repairs)"),
):
    """
    Scan DOWNLOADED JS artifacts (local files) using paths stored in DB (JSArtifact.path).
    Outputs masked previews + line/col to help you locate hits quickly in the saved file.
    """
    from datetime import datetime, timezone, timedelta

    from db.session import get_session
    from db.repo import ReconRepo
    from recon.js_secrets_finder import scan_files, write_json_report, write_html_report
    from recon.js_cache import ensure_js_cached
    from pathlib import Path

    def parse_since(s: str) -> Optional[datetime]:
        s = (s or "").strip().lower()
        if s in ("none", ""):
            return None
        if s == "24h":
            return datetime.now(timezone.utc) - timedelta(hours=24)
        if s == "7d":
            return datetime.now(timezone.utc) - timedelta(days=7)
        if s == "last-js":
            with get_session() as session:
                repo = ReconRepo(session)
                dt = repo.get_last_finished_run_time("js_analysis")
                return dt
        # ISO timestamp
        try:
            # accept "2025-12-26T12:00:00+00:00" etc
            return datetime.fromisoformat(s)
        except Exception:
            raise typer.BadParameter("Invalid only_changed_since. Use none|last-js|24h|7d|ISO timestamp")

    since_dt = parse_since(only_changed_since)

    with get_session() as session:
        repo = ReconRepo(session)
        items = repo.list_js_artifact_paths(
            program=program,
            only_with_secrets=only_with_secrets_flag,
            only_changed_after=since_dt,
            limit=limit,
        )

        if not items:
            typer.echo("[OK] No JS artifacts found to scan (did you run js_analysis?).")
            return

        missing = [(u, p) for (u, p) in items if not p or not Path(p).exists()]
        if missing and not repair_missing:
            typer.echo(
                f"[WARN] {len(missing)} JS artifacts are missing on disk. Re-run js_analysis or use --repair-missing.")
        elif missing and repair_missing:
            typer.echo(f"[REPAIR] {len(missing)} missing artifacts. Re-downloading into {artifacts_dir}/...")
            repaired_items: list[tuple[str, str]] = []
            repaired_ok = 0
            repaired_fail = 0

            for js_url, _old_path in items:
                # If it exists, keep it; if not, fetch it
                local_path = _old_path
                if not local_path or not Path(local_path).exists():
                    try:
                        local_path = ensure_js_cached(
                            repo=repo,
                            js_url=js_url,
                            program=program,
                            artifacts_dir=artifacts_dir,
                        )
                        if local_path:
                            repaired_ok += 1
                        else:
                            repaired_fail += 1
                    except Exception as e:
                        repaired_fail += 1
                        typer.echo(f"[REPAIR-FAIL] {js_url}: {e}")
                        local_path = None

                if local_path and Path(local_path).exists():
                    repaired_items.append((js_url, local_path))

            session.commit()
            items = repaired_items
            typer.echo(f"[REPAIR] ok={repaired_ok} fail={repaired_fail} remaining_to_scan={len(items)}")

    reports = scan_files(items, max_hits_per_file=max_hits_per_file)

    typer.echo(f"[SECRET-SCAN] files_considered={len(items)} files_with_hits={len(reports)} program={program or 'ALL'}")

    # CLI summary (masked previews only)
    for r in reports[:25]:
        typer.echo(f"\nFile: {r.js_url}")
        typer.echo(f"  path: {r.path}")
        typer.echo(f"  hits: {len(r.hits)}")
        for h in r.hits[:15]:
            typer.echo(f"   - {h.name} line={h.line}:{h.col} preview={h.preview}")

    if out_json:
        p = write_json_report(reports, out_json)
        typer.echo(f"\n[OK] JSON report: {p}")

    if out_html:
        p = write_html_report(reports, out_html)
        typer.echo(f"[OK] HTML report: {p}")


if __name__ == "__main__":
    app()

