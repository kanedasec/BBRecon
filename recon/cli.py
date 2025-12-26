from __future__ import annotations

import typer
from typing import Optional

app = typer.Typer(no_args_is_help=True)


@app.command()
def run(
    step: str = typer.Option("all", help="scope|subdomains|probe|fingerprint|content|all"),
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

    if step == "all":
        run_scope_download(program=program, run_all=all, interactive=interactive)
        run_subdomain_enum(program=program, run_all=all, max_parallel=max_parallel)
        run_asset_probing(program=program, run_all=all, batch_size=batch_size)
        run_fingerprinting(program=program, run_all=all, batch_size=fp_batch_size)
        run_content_discovery(program=program, run_all=all)
        return

    if step == "scope":
        run_scope_download(program=program, run_all=all, interactive=interactive)
    elif step == "subdomains":
        run_subdomain_enum(program=program, run_all=all, max_parallel=max_parallel)
    elif step == "probe":
        run_asset_probing(program=program, run_all=all, batch_size=batch_size)
    elif step == "fingerprint":
        run_fingerprinting(program=program, run_all=all, batch_size=fp_batch_size)
    elif step == "content":
        run_content_discovery(program=program, run_all=all)
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

    # ✅ NEW: Tech summary (only if supported)
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



if __name__ == "__main__":
    app()

