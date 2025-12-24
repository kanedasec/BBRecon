from __future__ import annotations

import typer
from typing import Optional

app = typer.Typer(no_args_is_help=True)


@app.command()
def run(
    step: str = typer.Option("all", help="scope|subdomains|probe|content|all"),
    program: Optional[str] = typer.Option(None, help="HackerOne team/program name"),
    all: bool = typer.Option(False, help="Run without program scoping"),
    interactive: bool = typer.Option(False, help="Allow interactive prompts (fallback)"),
    max_parallel: int = typer.Option(5, help="Parallelism for subdomain enum"),
    batch_size: int = typer.Option(500, help="Batch size for httpx probing"),
):
    from recon.pipeline.scope import run_scope_download
    from recon.pipeline.subdomains import run_subdomain_enum
    from recon.pipeline.probe import run_asset_probing
    from recon.pipeline.content import run_content_discovery

    if step == "all":
        run_scope_download(program=program, run_all=all, interactive=interactive)
        run_subdomain_enum(program=program, run_all=all, max_parallel=max_parallel)
        run_asset_probing(program=program, run_all=all, batch_size=batch_size)
        run_content_discovery(program=program, run_all=all)
        return

    if step == "scope":
        run_scope_download(program=program, run_all=all, interactive=interactive)
    elif step == "subdomains":
        run_subdomain_enum(program=program, run_all=all, max_parallel=max_parallel)
    elif step == "probe":
        run_asset_probing(program=program, run_all=all, batch_size=batch_size)
    elif step == "content":
        run_content_discovery(program=program, run_all=all)
    else:
        raise typer.BadParameter("Invalid step. Use scope|subdomains|probe|content|all")


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


if __name__ == "__main__":
    app()
