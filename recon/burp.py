from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from db.session import get_session
from db.repo import ReconRepo


def _utc_stamp() -> str:
    # Burp-friendly filename stamp: 2025-12-24T17_58_22Z
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H_%M_%SZ")


def _escape_host_for_regex(host: str) -> str:
    # turn "recruitment.roke.co.uk" into "recruitment\.roke\.co\.uk"
    return re.escape(host.strip().lower().rstrip("."))


def _burp_entry(host: str, protocol: str, port: int) -> dict:
    # Burp scope entries use regex strings (already anchored in your example)
    return {
        "enabled": True,
        "file": "^/.*",
        "host": f"^{_escape_host_for_regex(host)}$",
        "port": f"^{port}$",
        "protocol": protocol,
    }


def build_burp_config(
    program: str,
    include_wildcard_roots: bool = True,
    exclude_hosts_status: Optional[int] = 403,
) -> dict:
    """
    Build a Burp project configuration snippet for Target Scope.
    - include_wildcard_roots: include ^.*\.root$ entries from scope domains
    - exclude_hosts_status: e.g. 403 -> exclude hosts that consistently return 403 (from services table)
    """
    program = program.strip()
    if not program:
        raise ValueError("program is required")

    with get_session() as session:
        repo = ReconRepo(session)

        roots = repo.list_scope_domains(program=program)
        if not roots:
            raise ValueError(f"No scope domains found for program={program}. Run scope first.")

        include: list[dict] = []
        exclude: list[dict] = []

        # Include roots as wildcard (and also exact root) on 80/443
        if include_wildcard_roots:
            for root in roots:
                root = root.strip().lower().rstrip(".")
                # wildcard: ^.*\.root$
                wildcard_host = f"^.*\\.{re.escape(root)}$"
                include.append({"enabled": True, "file": "^/.*", "host": wildcard_host, "port": "^80$", "protocol": "http"})
                include.append({"enabled": True, "file": "^/.*", "host": wildcard_host, "port": "^443$", "protocol": "https"})

                # optional: exact root too (some programs include apex)
                exact = f"^{re.escape(root)}$"
                include.append({"enabled": True, "file": "^/.*", "host": exact, "port": "^80$", "protocol": "http"})
                include.append({"enabled": True, "file": "^/.*", "host": exact, "port": "^443$", "protocol": "https"})

        # Exclude hosts by status_code (commonly 403)
        if exclude_hosts_status is not None:
            triples = repo.list_service_host_triples_by_status(
                status_codes=[int(exclude_hosts_status)],
                program=program,
            )

            for host, _port, _scheme in triples:
                # Exclude both 80/443 variants to match your example behavior
                exclude.append(_burp_entry(host, "http", 80))
                exclude.append(_burp_entry(host, "https", 443))

    return {
        "target": {
            "scope": {
                "advanced_mode": True,
                "exclude": exclude,
                "include": include,
            }
        }
    }


def write_burp_config(program: str, out_path: str, exclude_hosts_status: Optional[int] = 403) -> str:
    Path(out_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    cfg = build_burp_config(program=program, exclude_hosts_status=exclude_hosts_status)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, separators=(",", ":"))
    return out_path


def export_alive_urls(program: str, out_path: str, status_code: int = 200) -> str:
    """
    Export URLs from services table with status_code (default 200).
    Output is plain text, one URL per line.
    """
    Path(out_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)

    with get_session() as session:
        repo = ReconRepo(session)
        urls = repo.list_service_urls(status_code=int(status_code), program=program)

    with open(out_path, "w", encoding="utf-8") as f:
        for u in urls:
            f.write(u + "\n")

    return out_path


def default_burp_filename(program: str) -> str:
    return f"artifacts/{program}-{_utc_stamp()}.json"


def default_urls_filename(program: str, status_code: int) -> str:
    return f"artifacts/{program}-urls-{status_code}-{_utc_stamp()}.txt"
