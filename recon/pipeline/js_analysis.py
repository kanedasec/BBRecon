from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from db.session import get_session
from db.repo import ReconRepo


JS_EXT_RE = re.compile(r"(?i)\.(mjs|js)(?:$|\?)")
JS_MAP_RE = re.compile(r"(?i)\.js\.map(?:$|\?)")
JS_CANDIDATE_RE = re.compile(r"(?i)\.(?:mjs|js)(?:$|[?#])|\.js\.map(?:$|[?#])")

# very pragmatic endpoint regexes
ABS_URL_RE = re.compile(r"https?://[a-z0-9\.\-_:]+(?:/[^\s\"\'\)<>\]]*)?", re.IGNORECASE)
REL_PATH_RE = re.compile(
    r"(?:(?:\"|')(/(?:api|graphql|swagger|openapi|api-docs|v1|v2|v3|rest)[^\"']+)(?:\"|'))",
    re.IGNORECASE,
)

# secrets-ish (pragmatic; tune later)
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}")
GENERIC_KEY_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|bearer|authorization)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
)

# optional: add some common patterns
AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")
GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,120}\b")

DOMAIN_RE = re.compile(r"(?i)\b([a-z0-9][a-z0-9\-]{0,62}\.)+[a-z]{2,}\b")


def is_js_url(u: str) -> bool:
    return bool(JS_CANDIDATE_RE.search((u or "").strip()))

def safe_filename_from_url(u: str) -> str:
    h = hashlib.sha1(u.encode("utf-8")).hexdigest()[:16]
    p = urlparse(u)
    base = os.path.basename(p.path) or "script.js"
    base = re.sub(r"[^a-zA-Z0-9\.\-_]+", "_", base)
    return f"{h}-{base}"


@dataclass
class JSAnalysisResult:
    js_url: str
    sha256: str
    size_bytes: int
    content_type: Optional[str]
    endpoints: list[str]
    domains: list[str]
    secret_types: list[str]
    secret_hits: list[str]


def download_js(url: str, timeout: int = 25) -> tuple[bytes, str | None]:
    r = requests.get(url, timeout=timeout, headers={"User-Agent": "ReconJS/1.0"})
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}")
    ctype = r.headers.get("content-type")
    return r.content, ctype


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def extract_from_js(js_text: str, base_url: str) -> tuple[list[str], list[str], list[str], list[str]]:
    """
    Returns: endpoints, domains, secret_types, secret_hits
    NOTE: secret_hits are SHORT SNIPPETS (no full dump). Types are what you store in DB.
    """
    endpoints: set[str] = set()
    domains: set[str] = set()

    secret_types: set[str] = set()
    secret_hits: set[str] = set()

    # absolute urls
    for m in ABS_URL_RE.findall(js_text):
        endpoints.add(m)

    # relative paths -> normalize to full URL
    for m in REL_PATH_RE.findall(js_text):
        try:
            endpoints.add(urljoin(base_url, m))
        except Exception:
            continue

    # domains
    for d in DOMAIN_RE.findall(js_text):
        domains.add(d.lower())

    # --- secrets-ish ---
    for s in JWT_RE.findall(js_text):
        secret_types.add("jwt")
        secret_hits.add(f"jwt:{s[:30]}...")

    for m in GENERIC_KEY_RE.finditer(js_text):
        secret_types.add("generic_key")
        secret_hits.add(m.group(0)[:120])

    for m in AWS_ACCESS_KEY_RE.finditer(js_text):
        secret_types.add("aws_access_key")
        secret_hits.add(m.group(0))

    for m in SLACK_TOKEN_RE.finditer(js_text):
        secret_types.add("slack_token")
        secret_hits.add(m.group(0)[:60] + "...")

    for m in GITHUB_TOKEN_RE.finditer(js_text):
        secret_types.add("github_token")
        secret_hits.add(m.group(0)[:60] + "...")

    return (
        sorted(endpoints),
        sorted(domains),
        sorted(secret_types),
        sorted(secret_hits),
    )


def run_js_analysis(
    program: str | None = None,
    artifacts_dir: str = "artifacts/js",
    only_new: bool = True,
    max_files: int | None = None,
) -> None:
    # 1) candidates
    with get_session() as session:
        repo = ReconRepo(session)
        candidates = repo.list_js_candidate_urls(program=program)

    candidates = [u for u in candidates if is_js_url(u)]
    if not candidates:
        print("[OK] No JS candidates found.")
        return

    # 2) run + process
    with get_session() as session:
        repo = ReconRepo(session)
        run_id = repo.start_run(
            step="js_analysis",
            meta={
                "program": program,
                "candidates": len(candidates),
                "only_new": only_new,
                "max_files": max_files,
            },
        )

        if only_new:
            targets = repo.list_missing_js_artifacts(candidates)
        else:
            targets = candidates

        if max_files is not None:
            targets = targets[: int(max_files)]

        print(f"[JS] candidates={len(candidates)} targets={len(targets)} program={program or 'ALL'}")

        base_dir = Path(artifacts_dir)
        if program:
            base_dir = base_dir / program
        base_dir.mkdir(parents=True, exist_ok=True)

        total_downloaded = 0
        total_endpoints = 0
        total_secrets = 0
        total_domains = 0

        discovered_to_insert: list[dict] = []

        for u in targets:
            try:
                body, ctype = download_js(u)
            except Exception as e:
                print(f"[FAIL] download {u}: {e}")
                continue

            digest = sha256_bytes(body)
            size = len(body)

            fname = safe_filename_from_url(u)
            fpath = str((base_dir / fname).resolve())
            with open(fpath, "wb") as f:
                f.write(body)

            try:
                text = body.decode("utf-8", errors="ignore")
            except Exception:
                text = ""

            endpoints, domains, secret_types, secret_hits = extract_from_js(text, base_url=u)

            # store artifact row (upsert)
            repo.upsert_js_artifact(
                url=u,
                sha256=digest,
                size_bytes=size,
                content_type=ctype,
                path=fpath,
                program=program,
                changed=False,
            )

            # mark secrets summary (no raw secrets stored)
            repo.mark_js_secrets(
                js_url=u,
                has_secrets=bool(secret_types),
                secret_types=secret_types,
                secret_count=len(secret_hits),
                program=program,
            )

            # feed endpoints back into discovered_urls
            for ep in endpoints:
                discovered_to_insert.append({"url": ep, "source": "js-analysis", "service_url": u})

            total_downloaded += 1
            total_endpoints += len(endpoints)
            total_domains += len(domains)
            total_secrets += len(secret_hits)

            print(
                f"[OK] {u} size={size} endpoints={len(endpoints)} domains={len(domains)} "
                f"secrets={len(secret_hits)} types={secret_types}"
            )

        if discovered_to_insert:
            uniq = {}
            for it in discovered_to_insert:
                url = (it.get("url") or "").strip()
                if url:
                    uniq[url] = it
            added = repo.upsert_discovered_urls(list(uniq.values()), program=program)
            print(f"[DB] js-analysis inserted discovered_urls: {added}")

        repo.finish_run(run_id)

    print("[DONE] JS Analysis")
    print(f"  downloaded: {total_downloaded}")
    print(f"  endpoints extracted: {total_endpoints}")
    print(f"  domains extracted:   {total_domains}")
    print(f"  secrets-ish hits:    {total_secrets}")
