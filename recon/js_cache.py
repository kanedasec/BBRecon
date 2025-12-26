from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import requests

from db.repo import ReconRepo


def safe_filename_from_url(u: str) -> str:
    h = hashlib.sha1(u.encode("utf-8")).hexdigest()[:16]
    p = urlparse(u)
    base = os.path.basename(p.path) or "script.js"
    base = re.sub(r"[^a-zA-Z0-9\.\-_]+", "_", base)
    return f"{h}-{base}"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def download_js(url: str, timeout: int = 25, max_bytes: int = 5_000_000) -> tuple[bytes, str | None]:
    r = requests.get(url, timeout=timeout, headers={"User-Agent": "ReconJS/1.0"}, stream=True)
    if r.status_code != 200:
        raise RuntimeError(f"HTTP {r.status_code}")

    ctype = (r.headers.get("content-type") or None)

    data = bytearray()
    for chunk in r.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        data.extend(chunk)
        if len(data) > max_bytes:
            raise RuntimeError(f"too large > {max_bytes} bytes")

    return bytes(data), ctype


def ensure_js_cached(
    repo: ReconRepo,
    js_url: str,
    program: str | None,
    artifacts_dir: str = "artifacts/js",
    timeout: int = 25,
    max_bytes: int = 5_000_000,
) -> str | None:
    """
    Ensure the JS file for js_url exists on disk.
    Returns local file path if present/downloaded, else None.
    """
    js_url = (js_url or "").strip()
    if not js_url:
        return None

    base_dir = Path(artifacts_dir)
    if program:
        base_dir = base_dir / program
    base_dir.mkdir(parents=True, exist_ok=True)

    fname = safe_filename_from_url(js_url)
    fpath = str((base_dir / fname).resolve())
    p = Path(fpath)

    if p.exists() and p.is_file():
        return str(p)

    # Download + store
    body, ctype = download_js(js_url, timeout=timeout, max_bytes=max_bytes)
    p.write_bytes(body)

    digest = sha256_bytes(body)
    size = len(body)

    # Upsert artifact metadata/path in DB
    repo.upsert_js_artifact(
        url=js_url,
        sha256=digest,
        size_bytes=size,
        content_type=ctype,
        path=str(p),
        program=program,
        changed=False,
    )

    return str(p)
