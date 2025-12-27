from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional


# ---------
# Schema
# ---------

@dataclass(frozen=True)
class InterestWeights:
    # Base events
    new_subdomain: int = 1
    new_service: int = 2
    new_url: int = 1

    # HTTP status signals (rare/interesting states)
    status_401: int = 3
    status_403: int = 3
    status_5xx: int = 4
    status_other_non_200: int = 1

    # URL pattern signals
    url_interesting: int = 3
    url_admin: int = 5
    url_auth: int = 4
    url_graphql: int = 6
    url_swagger_openapi: int = 6
    url_debug: int = 4
    url_upload: int = 4
    url_export: int = 3
    url_webhook: int = 4

    # JS artifact signals
    js_new_or_seen: int = 2
    js_changed: int = 4
    js_has_secrets: int = 7
    js_secret_count_per_hit: int = 1          # multiplied by capped secret_count
    js_secret_count_cap: int = 10             # cap contribution

    # Tech signals
    high_value_tech_hit: int = 5


@dataclass
class InterestItem:
    """
    A scored item that should bubble up to the hunter.
    `kind` examples: url|service|js|subdomain|tech
    """
    kind: str
    target: str
    score: int
    reasons: list[str]
    meta: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "target": self.target,
            "score": self.score,
            "reasons": self.reasons,
            "meta": self.meta,
        }


# ---------
# Classifier
# ---------

_ADMIN_RE = re.compile(r"(?i)(?:/admin\b|/administrator\b|/manage\b|/console\b)")
_AUTH_RE = re.compile(r"(?i)(?:/login\b|/signin\b|/auth\b|/oauth\b|/sso\b|/token\b)")
_GRAPHQL_RE = re.compile(r"(?i)/graphql\b")
_SWAGGER_RE = re.compile(r"(?i)(?:/swagger\b|/openapi\b|/api-docs\b)")
_DEBUG_RE = re.compile(r"(?i)(?:/debug\b|/actuator\b|/metrics\b|/health\b)")  # health is useful but noisy; keep weight modest
_UPLOAD_RE = re.compile(r"(?i)(?:/upload\b|/file\b|/files\b|/attachment\b)")
_EXPORT_RE = re.compile(r"(?i)(?:/export\b|/download\b|/report\b)")
_WEBHOOK_RE = re.compile(r"(?i)(?:/webhook\b|/hooks?\b|/callback\b)")


def classify_url(url: str) -> set[str]:
    tags: set[str] = set()
    if _ADMIN_RE.search(url): tags.add("admin")
    if _AUTH_RE.search(url): tags.add("auth")
    if _GRAPHQL_RE.search(url): tags.add("graphql")
    if _SWAGGER_RE.search(url): tags.add("swagger_openapi")
    if _DEBUG_RE.search(url): tags.add("debug")
    if _UPLOAD_RE.search(url): tags.add("upload")
    if _EXPORT_RE.search(url): tags.add("export")
    if _WEBHOOK_RE.search(url): tags.add("webhook")
    return tags


# ---------
# Scoring engine
# ---------

class InterestScorer:
    def __init__(self, weights: Optional[InterestWeights] = None) -> None:
        self.w = weights or InterestWeights()

    def score_url(self, url: str, is_interesting: bool = False, source: Optional[str] = None) -> InterestItem:
        reasons: list[str] = []
        score = self.w.new_url
        meta: dict[str, Any] = {"source": source}

        tags = classify_url(url)
        meta["tags"] = sorted(tags)

        if is_interesting:
            score += self.w.url_interesting
            reasons.append("matches interesting URL patterns")

        if "admin" in tags:
            score += self.w.url_admin
            reasons.append("admin/console path")
        if "auth" in tags:
            score += self.w.url_auth
            reasons.append("auth/login/token path")
        if "graphql" in tags:
            score += self.w.url_graphql
            reasons.append("GraphQL endpoint")
        if "swagger_openapi" in tags:
            score += self.w.url_swagger_openapi
            reasons.append("Swagger/OpenAPI docs")
        if "debug" in tags:
            score += self.w.url_debug
            reasons.append("debug/metrics/actuator path")
        if "upload" in tags:
            score += self.w.url_upload
            reasons.append("upload/files path")
        if "export" in tags:
            score += self.w.url_export
            reasons.append("export/download path")
        if "webhook" in tags:
            score += self.w.url_webhook
            reasons.append("webhook/callback path")

        if not reasons:
            reasons.append("new discovered URL")

        return InterestItem(kind="url", target=url, score=score, reasons=reasons, meta=meta)

    def score_service(self, url: str, status_code: Optional[int]) -> InterestItem:
        reasons: list[str] = ["new service"]
        score = self.w.new_service
        meta: dict[str, Any] = {"status_code": status_code}

        if status_code is None:
            return InterestItem(kind="service", target=url, score=score, reasons=reasons, meta=meta)

        if status_code == 401:
            score += self.w.status_401
            reasons.append("401 (auth boundary)")
        elif status_code == 403:
            score += self.w.status_403
            reasons.append("403 (access control boundary)")
        elif 500 <= status_code <= 599:
            score += self.w.status_5xx
            reasons.append("5xx (error state)")
        elif status_code != 200:
            score += self.w.status_other_non_200
            reasons.append("non-200 response")

        return InterestItem(kind="service", target=url, score=score, reasons=reasons, meta=meta)

    def score_js(
        self,
        js_url: str,
        changed: bool,
        has_secrets: bool,
        secret_count: int,
        secret_types: Optional[str],
    ) -> InterestItem:
        reasons: list[str] = []
        score = self.w.js_new_or_seen
        meta: dict[str, Any] = {
            "changed": bool(changed),
            "has_secrets": bool(has_secrets),
            "secret_count": int(secret_count or 0),
            "secret_types": secret_types or "",
        }

        if changed:
            score += self.w.js_changed
            reasons.append("JS changed (hash changed)")

        if has_secrets:
            score += self.w.js_has_secrets
            reasons.append("secret indicators detected")
            capped = min(int(secret_count or 0), self.w.js_secret_count_cap)
            if capped > 0:
                score += capped * self.w.js_secret_count_per_hit
                reasons.append(f"secret_count={secret_count} (capped at {self.w.js_secret_count_cap})")
            if secret_types:
                reasons.append(f"types={secret_types}")

        if not reasons:
            reasons.append("JS artifact observed")

        return InterestItem(kind="js", target=js_url, score=score, reasons=reasons, meta=meta)

    def score_tech(self, service_url: str, tech: str) -> InterestItem:
        return InterestItem(
            kind="tech",
            target=f"{service_url} :: {tech}",
            score=self.w.high_value_tech_hit,
            reasons=["high-value technology detected"],
            meta={"service_url": service_url, "tech": tech},
        )


def rank(items: list[InterestItem], top: int = 20) -> list[InterestItem]:
    items_sorted = sorted(items, key=lambda x: (x.score, len(x.reasons)), reverse=True)
    return items_sorted[: max(0, int(top))]
