from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    String,
    Integer,
    DateTime,
    Text,
    ForeignKey,
    UniqueConstraint,
    Boolean,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    step: Mapped[str] = mapped_column(String(50), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    meta_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<Run id={self.id} step={self.step} started_at={self.started_at}>"


class Program(Base):
    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    platform: Mapped[str] = mapped_column(String(40), default="hackerone")

    scopes: Mapped[list["ScopeDomain"]] = relationship(back_populates="program")

    def __repr__(self) -> str:
        return f"<Program id={self.id} name={self.name}>"


class ScopeDomain(Base):
    __tablename__ = "scopes"
    __table_args__ = (
        UniqueConstraint("program_id", "domain", name="uq_scope_program_domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    program: Mapped["Program"] = relationship(back_populates="scopes")

    def __repr__(self) -> str:
        return f"<ScopeDomain program_id={self.program_id} domain={self.domain}>"


class Subdomain(Base):
    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[Optional[int]] = mapped_column(ForeignKey("programs.id"), nullable=True, index=True)

    fqdn: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    root_domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    def __repr__(self) -> str:
        return f"<Subdomain fqdn={self.fqdn}>"


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[Optional[int]] = mapped_column(ForeignKey("programs.id"), nullable=True, index=True)

    url: Mapped[str] = mapped_column(String(2048), unique=True, index=True)
    fqdn: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    scheme: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)
    host: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    port: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)

    title: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    webserver: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    def __repr__(self) -> str:
        return f"<Service url={self.url}>"


class DiscoveredURL(Base):
    __tablename__ = "discovered_urls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[Optional[int]] = mapped_column(ForeignKey("programs.id"), nullable=True, index=True)

    url: Mapped[str] = mapped_column(String(2048), unique=True, index=True)
    source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    service_url: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class Fingerprint(Base):
    __tablename__ = "fingerprints"
    __table_args__ = (
        UniqueConstraint("service_url", "tech", name="uq_fingerprint_service_tech"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[Optional[int]] = mapped_column(ForeignKey("programs.id"), nullable=True, index=True)

    service_url: Mapped[str] = mapped_column(String(2048), index=True)
    tech: Mapped[str] = mapped_column(String(120), index=True)

    source: Mapped[Optional[str]] = mapped_column(String(50), nullable=True, index=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    def __repr__(self) -> str:
        return f"<Fingerprint tech={self.tech} service_url={self.service_url}>"

class JSArtifact(Base):
    __tablename__ = "js_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[Optional[int]] = mapped_column(ForeignKey("programs.id"), nullable=True, index=True)

    url: Mapped[str] = mapped_column(String(2048), unique=True, index=True)
    sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    content_type: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    path: Mapped[Optional[str]] = mapped_column(String(2048), nullable=True)

    has_secrets: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    secret_types: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)  # "jwt,aws_key,..."
    secret_count: Mapped[int] = mapped_column(Integer, default=0)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    last_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    def __repr__(self) -> str:
        return f"<JSArtifact url={self.url} sha256={self.sha256}>"
