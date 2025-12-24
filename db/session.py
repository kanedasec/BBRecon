from __future__ import annotations

import os
from contextlib import contextmanager

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from .base import Base

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///recon.db")

# For SQLite: needed for multithreaded collectors
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    echo=False,          
    future=True,
    connect_args=connect_args
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    """Create tables if they don't exist yet."""
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_session() -> Session:
    """Context manager that auto-commits/rollbacks."""
    init_db()
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
