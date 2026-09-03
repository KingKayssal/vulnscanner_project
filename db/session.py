"""
Engine/session management.
Local demo: SQLite file. Production: swap DATABASE_URL to Postgres, e.g.
    postgresql+psycopg://user:pass@host:5432/scanner
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .models import Base

DATABASE_URL = os.environ.get("SCANNER_DB_URL", "sqlite:///./scanner.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_session():
    return SessionLocal()
