"""
Database setup for SOC-Insight.

Uses SQLite by default so the project runs with zero external setup.
To move to PostgreSQL later, just change DATABASE_URL, e.g.:

    postgresql://user:password@localhost:5432/soc_insight

...and `pip install psycopg2-binary`. No other code changes are needed
because everything goes through SQLAlchemy's ORM.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.environ.get("SOC_DATABASE_URL", "sqlite:///./soc_insight.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session and closes it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Create all tables. Called once on startup."""
    # Import models here so they're registered on Base before create_all runs.
    from app import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
