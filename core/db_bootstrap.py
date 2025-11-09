# finbot/core/db_bootstrap.py

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from finbot.config import settings

# Import all ORM models so they’re registered in SQLAlchemy’s metadata.
# If your models live elsewhere, add imports here.
# Example: from finbot.core.auth.session import UserSession, Base
from finbot.core.auth import session as session_mod  # this should define Base and models

def create_all_tables() -> None:
    """
    Create all tables if they don't exist (SQLite/Postgres).
    Safe to call multiple times.
    """
    database_url = settings.get_database_url()
    engine = create_engine(database_url, **settings.get_database_config())

    # ensure models are imported BEFORE calling create_all
    Base = getattr(session_mod, "Base", None)
    if Base is None:
        raise RuntimeError("Could not find SQLAlchemy Base in finbot.core.auth.session")

    Base.metadata.create_all(bind=engine)

    # quick ping to ensure DB is reachable
    with Session(engine) as s:
        s.execute("SELECT 1")
