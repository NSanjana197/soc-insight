import pytest
from app.database import Base, engine, SessionLocal
from app import models  # noqa: F401  (register models on Base)


@pytest.fixture(autouse=True)
def _reset_db():
    """Every test starts with a completely clean, empty database -
    applies whether a test uses the `db` fixture directly or drives
    everything through the API via TestClient."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db(_reset_db):
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
