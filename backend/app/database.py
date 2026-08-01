from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.pool import NullPool
import os
from dotenv import load_dotenv
load_dotenv()

# Base de datos PostgreSQL
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://honeypot:honeypot@localhost:5432/honeypot")

engine = create_engine(
    DATABASE_URL,
    poolclass=NullPool,
    echo=False
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """Dependency para FastAPI: proporciona sesión de BD."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Crear tablas."""
    Base.metadata.create_all(bind=engine)