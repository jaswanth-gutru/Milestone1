from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Temporary local database for backend testing
DATABASE_URL = "sqlite:///./app.db"

# Create the SQLAlchemy engine
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # needed for SQLite in FastAPI
)

# Create a session local class
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our ORM models
Base = declarative_base()

