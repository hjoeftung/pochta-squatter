import asyncio
import os

import asyncpg

from dotenv import load_dotenv, find_dotenv
from sqlalchemy import MetaData, Table, Column, String, Boolean, ForeignKey, text
from sqlalchemy.ext.asyncio import create_async_engine


# Load database's params from .env
load_dotenv(dotenv_path=find_dotenv(), override=True)
user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
host = os.getenv("DB_HOST")
database = os.getenv("DB_NAME")

# Create sqlalchemy engine and metadata
url = f"postgresql+asyncpg://{user}:{password}@postgres:5432/{database}"
async_engine = create_async_engine(url, echo=True)
metadata = MetaData(bind=async_engine)


all_domains = Table(
    "all_domains", metadata,
    Column("url", String(150), primary_key=True),
    Column("is_alive", Boolean),
    Column("is_dangerous", Boolean)
)

dangerous_domains = Table(
    "dangerous_domains", metadata,
    Column("url", String(150), ForeignKey("all_domains.url"), primary_key=True),
    Column("owner_name", String(150)),
    Column("registrar_name", String(150)),
    Column("abuse_email", String(150))
)
