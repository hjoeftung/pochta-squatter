import asyncio
import os

from dotenv import load_dotenv, find_dotenv
from sqlalchemy import MetaData, Table, Column, String, Boolean, ForeignKey
from sqlalchemy.ext.asyncio import create_async_engine


# Load database's params from .env
load_dotenv(dotenv_path=find_dotenv(), override=True)
user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
host = os.getenv("DB_HOST")
database = os.getenv("DB_NAME")

# Create sqlalchemy engine and session
async_engine = create_async_engine(
    f"postgresql+asyncpg://{user}:{password}@{host}/{database}", echo=True
)
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


async def create_tables():
    async with async_engine.begin() as conn:
        await conn.run_sync(metadata.create_all())


def set_up_db():
    asyncio.run(create_tables())
