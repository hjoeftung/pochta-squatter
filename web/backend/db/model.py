import os

from dotenv import load_dotenv, find_dotenv
from sqlalchemy import (MetaData, Table, Column, String,
                        Boolean, Integer, ForeignKey, DateTime)
from sqlalchemy.ext.asyncio import create_async_engine


# Load database"s params from .env
load_dotenv(dotenv_path=find_dotenv(), override=True)
user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
host = os.getenv("DB_HOST")
database = os.getenv("DB_NAME")

# Create sqlalchemy engine and metadata
url = f"postgresql+asyncpg://{user}:{password}@postgres:5432/{database}"
async_engine = create_async_engine(url, echo=True)
convention = {
    "all_column_names": lambda constraint, table: "_".join([
        column.name for column in constraint.columns.values()
    ]),
    "ix": "ix__%(table_name)s__%(all_column_names)s",
    "uq": "uq__%(table_name)s__%(all_column_names)s",
    "ck": "ck__%(table_name)s__%(constraint_name)s",
    "fk": "fk__%(table_name)s__%(all_column_names)s__%(referred_table_name)s",
    "pk": "pk__%(table_name)s"
}

metadata = MetaData(naming_convention=convention)

all_domains = Table(
    "all_domains", metadata,
    Column("domain_id", Integer, primary_key=True, autoincrement=True),
    Column("url", String(150), unique=True, index=True),
    Column("is_alive", Boolean),
    Column("is_dangerous", Boolean),
    Column("last_updated", DateTime)
)

dangerous_domains = Table(
    "dangerous_domains", metadata,
    Column("domain_id", Integer, ForeignKey("all_domains.domain_id"),
           primary_key=True),
    Column("owner_name", String(150)),
    Column("registrar_id", ForeignKey("registrars.registrar_id")),
    Column("last_updated", DateTime)
)

registrars = Table(
    "registrars", metadata,
    Column("registrar_id", Integer, primary_key=True, autoincrement=True),
    Column("registrar_name", String(150), unique=True),
    Column("abuse_emails", String(150))
)
