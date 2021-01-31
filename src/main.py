#! usr/bin/env python3
# -*- coding: utf-8 -*-


import logging
import os
import sys

import psycopg2

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv, find_dotenv

from async_domain_parser import make_async_queries
from sync_domain_parser import make_sync_queries, InfringingDomainDB

# Initializing logger
logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("main")

# Load database's params from .env
load_dotenv(dotenv_path=find_dotenv(), override=True)
user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
host = os.getenv("DB_HOST")
database = os.getenv("DB_NAME")

# Create sqlalchemy engine and session
engine = create_engine(f"postgresql://{user}:{password}@{host}/{database}", echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


def count_rows():
    return session.query(InfringingDomainDB).count()


def run_queries() -> None:
    # make_async_queries()
    make_sync_queries()
    print("Database has been successfully updated")


def export_to_csv() -> None:
    try:
        with open("squat_domains.csv", "w"):
            with engine.connect() as conn:
                conn.execute(
                    f"""
                       COPY (SELECT * FROM infringing_domains) 
                            TO '/tmp/squat_domains.csv'
                            WITH (FORMAT CSV, HEADER);
                       """
                )

            print("Data has been successfully exported to a CSV file")

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL:", error)


def main(instruction="run"):
    if instruction == "run":
        run_queries()

    elif instruction == "export":
        export_to_csv()


if __name__ == "__main__":
    try:
        main(sys.argv[1])

    except IndexError:
        main()
