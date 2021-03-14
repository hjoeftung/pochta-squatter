#! usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import logging
import sys

import psycopg2

from src.infringement_checker import find_dangerous_domains
from src.model import async_engine
from src.whois_info_collector import run_whois_queries


# Initializing logger
logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    filename=".log"
)
logger = logging.getLogger(__name__)


def run_queries() -> None:
    # find_dangerous_domains()
    run_whois_queries()


async def export_to_csv() -> None:
    try:
        with open("squat_domains.csv", "w"):
            with async_engine.connect() as conn:
                await conn.execute(
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
        asyncio.run(export_to_csv())


if __name__ == "__main__":
    try:
        main(sys.argv[1])

    except IndexError:
        main()
