import logging

import psycopg2
from sqlalchemy import select

from pochta_squatter.db.model import (
    async_engine, all_domains, dangerous_domains)


logger = logging.getLogger(__name__)


async def get_dangerous_domains():
    select_dangerous_domains = select(
        all_domains.c.url, all_domains.c.is_alive, all_domains.c.is_dangerous,
        dangerous_domains.c.owner_name, dangerous_domains.c.registrar_name,
        dangerous_domains.c.abuse_email
    ).select_from(
        all_domains.join(
            dangerous_domains, all_domains.c.url == dangerous_domains.c.url)
    )

    async with async_engine.begin() as conn:
        result = await conn.execute(select_dangerous_domains)
    dangerous_domains_list = [dict(domain) for domain in result.fetchall()]
    return dangerous_domains_list


async def export_to_csv() -> None:
    try:
        with open("squat_domains.csv", "w"):
            with async_engine.connect() as conn:
                await conn.execute(
                    f"""
                       COPY (SELECT * FROM all_domains JOIN dangerous_domains
                       ON all_domains.url = dangerous_domains.url) 
                            TO '/tmp/squat_domains.csv'
                            WITH (FORMAT CSV, HEADER);
                       """
                )

            logger.info("Data has been successfully exported to a CSV file")

    except (Exception, psycopg2.Error) as error:
        logger.info("Error while connecting to PostgreSQL:", error)
