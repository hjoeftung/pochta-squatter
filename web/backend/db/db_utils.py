import logging
import csv

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from .model import async_engine, all_domains, dangerous_domains, registrars
from ..domains.whois_parser import prepare_url


logger = logging.getLogger(__name__)


async def get_dangerous_domains():
    select_dangerous_domains_stmt = select(
        all_domains.c.url, dangerous_domains.c.owner_name,
        registrars.c.registrar_name, registrars.c.abuse_emails,
        dangerous_domains.c.last_updated
    ).select_from(
        all_domains.join(
            dangerous_domains,
            all_domains.c.domain_id == dangerous_domains.c.domain_id
        ).join(
            registrars,
            dangerous_domains.c.registrar_id == registrars.c.registrar_id
        )
    )
    try:
        async with async_engine.begin() as conn:
            result = await conn.execute(select_dangerous_domains_stmt)
            rows = result.fetchall()
            result.close()
            rows = list(sorted(rows, key=lambda row: prepare_url(row["url"])))
            return rows

    except SQLAlchemyError as e:
        logger.error(
            f"SQLAlchemy error while selecting dangerous domains: {e}"
        )


async def get_dangerous_domains_list() -> list:
    rows = await get_dangerous_domains()
    logger.debug(f"There is a result: {rows}")
    dangerous_domains_list = []
    if rows:
        for domain in rows:
            domain = dict(domain)
            logger.debug(f"Here is domain: {domain}")
            domain["last_updated"] = domain["last_updated"].strftime("%d.%m.%Y")
            dangerous_domains_list.append(domain)
    return dangerous_domains_list


async def export_to_csv() -> None:
    path_to_csv_dir = "/usr/src/app/frontend/build/assets/csv/"
    csv_name = "dangerous_domains.csv"

    with open(f"{path_to_csv_dir + csv_name}", "w") as csv_file:
        rows = await get_dangerous_domains()
        logger.debug(rows[0]._fields())
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(rows[0]._fields())
        csv_writer.writerows(rows)
        logger.info("Data has been successfully exported to a CSV file")
