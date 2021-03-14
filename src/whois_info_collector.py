#! usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import logging

import whois

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert

from src.infringement_checker import measure_timing
from src.model import async_engine, all_domains, dangerous_domains
from src.progress_bar import ProgressBar


logger = logging.getLogger(__name__)


def get_whois_record(url: str) -> dict:
    """Get whois information on self.url. The collected whois record contains
    info on 4 parameters: "domain-name", "registrar-name", "owner-name" and
    "abuse-email"
    """

    try:
        whois_record = whois.whois(url)
        if whois_record["domain_name"]:
            whois_record["domain_name"] = "https://" + whois_record["domain_name"].lower()
        else:
            whois_record["domain_name"] = url

        return whois_record

    except whois.parser.PywhoisError:
        logger.info(f"Have not found whois record for {url}")
        return {"domain_name": url, "org": "", "registrar": "", "emails": ""}


async def get_dangerous_domains():
    select_dangerous_domains = select([all_domains.c.url]).where(
        all_domains.c.is_dangerous == True)

    async with async_engine.begin() as conn:
        dangerous_domains_list = await conn.execute(select_dangerous_domains)

    return [domain["url"] for domain in dangerous_domains_list]


async def mark_as_non_dangerous(domain_name):
    upd_stmt = (
        update(all_domains).
        where(all_domains.c.url == domain_name).
        values(is_dangerous=False)
    )
    async with async_engine.connect() as conn:
        await conn.execute(upd_stmt)


async def save_record(whois_record):
    insert_values = insert(dangerous_domains).values(
        url=f"{whois_record['domain_name']}",
        owner_name=f"{whois_record['org']}",
        registrar_name=f"{whois_record['registrar']}",
        abuse_email=f"{whois_record['emails']}"
    )
    update_records = insert_values.on_conflict_do_update(
        index_elements=[dangerous_domains.c.url],
        set_=dict(
            owner_name=insert_values.excluded.owner_name,
            registrar_name=insert_values.excluded.registrar_name,
            abuse_email=insert_values.excluded.abuse_email
        )
    )
    async with async_engine.connect() as conn:
        await conn.execute(update_records)

    logger.info(f"Saved whois record for {whois_record['domain_name']} to database")


async def gather() -> None:
    dangerous_domains_list = await get_dangerous_domains()
    progress_bar = ProgressBar(
        len(list(dangerous_domains_list)),
        "Collecting info on dangerous domains"
    )
    tasks = []
    for url in dangerous_domains_list:
        whois_record = get_whois_record(url)
        logger.info(f"Received whois record for: {url}")

        if whois_record["org"] == "JSC Russian Post":
            tasks.append(mark_as_non_dangerous(url))
            next(progress_bar)
            continue
        if isinstance(whois_record["emails"], list):
            whois_record["emails"] = ", ".join(whois_record["emails"])

        tasks.append(save_record(whois_record))
        next(progress_bar)

    await asyncio.gather(*tasks)


@measure_timing
def run_whois_queries():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(gather())


if __name__ == '__main__':
    run_whois_queries()