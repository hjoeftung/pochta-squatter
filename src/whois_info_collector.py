#! usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio
import logging

import whois

from sqlalchemy import select, update, text
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
    select_dangerous_domains = select(all_domains.c.url).where(
        all_domains.c.is_dangerous == True)

    async with async_engine.begin() as conn:
        result = await conn.execute(select_dangerous_domains)
    dangerous_domains_list = [domain["url"] for domain in result.fetchall()]
    print(len(dangerous_domains_list))
    return dangerous_domains_list


async def mark_as_non_dangerous(domain_name):
    upd_stmt = (
        update(all_domains).
        where(all_domains.c.url == domain_name).
        values(is_dangerous=False)
    )
    async with async_engine.connect() as conn:
        await conn.execute(upd_stmt)


async def save_record(whois_record, progress_bar):
    url = whois_record['domain_name'] if whois_record['domain_name'] else ""
    owner_name = whois_record['org'] if whois_record['org'] else ""
    registrar_name = whois_record['registrar'] if whois_record['registrar'] else ""
    abuse_email = whois_record['emails'] if whois_record['emails'] else ""

    upsert_stmt = text(
        f"INSERT INTO dangerous_domains (url, owner_name, registrar_name, abuse_email) "
        f"VALUES ('{url}', '{owner_name}', '{registrar_name}', '{abuse_email}') "
        f"ON CONFLICT (url) DO UPDATE SET "
        f"owner_name='{url}', registrar_name='{owner_name}', "
        f"abuse_email='{abuse_email}';"
    )

    async with async_engine.begin() as conn:
        await conn.execute(upsert_stmt)
    next(progress_bar)
    logger.info(f"Saved whois record for {whois_record['domain_name']} to database")


async def gather() -> None:
    dangerous_domains_list = await get_dangerous_domains()
    progress_bar = ProgressBar(
        len(dangerous_domains_list), "Collecting info on dangerous domains"
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

        tasks.append(save_record(whois_record, progress_bar))

    await asyncio.gather(*tasks)


@measure_timing
def run_whois_queries():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(gather())


if __name__ == '__main__':
    run_whois_queries()