#! usr/bin/env python3
# -*- coding: utf-8 -*-
import logging

import whois

from sqlalchemy import text

from ..db.model import async_engine


logger = logging.getLogger(__name__)


def get_whois_record(url: str) -> dict:
    """Get whois information on self.url. The collected whois record contains
    info on 4 parameters: "domain-name", "registrar-name", "owner-name" and
    "abuse-email"
    """

    try:
        whois_record = dict(whois.whois(url))
        if whois_record["domain_name"]:
            whois_record["domain_name"] = "https://" + whois_record["domain_name"].lower()
        else:
            whois_record["domain_name"] = url
        return whois_record

    except Exception:
        logger.info(f"Have not found whois record for {url}")
        return {"domain_name": url, "org": "", "registrar": "", "emails": ""}


async def save_whois_record(whois_record: dict):
    url = whois_record["domain_name"]
    owner_name = whois_record["org"] if whois_record["org"] else ""
    registrar_name = whois_record["registrar"] if whois_record["registrar"] else ""
    abuse_email = whois_record["emails"] if whois_record["emails"] else ""

    upsert_stmt = text(
        f"INSERT INTO dangerous_domains (url, owner_name, registrar_name, abuse_email) "
        f"VALUES ('{url}', '{owner_name}', '{registrar_name}', '{abuse_email}') "
        f"ON CONFLICT (url) DO UPDATE SET "
        f"owner_name='{url}', registrar_name='{owner_name}', "
        f"abuse_email='{abuse_email}';"
    )

    async with async_engine.begin() as conn:
        await conn.execute(upsert_stmt)
    logger.info(f"Saved whois record for {whois_record['domain_name']} to database")
