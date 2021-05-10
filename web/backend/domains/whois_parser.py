#! usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
import logging
import re
import time
from typing import Optional

import sqlalchemy.sql
import whois_alt

from sqlalchemy import text, select, insert
from sqlalchemy.exc import SQLAlchemyError

from ..db.model import async_engine, all_domains, registrars

logger = logging.getLogger(__name__)
REG_RU_NAMES = ["registrar of domain names reg.ru llc",
                "registrar of domain names reg.ru, llc",
                "regru-ru"]
RUCENTER_NAMES = ["regional network information center, jsc dba ru-center",
                  "ru-center-ru", "ru-center-rf"]

def prepare_url(url: str):
    """Drop 'http://' or 'https://' in the beginning of a url so that it
    could be passed to whois API"""

    try:
        url_match = re.match(r"https?://(.+)", url)
        main_url_part = url_match.group(1)
        return main_url_part
    except AttributeError:
        logger.error(f"Regexp did not find a match for url: {url}")
        return url


def get_whois_record(url: str) -> dict:
    """Get whois information on url.
        :return a dict containing four parameters of a retrieved whois record:
        'domain_name', 'owner_name', 'registrar_name', 'abuse_emails'
    """

    prepared_url = prepare_url(url)
    try:
        whois_record = whois_alt.get_whois(prepared_url)
        registrar_name = whois_record["registrar"][0] if (
            "registrar" in whois_record and whois_record["registrar"]) else ""
        abuse_emails = ", ".join(whois_record["emails"]) if (
            "emails" in whois_record and whois_record["emails"]) else ""

        if "contacts" in whois_record and whois_record["contacts"]:
            owner_name = whois_record["contacts"]["registrant"]
            owner_name = owner_name["organization"] if (
                    owner_name and "organization" in owner_name) else ""
        else:
            owner_name = ""

        return {"domain_name": url, "owner_name": owner_name,
                "registrar_name": registrar_name, "abuse_emails": abuse_emails}

    except whois_alt.shared.WhoisException as e:
        logger.info(f"Have not found whois record for {prepared_url}. "
                    f"Error message: {e}")
        return {"domain_name": url, "owner_name": "", "registrar_name": "",
                "abuse_emails": ""}


async def find_domain_id(domain_name: str) -> Optional[int]:
    select_stmt = (
        select(all_domains.c.domain_id).
        where(all_domains.c.url == domain_name)
    )

    try:
        async with async_engine.begin() as conn:
            result = await conn.execute(select_stmt)
            domain_id = result.fetchone()[0]
            return domain_id
    except Exception as e:
        logger.error(f"Unexpected error occurred: {e}")
        return sqlalchemy.sql.null()


async def find_registrar_id(registrar_name: str) -> Optional[int]:
    select_stmt = select(registrars.c.registrar_id). \
        where(registrars.c.registrar_name == registrar_name)

    try:
        async with async_engine.begin() as conn:
            result = await conn.execute(select_stmt)
            registrar_id = result.fetchone()[0]
            return registrar_id
    except Exception as e:
        logger.error(f"Unexpected error occurred: {e}")
        return None


async def save_registrar_info(registrar_name: str, abuse_emails: str):
    insert_stmt = (
        insert(registrars).
        values(registrar_name=registrar_name, abuse_emails=abuse_emails)
    )

    try:
        async with async_engine.begin() as conn:
            await conn.execute(insert_stmt)
    except SQLAlchemyError as e:
        logger.error(f"SQL error occurred: {e}")


async def save_domain_info(domain_id: int, owner_name: str,
                           registrar_id: Optional[int]):
    now = datetime.datetime.utcnow()
    upsert_stmt = text(f"""
            INSERT INTO dangerous_domains 
                (domain_id, owner_name, registrar_id, last_updated)
            VALUES 
                ({domain_id}, '{owner_name}', {registrar_id}, '{now}')
            ON CONFLICT (domain_id) DO UPDATE SET
                domain_id={domain_id}, owner_name='{owner_name}', 
                registrar_id={registrar_id}, last_updated='{now}';
        """)

    async with async_engine.begin() as conn:
        await conn.execute(upsert_stmt)


async def save_whois_record(whois_record: dict):
    domain_id = await find_domain_id(whois_record["domain_name"])
    registrar_name = whois_record["registrar_name"].lower().strip()
    abuse_emails = whois_record["abuse_emails"]
    owner_name = whois_record["owner_name"]
    registrar_id = sqlalchemy.sql.null()

    if registrar_name:
        if registrar_name in REG_RU_NAMES:
            registrar_name = "regru-ru"
        if registrar_name in RUCENTER_NAMES:
            registrar_name = "rucenter-ru"
        registrar_id = await find_registrar_id(registrar_name)
        if not registrar_id:
            await save_registrar_info(registrar_name, abuse_emails)
            registrar_id = await find_registrar_id(registrar_name)

    await save_domain_info(domain_id, owner_name, registrar_id)
    logger.info(
        f"Saved whois record for {whois_record['domain_name']} to database"
    )
