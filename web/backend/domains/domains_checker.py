#! usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import datetime
import functools
import logging
import time
from typing import Optional

import aiohttp

from aiohttp import ClientSession, ClientTimeout
from bs4 import BeautifulSoup
from sqlalchemy import text, update, select, delete
from sqlalchemy.exc import SQLAlchemyError

from .urls_generator import domains_list
from .whois_parser import get_whois_record, save_whois_record
from ..db.model import async_engine, metadata, all_domains, dangerous_domains

logger = logging.getLogger(__name__)


async def measure_timing(function):
    @functools.wraps(function)
    def _measure(*args, **kwargs):
        start = time.perf_counter()
        try:
            return function(*args, **kwargs)
        finally:
            runtime = time.perf_counter() - start
            logger.info(f"{function.__name__} finished in {runtime} seconds.")

    return _measure


class Domain:
    def __init__(self, url, session, engine):
        self.url = url
        self.is_alive = False
        self.is_dangerous = False
        self.session = session
        self.engine = engine
        self.text = ""

    async def _fetch_html_async(self, **kwargs) -> str:
        """Fetch html from the url asynchronously

        :return: the requested page's html
        **kwargs are passed to 'self.session.request()'
        """
        timeout = ClientTimeout(total=1800)
        response = await self.session.request(
            method="GET", url=self.url, timeout=timeout, **kwargs
        )
        response.raise_for_status()
        logging.info(f"Got response {response.status} for URL: {self.url}")
        html = await response.text()
        return html

    async def _check_if_alive(self, **kwargs):
        """Check whether the site is alive
            **kwargs are passed to 'session.request()'
        """

        try:
            logger.info(f"Trying to reach {self.url}")
            html = await self._fetch_html_async(**kwargs)

        except (aiohttp.ClientError, aiohttp.http.HttpProcessingError) as e:
            logger.error(f"aiohttp exception for {self.url}: {e}")
            self.is_alive = False
            return False

        except Exception as e:
            logger.error(
                f"Non-aiohttp exception for {self.url} occurred: {e}")
            self.is_alive = False
            return False

        else:
            logger.info(f"Site {self.url} has responded")
            self.is_alive = True
            domain_page = BeautifulSoup(html, "html.parser")
            page_text = domain_page.get_text()
            self.text = page_text

    def _check_if_dangerous(self):
        flag_words = ["почт", "росси", "отправлени", "посылк", "письм", "писем"]
        self.text.replace("\n", " ")
        page_text = self.text.split()
        potential_infringements = set(
            word.lower() for word in page_text for flag_word in flag_words
            if flag_word in word.lower()
        )

        if len(potential_infringements) > 2:
            logger.info(f"Potentially dangerous: "
                        f"{len(potential_infringements)} have been found: "
                        f"{potential_infringements}")
            self.is_dangerous = True

    async def _get_last_updated(self) -> Optional[datetime.datetime]:
        select_stmt = (
            select(all_domains.c.last_updated).
            where(all_domains.c.url == self.url)
        )

        try:
            async with async_engine.begin() as conn:
                result = await conn.execute(select_stmt)
                last_updated = result.fetchone()
                return last_updated[0] if last_updated else None
        except (SQLAlchemyError, Exception) as e:
            logger.error(f"Unexpected error occurred: {e}")
            return None

    async def _make_checks(self, **kwargs):
        await self._check_if_alive(**kwargs)
        if self.is_alive:
            self._check_if_dangerous()

    async def _save_record(self):
        now = datetime.datetime.utcnow()
        upsert_stmt = text(
            f"INSERT INTO "
            f"    all_domains (url, is_alive, is_dangerous, last_updated) "
            f"VALUES "
            f"    ('{self.url}', {self.is_alive}, {self.is_dangerous}, '{now}') "
            f"ON CONFLICT (url) DO UPDATE SET "
            f"    is_alive={self.is_alive}, is_dangerous={self.is_dangerous},"
            f"    last_updated='{now}';"
        )

        try:
            async with self.engine.begin() as conn:
                await conn.execute(upsert_stmt)
                logger.info(f"Successfully written {self.url} to database")
        except (SQLAlchemyError, Exception) as e:
            logger.error(f"Unexpected error occurred: {e}")

    async def _mark_as_non_dangerous(self):
        upd_stmt = (
            update(all_domains).
                where(all_domains.c.url == self.url).
                values(is_dangerous=False)
        )

        try:
            async with async_engine.begin() as conn:
                await conn.execute(upd_stmt)
        except SQLAlchemyError as e:
            logger.error(f"Unexpected error occurred: {e}")

    async def _process_whois(self):
        whois_record = get_whois_record(self.url)

        if whois_record["owner_name"] == "JSC Russian Post":
            await self._mark_as_non_dangerous()

        await save_whois_record(whois_record)

    async def process_url(self, **kwargs):
        last_updated = await self._get_last_updated()
        if last_updated:
            delta = time.time() - last_updated.replace(
                tzinfo=datetime.timezone.utc).timestamp()
            logger.debug(f"Delta between now and last updated: {delta}")

        if not last_updated or delta >= 43200:
            await self._make_checks(**kwargs)
            await self._save_record()

            if self.is_dangerous:
                await self._process_whois()


async def delete_non_dangerous_domains():
    select_non_dangerous_stmt = (
        select(dangerous_domains.c.domain_id).
        select_from(dangerous_domains.join(
            all_domains,
            dangerous_domains.c.domain_id == all_domains.c.domain_id
        )).
        where(all_domains.c.is_dangerous == False)
    )

    async with async_engine.begin() as conn:
        result = await conn.execute(select_non_dangerous_stmt)
        non_dangerous_domains_ids = result.fetchall()

        for domain_id in non_dangerous_domains_ids:
            await conn.execute(
                delete(dangerous_domains).
                where(dangerous_domains.c.domain_id == domain_id[0])
            )


async def find_dangerous_domains(**kwargs) -> None:
    timeout = ClientTimeout(total=1800)
    connection_pool_size = aiohttp.TCPConnector(limit=1000)
    urls = domains_list
    tasks = []

    async with async_engine.begin() as conn:
        await conn.run_sync(metadata.create_all)

    while True:
        async with ClientSession(
            timeout=timeout, connector=connection_pool_size
        ) as session:
            for url in urls:
                domain = Domain(url=url, session=session, engine=async_engine)
                tasks.append(domain.process_url(**kwargs))

            await asyncio.gather(*tasks)

        await delete_non_dangerous_domains()
        logger.debug("Finished searching for dangerous domains")

        # Schedule next search in 24 hours
        await asyncio.sleep(86400)
