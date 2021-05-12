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
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError

from .urls_generator import domains_list
from .whois_parser import get_whois_record, save_whois_record, executor
from ..db.db_utils import export_to_csv, whitelist_url
from ..db.model import async_engine, metadata, all_domains

logger = logging.getLogger(__name__)


async def measure_timing(function):
    @functools.wraps(function)
    def _measure(*args, **kwargs):
        start = time.perf_counter()
        try:
            return function(*args, **kwargs)
        finally:
            runtime = time.perf_counter() - start
            executor.submit(
                logger.info,
                f"{function.__name__} finished in {runtime} seconds."
            )

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
            executor.submit(logger.info, f"Trying to reach {self.url}")
            html = await self._fetch_html_async(**kwargs)

        except (aiohttp.ClientError, aiohttp.http.HttpProcessingError) as e:
            executor.submit(
                logger.error, f"aiohttp exception for {self.url}: {e}"
            )
            self.is_alive = False
            return False

        except Exception as e:
            executor.submit(
                logger.error,
                f"Non-aiohttp exception for {self.url} occurred: {e}"
            )
            self.is_alive = False
            return False

        else:
            executor.submit(logger.info, f"Site {self.url} has responded")
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
            executor.submit(
                logger.info,
                f"Potentially dangerous: "
                f"{len(potential_infringements)} have been found: "
                f"{potential_infringements}"
            )
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
                result.close()
                return last_updated[0] if last_updated else None
        except (SQLAlchemyError, Exception) as e:
            executor.submit(logger.error, f"Unexpected error occurred: {e}")
            return None

    async def _check_if_whitelisted(self):
        select_stmt = (
            select(all_domains.c.whitelisted).
                where(all_domains.c.url == self.url)
        )
        try:
            async with async_engine.begin() as conn:
                result = await conn.execute(select_stmt)
                whitelisted = result.fetchone()
                result.close()
                return (whitelisted[0]
                        if whitelisted
                        else False)
        except (SQLAlchemyError, Exception) as e:
            executor.submit(logger.error, f"Unexpected error occurred: {e}")
            return False

    async def _make_checks(self, **kwargs):
        await self._check_if_alive(**kwargs)
        if self.is_alive:
            self._check_if_dangerous()

    async def _save_record(self):
        now = datetime.datetime.utcnow()
        insert_stmt = (
            insert(all_domains).
                values(
                url=self.url, is_alive=self.is_alive,
                is_dangerous=self.is_dangerous, last_updated=now,
                whitelisted=False
            )
        )
        do_update_stmt = insert_stmt.on_conflict_do_update(
            index_elements=["url"],
            set_=dict(is_alive=self.is_alive, is_dangerous=self.is_dangerous,
                      last_updated=now)
        )
        try:
            async with self.engine.begin() as conn:
                await conn.execute(do_update_stmt)
                executor.submit(
                    logger.info,
                    f"Successfully written {self.url} to database"
                )
        except (SQLAlchemyError, Exception) as e:
            executor.submit(logger.error, f"Unexpected error occurred: {e}")

    async def _process_whois(self):
        whois_record = get_whois_record(self.url)

        if whois_record["owner_name"] == "JSC Russian Post":
            await whitelist_url(self.url)

        await save_whois_record(whois_record)

    async def process_url(self, **kwargs):
        last_updated = await self._get_last_updated()
        whitelisted = await self._check_if_whitelisted()
        if last_updated:
            delta = time.time() - last_updated.replace(
                tzinfo=datetime.timezone.utc).timestamp()
            executor.submit(
                logger.debug, f"Delta between now and last updated: {delta}"
            )

        # Skip making checks if the domain info was recently updated or
        # the domain has been whitelisted by the user
        if not last_updated or (delta >= 43200 and not whitelisted):
            await self._make_checks(**kwargs)
            await self._save_record()

            if self.is_dangerous:
                await self._process_whois()


async def find_dangerous_domains(**kwargs) -> None:
    timeout = ClientTimeout(total=1800)
    connection_pool_size = aiohttp.TCPConnector(limit=1000)
    urls = domains_list
    tasks = []

    async with async_engine.begin() as conn:
        await conn.run_sync(metadata.create_all)

    async with ClientSession(
            timeout=timeout, connector=connection_pool_size
    ) as session:
        for url in urls:
            domain = Domain(url=url, session=session, engine=async_engine)
            tasks.append(domain.process_url(**kwargs))
        await asyncio.gather(*tasks)
    executor.submit(logger.debug, "Finished searching for dangerous domains")
    await export_to_csv()
