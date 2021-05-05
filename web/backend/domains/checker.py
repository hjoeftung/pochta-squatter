#! usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import functools
import logging
import time

import aiohttp

from aiohttp import ClientSession, ClientTimeout
from bs4 import BeautifulSoup
from sqlalchemy import text, update

from .urls_generator import domains_list
from .whois_parser import get_whois_record, save_whois_record
from ..db.model import async_engine, metadata, all_domains, dangerous_domains


logger = logging.getLogger(__name__)


def measure_timing(function):
    @functools.wraps(function)
    def _measure(*args, **kwargs):
        start = time.perf_counter()
        try:
            return function(*args, **kwargs)
        finally:
            runtime = time.perf_counter() - start
            print(f"{function.__name__} finished in {runtime} seconds.")

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
        timeout = ClientTimeout(total=300)
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
            logger.info(f"Potentially dangerous: {len(potential_infringements)} "
                        f"have been found: {potential_infringements}")
            self.is_dangerous = True

    async def _make_checks(self, **kwargs):
        await self._check_if_alive(**kwargs)
        if self.is_alive:
            self._check_if_dangerous()

    async def _save_record(self):
        upsert_stmt = text(
            f"INSERT INTO all_domains (url, is_alive, is_dangerous) "
            f"VALUES ('{self.url}', {self.is_alive}, {self.is_dangerous}) "
            f"ON CONFLICT (url) DO UPDATE SET "
            f"is_alive={self.is_alive}, is_dangerous={self.is_dangerous};"
        )

        try:
            async with self.engine.begin() as conn:
                await conn.execute(upsert_stmt)
                logger.info(f"Successfully written {self.url} to database")
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")

    async def mark_as_non_dangerous(self):
        upd_stmt = (
            update(all_domains).
                where(all_domains.c.url == self.url).
                values(is_dangerous=False)
        )

        try:
            async with async_engine.connect() as conn:
                await conn.execute(upd_stmt)
        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")

    async def process_whois(self):
        whois_record = get_whois_record(self.url)

        if whois_record["org"] == "JSC Russian Post":
            await self.mark_as_non_dangerous()
        if isinstance(whois_record["emails"], list):
            whois_record["emails"] = ", ".join(whois_record["emails"])

        await save_whois_record(whois_record)

    async def process_url(self, **kwargs):
        await self._make_checks(**kwargs)
        await self._save_record()

        if self.is_dangerous:
            await self.process_whois()


@measure_timing
async def find_dangerous_domains(**kwargs) -> None:
    timeout = ClientTimeout(total=1800)
    conn = aiohttp.TCPConnector(limit=1000)
    urls = domains_list

    async with ClientSession(timeout=timeout, connector=conn) as session:
        async with async_engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

        for url in urls:
            domain = Domain(url=url, session=session, engine=async_engine)
            await asyncio.create_task(domain.process_url(**kwargs))
