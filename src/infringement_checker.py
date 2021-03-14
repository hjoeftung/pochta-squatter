#! usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import functools
import logging
import time

import aiohttp

from aiohttp import ClientSession, ClientTimeout
from bs4 import BeautifulSoup
from sqlalchemy.dialects.postgresql import insert

from src.domains_generator import domains_list
from src.model import async_engine, all_domains, metadata
from src.progress_bar import ProgressBar


logger = logging.getLogger(__name__)
progress_bar = ProgressBar(len(domains_list), "Checking for dangerous urls")


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

    async def _fetch_html_async(self, **kwargs) -> str:
        """Fetch html from the url asynchronously

        :return: the requested page's html
        **kwargs are passed to 'self.session.request()'
        """
        timeout = ClientTimeout(3)
        response = await self.session.request(
            method="GET", url=self.url, timeout=timeout, **kwargs)
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
            logger.error(
                f"aiohttp exception for {self.url}: {e}")

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

            self.html = page_text

    def _check_if_dangerous(self):
        flag_words = ["почт", "росси", "отправлени", "посылк", "письм", "писем"]
        self.html.replace("\n", " ")
        text = self.html.split()
        potential_infringements = set(
            word.lower() for word in text for flag_word in flag_words
            if flag_word in word.lower()
        )

        if len(potential_infringements) > 2:
            logger.info(f"Potentially dangerous: {len(potential_infringements)} "
                        f"have been found: {potential_infringements}")
            self.is_dangerous = True

    async def _collect_info(self, **kwargs):
        await self._check_if_alive(**kwargs)
        if self.is_alive:
            self._check_if_dangerous()

    async def _save_record(self):
        insert_values = insert(all_domains).values(
            url=f"{self.url}",
            is_alive=self.is_alive,
            is_dangerous=self.is_dangerous
        )
        update_records = insert_values.on_conflict_do_update(
            index_elements=[all_domains.c.url],
            set_=dict(is_alive=insert_values.excluded.is_alive,
                      is_dangerous=insert_values.excluded.is_alive))

        try:
            async with self.engine.connect() as conn:
                await conn.execute(update_records)
                logger.info(f"Successfully written {self.url} to database")

        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")

    async def collect_and_save(self, **kwargs):
        await self._collect_info(**kwargs)
        await self._save_record()
        next(progress_bar)


async def gather(**kwargs) -> None:
    timeout = ClientTimeout(total=1800)

    async with ClientSession(timeout=timeout) as session:
        async with async_engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

            tasks = []
            urls = domains_list

            for url in urls:
                domain = Domain(url=url, session=session, engine=async_engine)
                tasks.append(domain.collect_and_save(**kwargs))
            await asyncio.gather(*tasks)


@measure_timing
def find_dangerous_domains() -> None:
    """Main function running the requests and
    saving results to database"""
    loop = asyncio.get_event_loop()
    loop.run_until_complete(gather())


if __name__ == "__main__":
    find_dangerous_domains()
