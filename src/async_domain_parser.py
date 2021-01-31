#! usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import sys
import time

import aiohttp

from aiohttp import ClientSession, ClientTimeout
from aiopg.sa import create_engine
from dotenv import load_dotenv, find_dotenv
from bs4 import BeautifulSoup
from sqlalchemy import Table, Column, Boolean, String, MetaData
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.schema import CreateTable

from domains_generator import generate_final_domains_list


logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("async_domain_parser")

# Load database's params from .env
load_dotenv(dotenv_path=find_dotenv(), override=True)
user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
host = os.getenv("DB_HOST")
database = os.getenv("DB_NAME")

# Create aiopg.sa engine and load metadata
metadata = MetaData()
all_domains = Table("all_domains", metadata,
                    Column("url", String(150), primary_key=True, unique=True),
                    Column("is_alive", Boolean),
                    Column("is_dangerous", Boolean)
                    )


class Domain:
    def __init__(self, url, session, engine):
        self.url = url
        self.is_alive = False
        self.is_dangerous = False
        self.session = session
        self.engine = engine
        self.html = ""

    async def fetch_html_async(self, **kwargs) -> str:
        """Fetch html from the url asynchronously

        :return: the requested page's html
        **kwargs are passed to 'self.session.request()'
        """

        response = await self.session.request(method="GET", url=self.url,
                                              allow_redirects=True, **kwargs)
        response.raise_for_status()
        logging.info(f"Got response {response.status} for URL: {self.url}")
        html = await response.text()
        return html

    async def check_if_alive(self, **kwargs):
        """Check whether the site is alive

            **kwargs are passed to 'session.request()'
        """

        try:
            logger.info(f"Trying to reach {self.url}")
            html = await self.fetch_html_async(**kwargs)

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

    def check_if_dangerous(self):
        """if "Домен продается" or "домен продается" in self.html:
            self.is_dangerous = False
            return"""

        flag_words = ["почт", "росси", "отправлени", "посылк", "письм", "писем"]
        self.html.replace("\n", " ")
        text = self.html.split()
        potential_infringements = set(
            word.lower() for word in text for flag_word in flag_words
            if flag_word in word.lower()
        )

        if len(potential_infringements) > 2:
            logger.info(f"Potentially infringes: {len(potential_infringements)} "
                        f"have been found: {potential_infringements}")
            self.is_dangerous = True

    async def collect_and_save_to_db(self, **kwargs):
        """Collect and format whois data on the domain name"""

        await self.check_if_alive(**kwargs)
        if self.is_alive:
            self.check_if_dangerous()

        try:
            async with self.engine.acquire() as conn:
                insert_values = insert(all_domains).values(
                    url=f"{self.url}",
                    is_alive=self.is_alive,
                    is_dangerous=self.is_dangerous
                )
                update_records = insert_values.on_conflict_do_update(
                    index_elements=['url'],
                    set_=dict(is_alive=self.is_alive,
                              is_dangerous=self.is_dangerous)
                )
                await conn.execute(update_records)
                logger.info(f"Successfully written {self.url} to database")

        except Exception as e:
            logger.error(f"Unexpected error occurred: {e}")


async def gather(**kwargs) -> None:
    timeout = ClientTimeout(total=1800)
    async with ClientSession(timeout=timeout) as session:
        async with create_engine(user=user, password=password,
                                 database=database, host=host) as engine:
            async with engine.acquire() as conn:
                await conn.execute("DROP TABLE IF EXISTS all_domains")
                await conn.execute(CreateTable(all_domains))
            tasks = []
            urls = generate_final_domains_list()
            for url in urls:
                domain = Domain(url=url, session=session, engine=engine)
                tasks.append(
                    domain.collect_and_save_to_db(**kwargs)
                )
            await asyncio.gather(*tasks)


def make_async_queries() -> None:
    """Main function running the requests and
    saving results to database"""
    start = time.perf_counter()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(gather())
    elapsed = time.perf_counter() - start
    print(f"The program finished in {elapsed} seconds.")


if __name__ == "__main__":
    make_async_queries()