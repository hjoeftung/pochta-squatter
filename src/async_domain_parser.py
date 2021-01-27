#! usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import sys
import time

import aiohttp
import sqlalchemy as sa

from aiohttp import ClientSession, ClientTimeout
from aiopg.sa import create_engine
from bs4 import BeautifulSoup
from dotenv import load_dotenv, find_dotenv
from sqlalchemy import Column, Boolean, String
from sqlalchemy.ext.declarative import declarative_base

from domains_generator import generate_final_domains_list


logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("async_domain_parser")

# Load database's params from .env
load_dotenv(dotenv_path="secrets.env", override=True)
user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
host = os.getenv("DB_HOST")
database = os.getenv("DB_NAME")

# Create sqlalchemy engine and declarative Base class
metadata = sa.MetaData()
engine = create_engine(f"postgresql://{user}:{password}@{host}/{database}", echo=True)
Base = declarative_base()


class Domain(Base):
    __tablename__ = "all_domains"

    url = Column(String(150), primary_key=True, unique=True)
    is_alive = Column(Boolean)
    potentially_infringes = Column(Boolean)

    def __repr__(self):
        return (f"""
        <Domain(url={self.url},
                is_alive={self.is_alive},
                potentially_infringes={self.potentially_infringes})>""")


async def fetch_html_async(url: str, session: ClientSession, **kwargs) -> str:
    """Fetch html from the url asynchronously

    :param url: url to which we are sending request
    :param session: aiohttp's ClientSession instance
    :return: the requested page's html
    **kwargs are passed to 'session.request()'
    """

    response = await session.request(method="GET", url=url,
                                     allow_redirects=True, **kwargs)
    response.raise_for_status()
    logging.info(f"Got response {response.status} for URL: {url}")
    html = await response.text()
    return html


async def check_if_alive_and_infringes(url: str, session: ClientSession,
                                       **kwargs) -> dict:
    """Check whether the site is alive and may potentially infringe Pochta's
    trademarks

        :param url: url to which we are sending request
        :param session: aiohttp's ClientSession instance
        :return: dictionary with domain_name, is_alive and
        potentially_infringes keys (results of the check)
        **kwargs are passed to 'session.request()'
    """

    flag_words = ["почт", "росси", "отправлени", "посылк", "письм", "писем"]

    try:
        logger.info(f"Trying to reach {url}")
        html = await fetch_html_async(url=url,
                                      session=session,
                                      **kwargs)

    except (aiohttp.ClientError, aiohttp.http.HttpProcessingError,) as e:
        logger.error(
            f"aiohttp exception for {url}: {e}")

        return {"domain-name": url,
                "is-alive": False,
                "potentially-infringes": False}

    except Exception as e:
        logger.error(
            f"Non-aiohttp exception for {url} occurred: {e}")

        return {"domain-name": url,
                "is-alive": False,
                "potentially-infringes": False}
    else:
        logger.info(f"Site {url} has responded")
        domain_page = BeautifulSoup(html, "html.parser")
        page_text = domain_page.get_text()
        page_text.replace("\n", " ")
        page_text = page_text.split()
        potential_infringements = set(
            word.lower() for word in page_text for flag_word in flag_words
            if flag_word in word.lower()
        )
        if len(potential_infringements) > 2:
            logger.info(f"Potentially infringes: {len(potential_infringements)} "
                        f"have been found: {potential_infringements}")
            return {"domain-name": url,
                    "is-alive": True,
                    "potentially-infringes": True,
                    "num-potential-infringements": len(potential_infringements)}
        else:
            logger.info(f"Does not infringe: {len(potential_infringements)} "
                        f"have been found: {potential_infringements}")
            return {"domain-name": url,
                    "is-alive": True,
                    "potentially-infringes": False}


async def collect_and_save_to_db(url: str, pool, **kwargs):
    """Collect and format whois data on the domain name

    :param url: the name of the domain on which we are
    collecting info
    :param pool: database connection pool aiopg.Pool object
    """

    record = await check_if_alive_and_infringes(url=url, **kwargs)

    try:
        with (await pool.cursor()) as cur:
            await cur.execute(f"""
                   INSERT INTO squat_domains (
                       domain_name,
                       is_alive,
                       potentially_infringes)

                       VALUES (
                            '{record["domain-name"]}',
                            {record['is-alive']},
                            {record['potentially-infringes']})

                       ON CONFLICT (domain_name) DO UPDATE SET 
                            domain_name = '{record["domain-name"]}',
                            is_alive = {record['is-alive']},
                            potentially_infringes = {record['potentially-infringes']};
                       """)
            logger.info(f"Saved to database: {record['domain-name']}")
    except Exception as e:
        logger.error(f"Unexpected error occurred: {e}")


async def gather(domain_names: list, **kwargs) -> None:
    timeout = ClientTimeout(total=1800)
    async with ClientSession(timeout=timeout) as session:
        async with aiopg.create_pool(dsn=db_params) as pool:
            tasks = []
            for domain_name in domain_names:
                tasks.append(
                    collect_and_save_to_db(url=domain_name,
                                           session=session,
                                           pool=pool,
                                           **kwargs)
                )
            await asyncio.gather(*tasks)


def main() -> None:
    """Main function running the requests and
    saving results to database"""
    domains_to_check = generate_final_domains_list()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(gather(domains_to_check))


if __name__ == "__main__":
    start = time.perf_counter()
    main()
    elapsed = time.perf_counter() - start
    print(f"The program finished in {elapsed} seconds.")
