#! usr/bin/env python3
# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import re
import sys
import time

import aiopg
import aiohttp
import psycopg2
import requests
import whois

from aiohttp import ClientSession, ClientTimeout
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from googlesearch import search

from domains_generator import generate_final_domains_list


logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("domain_data_receiver")
load_dotenv(dotenv_path="secrets.env", override=True)

db_params = os.getenv("DB_PARAMS")


async def fetch_html_async(url: str, session: ClientSession, **kwargs) -> str:
    """Fetch html from the url asynchronously

    :param url: url to which we are sending request
    :param session: aiohttp's ClientSession instance
    :return: whether the domain is alive (responding) or not
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
        :return: whether the domain is alive (responding) or not
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


def fetch_html_sync(url: str) -> str:
    """Fetch html from the url asynchronously

        :param url: url to which we are sending request
    """
    response = requests.get(url=url, timeout=3)
    return response.text


def get_whois_record(domain_name: str) -> dict:
    """Get whois information

    :param domain_name: the name of the domain on which we're getting whois info
    :return: the collected whois record containing info on 4 parameters: "domain-name",
    "registrar-name", "owner-name" and "abuse-email"
    """

    try:
        whois_record = whois.whois(domain_name)
        return {"domain-name": domain_name,
                "registrar-name": whois_record["registrar"],
                "owner-name": whois_record["org"],
                "abuse-email": whois_record["emails"]}

    except whois.parser.PywhoisError:
        logger.info(f"Have not found whois record for {domain_name}")
        return {"domain-name": domain_name,
                "registrar-name": None,
                "owner-name": None,
                "abuse-email": None}  # No whois data for domain


def get_abuse_email(registrar_name: str) -> str:
    """Get the registrar's abuse email to which we may send complaints

    :param registrar_name: the name of the registrar whose abuse e-mail we are
    looking for
    :param session: aiohttp's ClientSession instance
    :return: abuse email of the registrar
    """

    links_to_contact_page = search(registrar_name + " abuse email",
                                   tld="co.in", num=10, stop=10, pause=5)

    for link in links_to_contact_page:
        try:
            html = fetch_html_sync(url=link)

        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout) as e:
            logger.error(f"requests error for {link}: {e}")
            pass

        except Exception as e:
            logger.error(f"Non-requests error for {link}: {e}")
            pass

        else:
            contacts_page = BeautifulSoup(html, "html.parser")
            email_pattern = re.compile(
                "\\s[^\\s]*abuse@[a-z]*[.][a-z]{2,6}[\\s.,]", re.IGNORECASE
            )
            abuse_emails_paras = contacts_page.find_all(string=email_pattern)
            if abuse_emails_paras:
                abuse_emails = [email_pattern.search(email_para).group()[1:-1]
                                for email_para in abuse_emails_paras]

                logger.info(f"Abuse emails for registrar {registrar_name} "
                            f"have been found: {','.join(abuse_emails)}")
                return ", ".join(abuse_emails)


async def async_part(domain_names: list, **kwargs) -> None:
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


def sync_part() -> None:
    conn = psycopg2.connect(
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"))

    cur1 = conn.cursor()
    cur1.execute(f"""
            SELECT domain_name FROM squat_domains
            WHERE potentially_infringes = True;
        """)
    infringing_domains = cur1.fetchall()
    cur1.close()
    print(infringing_domains)

    for domain_tuple in infringing_domains:
        domain = domain_tuple[0]
        whois_record = get_whois_record(domain)
        logger.info(f"Received whois record for: {domain}")
        if whois_record:
            if whois_record["owner-name"] == "JSC Russian Post":
                cur2 = conn.cursor()
                cur2.execute(f"""
                        UPDATE squat_domains
                            SET potentially_infringes = False
                            WHERE domain_name = '{domain}';
                        """)
                cur2.close()
                continue

            if not whois_record["abuse-email"] and whois_record["registrar-name"]:
                logger.info(f"No abuse e-mail info found for: {domain}")
                whois_record["abuse-email"] = get_abuse_email(whois_record["registrar-name"])
            elif isinstance(whois_record["abuse-email"], list):
                whois_record["abuse-email"] = ", ".join(whois_record["abuse-email"])

            logger.info(f"Got abuse email: : {whois_record}")
            cur3 = conn.cursor()
            cur3.execute(f"""
                UPDATE squat_domains
                    SET
                        registrar_name = '{whois_record["registrar-name"]
                                            if whois_record["registrar-name"]
                                            else None}', 
                        owner_name = '{whois_record["owner-name"]
                                        if whois_record["owner-name"]
                                        else None}',
                        abuse_email = '{whois_record["abuse-email"]
                                        if whois_record['abuse-email']
                                        else None}'
                    WHERE domain_name = '{domain}';
            """)
            cur3.close()
            logger.info(f"Saved whois record for {domain} to database")
        conn.commit()


def get_and_save_domain_data() -> None:
    """Main function running both async and sync parts of the script

    """
    domains_to_check = generate_final_domains_list()
    loop = asyncio.get_event_loop()
    loop.run_until_complete(async_part(domains_to_check))
    sync_part()


if __name__ == "__main__":
    start = time.perf_counter()
    get_and_save_domain_data()
    elapsed = time.perf_counter() - start
    print(f"The program finished in {elapsed} seconds.")
