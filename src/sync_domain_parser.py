#! usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import re
import sys

import requests
import whois

from bs4 import BeautifulSoup
from dotenv import load_dotenv
from googlesearch import search
from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from async_domain_parser import Domain


# Initialize a logger
logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("sync_domain_parser")

# Load database's params from .env
load_dotenv(dotenv_path="secrets.env", override=True)
user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
host = os.getenv("DB_HOST")
database = os.getenv("DB_NAME")

# Create sqlalchemy engine, session and declarative base
engine = create_engine(f"postgresql://{user}:{password}@{host}/{database}", echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()


# Define schema for a db table
class InfringingDomainDB(Base):
    __tablename__ = "infringing_domains"

    url = Column(String(150), primary_key=True, unique=True)
    owner_name = Column(String(150))
    registrar_name = Column(String(150))
    abuse_email = Column(String(500))

    def __repr__(self):
        return (f"""
        <InfringingDomain(url={self.url},
                          owner_name={self.owner_name},
                          registrar_name={self.registrar_name},
                          abuse_email={self.abuse_email}
                          )>""")


class InfringingDomain:
    def __init__(self, url):
        self.url = url
        self.owner_name = ""
        self.registrar_name = ""
        self.abuse_email = ""

    def get_whois_record(self) -> bool:
        """Get whois information on self.url. The collected whois record contains
        info on 4 parameters: "domain-name", "registrar-name", "owner-name" and
        "abuse-email"

        :return True if whois search was successful and False if not
        """

        try:
            whois_record = whois.whois(self.url)
            self.registrar_name = whois_record["registrar"]
            self.owner_name = whois_record["org"]
            self.abuse_email = whois_record["emails"]

            return True

        except whois.parser.PywhoisError:
            logger.info(f"Have not found whois record for {self.url}")

            return False

    def fetch_html(self, url) -> str:
        """Fetch html from the self.url"""
        try:
            response = requests.get(url=url, timeout=3)
        except requests.exceptions.RequestException as e:
            logger.error(f"Requests exception occurred while requesting {url}: {e}")
        else:
            return response.text

    def get_abuse_email(self):
        """Get the registrar's abuse email to which we may send complaints"""

        links_to_contact_page = search(self.registrar_name + " abuse email",
                                       tld="co.in", num=10, stop=10, pause=5)

        for link in links_to_contact_page:
            try:
                html = self.fetch_html(url=link)

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

                    logger.info(f"Abuse emails for registrar {self.registrar_name} "
                                f"have been found: {','.join(abuse_emails)}")
                    self.abuse_email = ", ".join(abuse_emails)


def main() -> None:
    infringing_domains = session.query(Domain).filter(
        Domain.potentially_infringes==True)

    for domain_record in infringing_domains:
        domain = InfringingDomain(domain_record.domain_name)

        if domain.get_whois_record():
            logger.info(f"Received whois record for: {domain.url}")

            if domain.owner_name == "JSC Russian Post":
                domain_record.potentially_infringing = False
                session.add(domain_record)

            if not domain.abuse_email and domain.registrar_name:
                logger.info(f"No abuse e-mail info found for: {domain.url}")
                domain.get_abuse_email()
                logger.info(f"Got abuse email for {domain.url}: {domain.abuse_email}")

            elif isinstance(domain.abuse_email, list):
                domain.abuse_email = ", ".join(domain.abuse_email)

            infringing_domain_record = InfringingDomainDB(
                                            url=domain.url,
                                            owner_name=domain.owner_name,
                                            registrar_name=domain.registrar_name,
                                            abuse_email=domain.abuse_email
                                        )
            session.add(infringing_domain_record)
            session.commit()
            logger.info(f"Saved whois record for {domain} to database")