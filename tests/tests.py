import os
import random
import re

import pytest

from aiohttp import ClientSession
from aiopg.sa import create_engine
from dotenv import load_dotenv, find_dotenv

from async_domain_parser import Domain
from sync_domain_parser import InfringingDomain
from domains_generator import generate_final_domains_list


# Load database's params from .env
load_dotenv(dotenv_path=find_dotenv(), override=True)
user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
host = os.getenv("DB_HOST")
database = os.getenv("DB_NAME")

test_str = "\n\t  [Querying whois.verisign-grs.com]\n[Redirected to whois.ascio.com]\n[Querying whois.ascio.com]\n[whois.ascio.com]\nDomain Name: skillinge.com\nRegistry Domain ID: 12852732_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.ascio.com\nRegistrar URL: http://www.ascio.com\nUpdated Date: 2017-10-13T01:29:44Z\nCreation Date: 1999-11-12T16:07:05Z\nRegistrar Registration Expiration Date: 2018-11-12T21:07:05Z\nRegistrar: Ascio Technologies, Inc\nRegistrar IANA ID: 106\nRegistrar Abuse Contact Email: abuse@ascio.com\nRegistrar Abuse Contact Phone: +44.2070159370\nDomain Status: OK https://icann.org/epp#ok\nRegistry Registrant ID:\nRegistrant Name: Berit AAkesson\nRegistrant Organization: Skillinge Foretagareforening\nRegistrant Street: Skolgatan 22\nRegistrant"


def test_regexp(test_str: str=test_str) -> str:
    email_pattern = re.compile("\\s[^\\s]*abuse@[a-z]*[.][a-z]{2,6}[\\s.,]", re.IGNORECASE)
    return email_pattern.search(test_str).group()[1:-1]


def test_domain_google_search(domain):
    assert domain.get_abuse_email(registrar_name="RU-REG-RU") == "abuse@reg.ru"
    assert domain.get_abuse_email(registrar_name="Regional Network Information Center, JSC dba RU-CENTER") == "tld-abuse@nic.ru"


async def test_async_funcs(**kwargs):
    async with ClientSession() as session:
        async with create_engine(user=user, password=password,
                                 database=database, host=host) as engine:
            # A random 20 elements sample taken with random.sample()
            # from final_domains_list
            url1 = "https://zakaznoepost.site"
            url2 = "https://kabinet-pochta.ru"
            url3 = "https://wwwpostservice.com"
            url4 =  "http://emspost.ru"
            url5 = "https://ems-post.ru"

            domain1 = Domain(url=url1, session=session, engine=engine)
            assert await domain1._check_if_alive(**kwargs) == False

            domain2 = Domain(url=url2, session=session, engine=engine)
            assert domain2._check_if_alive(**kwargs) == True
            assert domain2._check_if_dangerous() == True

            domain3 = Domain(url=url3, session=session, engine=engine)
            assert

if __name__ == "__main__":
