import os
import re

import pytest
import psycopg2
from dotenv import load_dotenv

from async_domain_parser import get_abuse_email
from async_domain_parser import check_if_alive_and_infringes


test_str = """
 "\n\t  [Querying whois.verisign-grs.com]\n[Redirected to whois.ascio.com]\n[Querying whois.ascio.com]\n[whois.ascio.com]\nDomain Name: skillinge.com\nRegistry Domain ID: 12852732_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.ascio.com\nRegistrar URL: http://www.ascio.com\nUpdated Date: 2017-10-13T01:29:44Z\nCreation Date: 1999-11-12T16:07:05Z\nRegistrar Registration Expiration Date: 2018-11-12T21:07:05Z\nRegistrar: Ascio Technologies, Inc\nRegistrar IANA ID: 106\nRegistrar Abuse Contact Email: abuse@ascio.com\nRegistrar Abuse Contact Phone: +44.2070159370\nDomain Status: OK https://icann.org/epp#ok\nRegistry Registrant ID:\nRegistrant Name: Berit AAkesson\nRegistrant Organization: Skillinge Foretagareforening\nRegistrant Street: Skolgatan 22\nRegistrant 
 """


def test_regexp(test_str: str=test_str) -> str:
    email_pattern = re.compile("\\s[^\\s]*abuse@[a-z]*[.][a-z]{2,6}[\\s.,]", re.IGNORECASE)
    return email_pattern.search(test_str).group()[1:-1]


def test_domain_google_search():
    assert get_abuse_email(registrar_name="RU-REG-RU") == "abuse@reg.ru"
    assert get_abuse_email("Regional Network Information Center, JSC dba RU-CENTER") == "tld-abuse@nic.ru"


if __name__ == "__main__":
    connection = psycopg2.connect(
        user="antisquat",
        password="StopSquatters",
        host="localhost",
        database="pochta_domains")

    load_dotenv(dotenv_path="secrets.env", override=True)
    check_if_alive_and_infringes("https://")