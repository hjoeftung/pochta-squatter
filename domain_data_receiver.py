#! usr/bin/env python3
# -*- coding: utf-8 -*-


import re
import sys
import urllib

import requests
import whois

from bs4 import BeautifulSoup
from googlesearch import search
from time import sleep


def get_whois_record(domain_name: str) -> dict:
    """

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
        return {"domain-name": domain_name,
                "registrar-name": None,
                "owner-name": None,
                "abuse-email": None}  # No whois data for domain


def check_if_alive(domain_name: str) -> bool:
    """

    :param domain_name: the name of the domain to which we are sending request
    :return: whether the domain is alive (responding) or not
    """

    full_domains = ["https://" + domain_name, "http://" + domain_name]

    for full_domain in full_domains:
        try:
            response = requests.get(full_domain, timeout=1, stream=True)

            if response.status_code == requests.codes.ok:
                # domain is alive

                return True

        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            pass

    # domain is not alive
    return False


def check_if_infringes(domain_name):
    flag_words = ["почт", "отправлени", "посылк"]
    full_domains = ["https://" + domain_name, "http://" + domain_name]

    for full_domain in full_domains:
        try:
            domain_response = requests.get(full_domain, timeout=1, stream=True)
            domain_page = BeautifulSoup(domain_response.text, "html.parser")
            page_text = domain_page.get_text()

            potential_infringements = [word in page_text for word in flag_words]

            flag_words_counter = 0
            for word in potential_infringements:
                if word:
                    flag_words_counter += 1

            if flag_words_counter >= 2:
                return True

        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            pass

        except urllib.error.HTTPError:
            sleep(2)

    return False


def get_abuse_email(registrar_name: str) -> str:
    """

    :param registrar_name: the name of the registrar whose abuse e-mail we are
    looking for
    :return: abuse email of the registrar
    """

    links_to_contact_page = search(registrar_name + " abuse email",
                                   tld="co.in", num=10, stop=10, pause=5)

    for link in links_to_contact_page:
        try:
            contacts_page = requests.get(link, timeout=3, stream=True)
            contacts_page = BeautifulSoup(contacts_page.text, "html.parser")
            abuse_email = contacts_page.find_all(string=re.compile("@"))
            email_pattern = re.compile(
                r"([a-z0-9_.-]+)?abuse@([\da-z.-]+)\.([a-z.]{2,6})")
            abuse_email = re.search(email_pattern, str(abuse_email))
            if abuse_email:
                abuse_email = abuse_email.group(0)

                return abuse_email

        except (TimeoutError, requests.exceptions.ReadTimeout):
            pass


def collect_and_format_domain_data(domain_name: str) -> dict:
    """

    :param domain_name: the name of the domain on which we are
    collecting info
    :return: the collected record containing the following info
    on the domain: "domain-name", "registrar-name", "abuse-email",
    "owner-name", "is-alive"
    """
    whois_record = get_whois_record(domain_name)

    if whois_record["registrar-name"]:
        whois_record["is-alive"] = check_if_alive(domain_name)

        if whois_record["is-alive"] and whois_record["owner-name"] != "JSC Russian Post":
            whois_record["potentially-infringes"] = check_if_infringes(domain_name)

            # In case no email is provided in the whois.whois response
            # for a potentially squatting domain we google for the email
            """if whois_record["potentially-infringes"] and not whois_record["abuse-email"]:
                whois_record["abuse-email"] = get_abuse_email(
                    whois_record["registrar-name"])
            else:
                whois_record["abuse-email"] = None"""
        else:
            whois_record["potentially-infringes"] = False

        for key in whois_record.keys():
            if isinstance(whois_record[key], list):
                whois_record[key] = ", ".join(whois_record[key])

        return whois_record

    else:
        whois_record["is-alive"] = False
        whois_record["potentially-infringes"] = False

        return whois_record


if __name__ == "__main__":
    collect_and_format_domain_data(sys.argv[1])
