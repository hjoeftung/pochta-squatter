#! usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys

import psycopg2
import requests
import whois

from bs4 import BeautifulSoup
from googlesearch import search


RU_PREFIX_NAMES = ()
RU_POCHTA_NAMES = ("почта", "пошта")
RU_POSTFIX_NAMES = ()
RU_DOMAIN_ZONES = (".рф",)

EN_PREFIX_NAMES = ()
EN_POCHTA_NAMES = ("pochta", "poshta")
EN_POSTFIX_NAMES = ()
EN_DOMAIN_ZONES = (".ru", ".net", ".info", ".org")


def generate_domains_list() -> list:
    ru_domains = [ru_name + ru_zone for ru_name in RU_POCHTA_NAMES
                  for ru_zone in RU_DOMAIN_ZONES]
    en_domains = [en_name + en_zone for en_name in EN_POCHTA_NAMES
                  for en_zone in EN_DOMAIN_ZONES]

    print("Generating domains list.\n")

    return ru_domains + en_domains


def get_whois_record(domain: str) -> dict:
    print(f"Getting whois record for {domain}")

    try:
        whois_record = whois.whois(domain)
        print(f"Whois record for {domain} has been successfully collected.")

        return {"domain-name": domain,
                "registrar-name": whois_record["registrar"],
                "owner-name": whois_record["org"],
                "abuse-email": whois_record["emails"]}

    except whois.parser.PywhoisError:
        return {}  # No whois data for domain


def check_if_alive(domain: str) -> bool:
    print(f"Checking if alive for {domain}.")

    full_domains = ["https://" + domain, "http://" + domain]

    for full_domain in full_domains:
        try:
            response = requests.get(full_domain, timeout=3, stream=True)

            if response.status_code == requests.codes.ok:
                # domain is alive

                return True

        except requests.exceptions.ConnectionError or TimeoutError:
            pass

    # domain is not alive
    return False


def get_abuse_email(registrar_name: str) -> str:
    links_to_contact_page = search(registrar_name + " abuse email",
                                   tld="co.in", num=10, stop=10, pause=2)

    for link in links_to_contact_page:
        try:
            contacts_page = requests.get(link, timeout=3, stream=True)
            contacts_page = BeautifulSoup(contacts_page.text, "html.parser")
            abuse_email = contacts_page.find_all(string=re.compile("abuse@"))

            email_pattern = re.compile(
                r"([a-z0-9_.-]+)@([\da-z.-]+)\.([a-z.]{2,6})")
            abuse_email = re.search(email_pattern, str(abuse_email))

            if abuse_email:
                abuse_email = abuse_email.group(1)[0]

                return abuse_email

        except TimeoutError:
            break


def format_whois_record(whois_record, domain) -> dict:
    # Getting rid of hardly intelligible domain ids such as
    # 'XN--80A1ACNY.XN--P1AI' for .рф domain zone
    whois_record["domain-name"] = domain

    is_alive = check_if_alive(domain)
    whois_record["is-alive"] = is_alive

    # In case no email is provided in the whois.whois response
    # we google for it
    if not whois_record["abuse-email"]:
        whois_record["abuse-email"] = get_abuse_email(
            whois_record["registrar-name"])

    # We need varchar in 'abuse_email' column in our db. So if we
    # get several emails in whois.whois response we pick only one
    if isinstance(whois_record["abuse-email"], list):
        whois_record["abuse-email"] = whois_record["abuse-email"][0]

    return whois_record


def create_db_table() -> None:
    try:
        cursor = connection.cursor()
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS squat_domains (
                           domain_name varchar(50) NOT NULL, 
                           registrar_name varchar(50),
                           owner_name varchar(50),
                           abuse_email varchar(50),
                           is_alive bool NOT NULL,
                           UNIQUE(domain_name)
                       );
                       """)

        cursor.close()
        connection.commit()

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL:\n", error)


def save_whois_record(whois_record: dict) -> None:
    try:
        cursor = connection.cursor()
        cursor.execute(f"""
           INSERT INTO squat_domains (
               domain_name, 
               registrar_name, 
               owner_name, 
               abuse_email,
               is_alive)
               
               VALUES (
                   '{whois_record["domain-name"]}',
                   '{whois_record["registrar-name"]}',
                   '{whois_record["owner-name"]
                        if whois_record["owner-name"]
                        else 'NULL'}',
                   '{whois_record["abuse-email"]
                        if whois_record['abuse-email']
                        else "NULL"}',
                   {whois_record['is-alive']})

               ON CONFLICT (domain_name) DO UPDATE SET 
                    registrar_name = '{whois_record["registrar-name"]}', 
                    owner_name = '{whois_record["owner-name"]
                                        if whois_record["owner-name"]
                                        else 'NULL'}',
                    abuse_email = '{whois_record["abuse-email"]
                                        if whois_record['abuse-email']
                                        else "NULL"}',
                    is_alive = {whois_record['is-alive']};
               """)

        cursor.close()
        connection.commit()
        print(f"Whois record for {whois_record['domain-name']} has "
              "been successfully saved.\n")

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL:", error)


def get_domains_list() -> list:
    try:
        cursor = connection.cursor()
        cursor.execute(
            f"""
            SELECT domain_name FROM squat_domains;
            """
        )

        domains_list = cursor.fetchall()
        cursor.close()

        return domains_list

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL:", error)


def check_if_domain_in_db(domain_name) -> bool:
    try:
        cursor = connection.cursor()
        cursor.execute(
            f"""
            SELECT exists (SELECT 1 FROM squat_domains 
                           WHERE domain_name = '{domain_name}');
            """
        )

        domain_is_in_db = cursor.fetchone()[0]
        cursor.close()

        if domain_is_in_db:
            return True

        return False

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL:", error)


def upload_whois_records():
    domains_list = generate_domains_list()
    create_db_table()

    for domain_name in domains_list:
        if check_if_domain_in_db(domain_name):
            print(f"{domain_name} is already saved in our database.")
        else:
            whois_response = get_whois_record(domain_name)
            whois_record = format_whois_record(whois_response, domain_name)
            save_whois_record(whois_record)


def update_whois_records_in_db():
    domains_list = get_domains_list()

    for domain_name in domains_list:
        domain_name = domain_name[0]
        whois_response = get_whois_record(domain_name)
        whois_record = format_whois_record(whois_response, domain_name)
        save_whois_record(whois_record)


def main(instruction="update"):
    if instruction == "update":
        update_whois_records_in_db()

    elif instruction == "upload":
        upload_whois_records()

    connection.close()


if __name__ == "__main__":
    connection = psycopg2.connect(
        user="antisquat",
        password="StopSquatters",
        host="localhost",
        database="pochta_domains")

    try:
        main(sys.argv[1])

    except IndexError:
        main()
