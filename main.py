#! usr/bin/env python3
# -*- coding: utf-8 -*-


import logging
import os
import sys

import psycopg2

from progress.bar import ChargingBar
from dotenv import load_dotenv

from domains_generator import generate_final_domains_list


logging.basicConfig(
    format="%(asctime)s %(levelname)s:%(name)s: %(message)s",
    level=logging.DEBUG,
    datefmt="%d-%b-%y %H:%M:%S",
    stream=sys.stderr,
)
logger = logging.getLogger("main")

load_dotenv(dotenv_path="secrets.env", override=True)
connection = psycopg2.connect(
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    host=os.getenv("DB_HOST"),
    database=os.getenv("DB_NAME"))


def create_db_table() -> None:
    try:
        cursor = connection.cursor()
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS squat_domains (
                           domain_name varchar(150) NOT NULL, 
                           registrar_name varchar(150),
                           owner_name varchar(150),
                           abuse_email varchar(150),
                           is_alive bool NOT NULL,
                           potentially_infringes bool,
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
               is_alive,
               potentially_infringes)
               
               VALUES (
                   '{whois_record["domain-name"]}',
                   '{whois_record["registrar-name"]
                        if whois_record["registrar-name"]
                        else None}',
                   '{whois_record["owner-name"]
                        if whois_record["owner-name"]
                        else None}',
                   '{whois_record["abuse-email"]
                        if whois_record['abuse-email']
                        else None}',
                   {whois_record['is-alive']},
                   {whois_record['potentially-infringes']})
                        
               ON CONFLICT (domain_name) DO UPDATE SET 
                    registrar_name = '{whois_record["registrar-name"]
                                        if whois_record["registrar-name"]
                                        else None}', 
                    owner_name = '{whois_record["owner-name"]
                                        if whois_record["owner-name"]
                                        else None}',
                    abuse_email = '{whois_record["abuse-email"]
                                        if whois_record['abuse-email']
                                        else None}',
                    is_alive = {whois_record['is-alive']},
                    potentially_infringes = {whois_record['potentially-infringes']};
               """)

        cursor.close()
        connection.commit()

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL:", error)


def get_domains_list() -> list:
    try:
        cursor = connection.cursor()
        cursor.execute(
            f"""
            SELECT domain_name FROM squat_domains WHERE registrar_name <> 'None';
            """
        )

        domains_list = [domain_name_tuple[0] for domain_name_tuple in
                        cursor.fetchall()]
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


def count_rows() -> int:
    try:
        cursor = connection.cursor()
        cursor.execute(
            f"""
            SELECT count(*) FROM squat_domains;
            """
        )

        num_of_rows = cursor.fetchone()[0]
        cursor.close()

        return num_of_rows

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL:", error)


def upload_records_to_database() -> None:
    domains_list = generate_final_domains_list()
    print(f"{len(domains_list)} domain names generated.")
    create_db_table()
    bar = ChargingBar("Uploading data", max=len(domains_list) - count_rows())

    for domain_name in domains_list:

        if check_if_domain_in_db(domain_name):
            pass

        else:
            domain_data = make_initial_search(domain_name)
            save_whois_record(domain_data)
            bar.next()

    bar.finish()


def update_database() -> None:
    domains_list = get_domains_list()
    print(f"{len(domains_list)} records are to be updated")

    bar = ChargingBar("Updating database", max=len(domains_list))

    for domain_name in domains_list:
        domain_data = make_initial_search(domain_name)
        save_whois_record(domain_data)
        bar.next()

    bar.finish()

    print("Database has been successfully updated")


def export_to_csv() -> None:
    try:
        with open("squat_domains.csv", "w"):
            cursor = connection.cursor()
            cursor.execute(
                f"""
                   COPY (SELECT * FROM squat_domains WHERE potentially_infringes = TRUE) 
                        TO '/tmp/squat_domains.csv'
                        WITH (FORMAT CSV, HEADER);
                   """
            )

            cursor.close()

            print("Data has been successfully exported to a CSV file")

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL:", error)


def main(instruction="update"):
    if instruction == "update":
        update_database()

    elif instruction == "upload":
        upload_records_to_database()

    elif instruction == "export":
        export_to_csv()

    connection.close()


if __name__ == "__main__":
    try:
        main(sys.argv[1])

    except IndexError:
        main()
