#! usr/bin/env python3
# -*- coding: utf-8 -*-


import logging
import os
import sys

import psycopg2

from dotenv import load_dotenv

from domains_generator import generate_final_domains_list
from domain_data_receiver import get_and_save_domain_data


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
        logger.error("Error while connecting to PostgreSQL:\n", error)


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
        logger.error("Error while connecting to PostgreSQL:", error)


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

        return domain_is_in_db == 1

    except (Exception, psycopg2.Error) as error:
        logger.error("Error while connecting to PostgreSQL:", error)


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
        logger.error("Error while connecting to PostgreSQL:", error)


def first_run() -> None:
    domains_list = generate_final_domains_list()
    print(f"{len(domains_list)} domain names generated.")
    create_db_table()
    get_and_save_domain_data()


def update_database() -> None:
    domains_list_len = count_rows()
    print(f"{domains_list_len} records are to be updated")
    get_and_save_domain_data()
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
        first_run()

    elif instruction == "export":
        export_to_csv()

    connection.close()


if __name__ == "__main__":
    try:
        main(sys.argv[1])

    except IndexError:
        main()
