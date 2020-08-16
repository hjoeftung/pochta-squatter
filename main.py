#! usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import sys

import psycopg2

from progress.bar import ChargingBar

from domain_data_receiver import collect_and_format_domain_data
from domains_generator import generate_final_domains_list


connection = psycopg2.connect(
    user="antisquat",
    password="StopSquatters",
    host="localhost",
    database="pochta_domains")


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
                   '{whois_record["registrar-name"]
                        if whois_record["registrar-name"]
                        else 'NULL'}',
                   '{whois_record["owner-name"]
                        if whois_record["owner-name"]
                        else 'NULL'}',
                   '{whois_record["abuse-email"]
                        if whois_record['abuse-email']
                        else "NULL"}',
                   {whois_record['is-alive']})

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
                    is_alive = {whois_record['is-alive']};
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
            SELECT domain_name FROM squat_domains;
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


def upload_whois_records():
    domains_list = generate_final_domains_list()
    create_db_table()
    # bar = ChargingBar("Processing", max=len(domains_list))
    counter = 0

    for domain_name in domains_list:
        domain_data = collect_and_format_domain_data(domain_name)
        save_whois_record(domain_data)
        # bar.next()
        counter += 1
        print(counter, domain_name, domain_data)

    # bar.finish()


def update_whois_records_in_db():
    domains_list = get_domains_list()
    bar = ChargingBar("Processing", max=len(domains_list))

    for domain_name in domains_list:
        domain_data = collect_and_format_domain_data(domain_name)
        save_whois_record(domain_data)
        bar.next()

    bar.finish()


def export_to_csv():
    try:
        with open("squat_domains.csv", "w"):
            cursor = connection.cursor()
            cursor.execute(
                f"""
                   COPY squat_domains TO '{os.getcwd()}/squat_domains.csv'
                        DELIMITER ',' CSV;
                   """
            )

            cursor.close()

    except (Exception, psycopg2.Error) as error:
        print("Error while connecting to PostgreSQL:", error)


def main(instruction="update"):
    if instruction == "update":
        update_whois_records_in_db()

    elif instruction == "upload":
        upload_whois_records()

    elif instruction == "export":
        export_to_csv()

    connection.close()


if __name__ == "__main__":
    try:
        main(sys.argv[1])

    except IndexError:
        main()
