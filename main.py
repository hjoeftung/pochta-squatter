#! usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

import psycopg2

from domain_data_receiver import collect_and_format_domain_data
from domains_generator import generate_domains_list


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


def upload_whois_records():
    domains_list = generate_domains_list()
    create_db_table()

    for domain_name in domains_list:
        if check_if_domain_in_db(domain_name):
            print(f"{domain_name} is already saved in our database.")
        else:
            domain_data = collect_and_format_domain_data(domain_name)
            save_whois_record(domain_data)


def update_whois_records_in_db():
    domains_list = get_domains_list()

    for domain_name in domains_list:
        domain_data = collect_and_format_domain_data(domain_name)
        save_whois_record(domain_data)


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
