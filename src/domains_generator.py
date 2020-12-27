#! usr/bin/env python3
# -*- coding: utf-8

from dnstwist import DomainFuzz


CONNECTORS = ["", "-"]

RU_PREFIXES = ["", "ру", "рус", "рос", "заказное", "отправка", "кабинет", "российская"]
RU_MAIN_NAMES = ["почта"]
RU_POSTFIX_NAMES = ["", "инфо", "трекер"]
RU_DOMAIN_ZONES = [".рф"]

EN_PREFIXES = ["", "ems", "www", "ru", "rus", "ros", "zakaznoe", "otpravka", "kabinet",
               "cabinet", "russian"]
EN_MAIN_NAMES = ["pochta", "post"]
EN_POSTFIXES = ["", "track", "tracker", "info", "r", "ru", "rus", "ros", "rossii", "russia",
                "rossiya", "index", "service", "servise", "kabinet", "cabinet"]
EN_DOMAIN_ZONES = [".ru", ".net", ".info", ".org", ".site", ".su", ".com", ".ru.com"]


def generate_single_domains_list(connectors: list, prefixes: list, main_names: list,
                                 postfixes: list, domain_zones: list) -> list:
    domains = []

    for connector in connectors:
        for prefix in prefixes:
            for name in main_names:
                for postfix in postfixes:
                    for domain_zone in domain_zones:
                        if not prefix and not postfix:
                            domains.append(name + domain_zone)
                        elif postfix and not prefix:
                            domains.append(name + connector + postfix + domain_zone)
                        elif prefix and not postfix:
                            domains.append(prefix + connector + name + domain_zone)
                        else:
                            domains.append(prefix + connector + name + connector +
                                           postfix + domain_zone)

    return domains


def generate_final_domains_list() -> list:
    print("Generating domains list.\n")

    ru_domains = generate_single_domains_list(CONNECTORS, RU_PREFIXES, RU_MAIN_NAMES,
                                              RU_POSTFIX_NAMES, RU_DOMAIN_ZONES)
    en_domains = generate_single_domains_list(CONNECTORS, EN_PREFIXES, EN_MAIN_NAMES,
                                              EN_POSTFIXES, EN_DOMAIN_ZONES)

    dns_twist = DomainFuzz("pochta.ru")
    dns_twist.generate()
    dns_twist_domains = [domain["domain-name"] for domain in dns_twist.domains]
    final_domains_list = ru_domains + en_domains + dns_twist_domains
    final_domains_list = [protocol + domain_name for domain_name in final_domains_list
                          for protocol in ["http://", "https://"]]

    return final_domains_list


if __name__ == "__main__":
    [print(domain) for domain in generate_final_domains_list()]
    print(len(generate_final_domains_list()))
