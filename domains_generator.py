#! usr/bin/env python3
# -*- coding: utf-8

CONNECTORS = ["", "-", "_"]

RU_PREFIXES = ["", "ру", "рус", "рос"]
RU_MAIN_NAMES = ["почта"]
RU_POSTFIX_NAMES = ["", "инфо", ]
RU_DOMAIN_ZONES = [".рф"]

EN_PREFIXES = ["", "ru", "rus", "ros"]
EN_MAIN_NAMES = ["pochta"]
EN_POSTFIXES = ["", "info"]
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
                            domains.append(prefix + connector + name + connector + postfix +
                                           domain_zone)

    return domains


def generate_final_domains_list() -> list:
    print("Generating domains list.\n")

    ru_domains = generate_single_domains_list(CONNECTORS, RU_PREFIXES, RU_MAIN_NAMES,
                                              RU_POSTFIX_NAMES, RU_DOMAIN_ZONES)
    en_domains = generate_single_domains_list(CONNECTORS, EN_PREFIXES, EN_MAIN_NAMES,
                                              EN_POSTFIXES, EN_DOMAIN_ZONES)



    return list(set(ru_domains + en_domains))


if __name__ == "__main__":
    [print(domain) for domain in generate_final_domains_list()]
    print(len(generate_final_domains_list()))
