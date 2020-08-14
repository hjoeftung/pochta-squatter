#! usr/bin/env python3
# -*- coding: utf-8


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


if __name__ == "__main__":
    generate_domains_list()
