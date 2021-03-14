import logging
import re

import requests

from bs4 import BeautifulSoup
from googlesearch import search


logger = logging.getLogger(__name__)


def get_abuse_email(self):
    """Get the registrar's abuse email to which we may send complaints"""

    links_to_contact_page = search(
        self.registrar_name + " registrar abuse email",
        tld="co.in", num=10, stop=10, pause=5
    )
    print([link for link in links_to_contact_page])
    for link in links_to_contact_page:
        try:
            html = fetch_html(url=link)

        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout) as e:
            logger.error(f"requests error for {link}: {e}")
            pass

        except Exception as e:
            logger.error(f"Non-requests error for {link}: {e}")
            pass

        else:
            if html:
                return self.find_abuse_email(html)


def find_abuse_email(self, html):
    contacts_page = BeautifulSoup(html, "html.parser")
    email_pattern = re.compile(
        "([\\s])*?|([a-z]*?-)abuse([a-z]+)@[a-z]+[.][a-z]{2,6}[\\s.,;]", re.IGNORECASE
    )
    abuse_emails_paras = contacts_page.find_all(string=email_pattern)

    if abuse_emails_paras:
        abuse_emails = [email_pattern.search(email_para).group()[1:-1]
                        for email_para in abuse_emails_paras]

        logger.info(f"Abuse emails for registrar {self.registrar_name} "
                    f"have been found: {','.join(abuse_emails)}")
        self.abuse_email = ", ".join(abuse_emails)

        return abuse_emails