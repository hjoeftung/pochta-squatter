from web.backend.domains import whois_parser


def test_prepare_url():
    http_test_urls = [
        "http://заказное-почта.рф",
        "http://russian-post-cabinet.ru.com",
    ]
    https_test_urls = [
        "https://заказное-почта.рф",
        "https://russian-post-cabinet.com",
        "https://russian-post-cabinet.ru.com"
    ]
    for http_url in http_test_urls:
        assert whois_parser.prepare_url(http_url) == http_url[7:]

    for https_url in https_test_urls:
        assert whois_parser.prepare_url(https_url) == https_url[8:]

    # Test that function returns whole url if it does not match the pattern
    assert whois_parser.prepare_url("unknown_pattern") == "unknown_pattern"


def test_get_whois_record():
    assert whois_parser.get_whois_record("https://nonexisting.url") == {
        "domain_name": "https://nonexisting.url", "owner_name": "",
        "registrar_name": "", "abuse_emails": ""
    }
    assert whois_parser.get_whois_record("https://почта.рф")["owner_name"] == (
        "JSC Russian Post"
    )
    assert whois_parser.get_whois_record("http://почта.рф")[
               "registrar_name"
           ] == "RUCENTER-RF"
