"""Make sure that the parsing functions for specific functions are imported properly."""

from ioc_finder import parse_urls


def test_url_parsing_func():
    results = parse_urls("https://google.com")
    assert results == ["https://google.com"]
