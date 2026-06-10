import concurrent.futures
import functools

from ioc_finder import find_iocs


def test_nested_concurrency():
    texts = ["example.com", "foo bar bang buzz", "This is just an example.com https://example.org/test/bingo.php"]
    results = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = [i for i in executor.map(find_iocs, texts)]

    assert results[0]["domains"] == ["example.com"]
    assert "example.com" in results[2]["domains"]
    assert "example.org" in results[2]["domains"]
    assert results[2]["urls"] == ["https://example.org/test/bingo.php"]


def test_unicode_layer_concurrency():
    """The Unicode grammar layer (`ioc_grammars.unicode_domain_layer()`) is
    module-shared just like the ASCII grammars — exercise it from multiple
    threads (including its lazy first build) to guard against state leakage."""
    texts = ["warrıors.com", "foo bar bang buzz", "an example.com and https://exämple.org/test/bingo.php"]

    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(functools.partial(find_iocs, parse_unicode_iocs=True), texts))

    assert results[0]["domains"] == ["warrıors.com"]
    assert results[1]["domains"] == []
    assert "example.com" in results[2]["domains"]
    assert "exämple.org" in results[2]["domains"]
    assert results[2]["urls"] == ["https://exämple.org/test/bingo.php"]
