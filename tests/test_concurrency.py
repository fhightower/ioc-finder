import concurrent.futures

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
