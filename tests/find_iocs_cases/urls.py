from pytest import param

URL_DATA = [
    param(
        "1.1.1.1/0",
        {"urls": ["1.1.1.1/0"]},
        {"data_types": ["urls"]},
        id="cidr_range_with_data_types_urls",
    ),
    param(
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {"urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"], "domains": ["bar.com", "foo.com", "example.com"]},
        {},
        id="URL and domains parsed",
    ),
    param(
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {"urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"]},
        {"data_types": ["urls"]},
        id="Only URL parsed when data_types is used",
    ),
]
