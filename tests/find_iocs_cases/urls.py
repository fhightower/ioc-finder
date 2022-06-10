from pytest import param

URL_DATA = [
    param(
        "1.1.1.1/0",
        {"urls": []},
        {"included_ioc_types": ["urls"]},
        id="cidr_range_with_included_ioc_types_urls",
    ),
    param(
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {
            "urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"],
            "domains": ["bar.com", "foo.com", "example.com"],
        },
        {},
        id="URL and domains parsed",
    ),
    param(
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {"urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"]},
        {"included_ioc_types": ["urls"]},
        id="Only URL parsed when included_ioc_types is used",
    ),
]
