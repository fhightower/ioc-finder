from pytest import param

DATA_TYPES_DATA = [
    param(  # in this example, a URL and domains are parsed
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {
            "urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"],
            "domains": ["bar.com", "foo.com", "example.com"],
        },
        {},
        id="URL and domains parsed",
    ),
    param(  # in this example, only a URL is parsed b/c that's the only data type we specified
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {"urls": ["https://example.com/test%20page/foo.com/bingo.php?q=bar.com"]},
        {"data_types": ["urls"]},
        id="Only URL parsed when data_types is used",
    ),
    param(  # in this example, only a URL is parsed b/c that's the only data type we specified
        "https://example.com/test%20page/foo.com/bingo.php?q=bar.com",
        {"domains": ["bar.com", "foo.com", "example.com"]},
        {"data_types": ["domains"]},
        id="Only domains parsed when data_types is used",
    ),
]
